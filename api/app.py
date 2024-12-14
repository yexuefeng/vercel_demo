from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, date
import os
import hashlib
import base64
from collections import defaultdict
import logging
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
import json
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 创建 Flask 应用
app = Flask(__name__)
CORS(app)

# 数据库配置
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 5,
    'max_overflow': 10,
    'pool_timeout': 30,
    'pool_recycle': 1800,
}

# 初始化扩展
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Google OAuth 配置
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

# 模型定义
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    name = db.Column(db.String(100))
    google_id = db.Column(db.String(100), unique=True)
    google_credentials = db.Column(db.Text)
    profile_pic = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    login_type = db.Column(db.String(20))
    todos = db.relationship('Todo', backref='user', lazy=True)

    def set_password(self, password):
        # 使用 SHA256 + 盐值的方式加密密码
        salt = os.urandom(16)
        password_bytes = password.encode('utf-8')
        salt_password = salt + password_bytes
        hash_obj = hashlib.sha256(salt_password)
        hash_value = hash_obj.digest()
        self.password_hash = base64.b64encode(salt + hash_value).decode('utf-8')

    def check_password(self, password):
        try:
            stored = base64.b64decode(self.password_hash.encode('utf-8'))
            salt = stored[:16]
            stored_hash = stored[16:]
            password_bytes = password.encode('utf-8')
            salt_password = salt + password_bytes
            hash_obj = hashlib.sha256(salt_password)
            calculated_hash = hash_obj.digest()
            return calculated_hash == stored_hash
        except Exception:
            return False

class Tag(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    complete = db.Column(db.Boolean, default=False)
    due_date = db.Column(db.Date, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    priority = db.Column(db.String(20), default='medium')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'), nullable=True)
    tag = db.relationship('Tag', backref='todos')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    """初始化数据库"""
    with app.app_context():
        try:
            # 创建所有表
            db.create_all()
            logger.info("Database tables created successfully")
            
            # 检查是否需要创建默认用户和标签
            if not User.query.first():
                # 创建测试用户
                test_user = User(
                    email='test@example.com',
                    name='Test User',
                    login_type='local'
                )
                test_user.set_password('password123')
                db.session.add(test_user)
                db.session.commit()
                
                # 创建默认标签
                default_tags = ['个人', '项目', '团队']
                for tag_name in default_tags:
                    tag = Tag(name=tag_name, user_id=test_user.id)
                    db.session.add(tag)
                db.session.commit()
                logger.info("Created default user and tags")
                
        except Exception as e:
            logger.error(f"Database initialization error: {str(e)}")
            raise

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.login_type == 'local' and user.check_password(password):
            login_user(user)
            logger.info(f"User logged in: {user.email}")
            return redirect(url_for('index'))
        else:
            # 如果用户不存在，提示注册
            if not user:
                flash('该邮箱未注册，请先注册账号')
            else:
                flash('邮箱或密码错误')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        
        # 验证输入
        if not email or not password:
            flash('请填写所有必填字段')
            return redirect(url_for('register'))
        
        # 检查邮箱是否已注册
        if User.query.filter_by(email=email).first():
            flash('该邮箱已注册，请直接登录')
            return redirect(url_for('login'))
        
        try:
            # 创建新用户
            user = User(
                email=email,
                name=name or email.split('@')[0],
                login_type='local'
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            # 自动登录
            login_user(user)
            logger.info(f"New user registered and logged in: {user.email}")
            return redirect(url_for('index'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error registering user: {str(e)}")
            flash('注册失败，请重试')
            return redirect(url_for('register'))
    
    return render_template('login.html')

@app.route('/google-login')
def google_login():
    flow = get_google_flow()
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['state'] = state
    logger.info("Redirecting to Google authorization")
    return redirect(authorization_url)

@app.route('/callback')
def oauth2callback():
    logger.info("Received Google callback")
    
    try:
        flow = get_google_flow()
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        service = build('oauth2', 'v2', credentials=credentials)
        user_info = service.userinfo().get().execute()
        
        user = User.query.filter_by(google_id=user_info['id']).first()
        if not user:
            # 检查是否存在用相同邮箱的本地账户
            existing_user = User.query.filter_by(email=user_info['email']).first()
            if existing_user:
                # 如果存在本地账户，则关联Google账号
                existing_user.google_id = user_info['id']
                existing_user.google_credentials = json.dumps({
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token,
                    'token_uri': credentials.token_uri,
                    'client_id': credentials.client_id,
                    'client_secret': credentials.client_secret,
                    'scopes': credentials.scopes
                })
                user = existing_user
            else:
                # 创建新的Google账户
                user = User(
                    email=user_info['email'],
                    name=user_info.get('name'),
                    google_id=user_info['id'],
                    profile_pic=user_info.get('picture'),
                    google_credentials=json.dumps({
                        'token': credentials.token,
                        'refresh_token': credentials.refresh_token,
                        'token_uri': credentials.token_uri,
                        'client_id': credentials.client_id,
                        'client_secret': credentials.client_secret,
                        'scopes': credentials.scopes
                    }),
                    login_type='google'
                )
                db.session.add(user)
            
            db.session.commit()
            logger.info(f"New Google user created: {user.email}")
        
        login_user(user)
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Error in Google callback: {str(e)}")
        flash('Google登录失败，请重试')
        return redirect(url_for('login'))

@app.route('/gmail')
@login_required
def gmail():
    try:
        if not current_user.google_credentials:
            logger.error("No Google credentials found")
            return redirect(url_for('login'))
        
        creds_data = json.loads(current_user.google_credentials)
        credentials = Credentials.from_authorized_user_info(creds_data)
        
        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                # 更新存储的凭证
                current_user.google_credentials = json.dumps({
                    'token': credentials.token,
                    'refresh_token': credentials.refresh_token,
                    'token_uri': credentials.token_uri,
                    'client_id': credentials.client_id,
                    'client_secret': credentials.client_secret,
                    'scopes': credentials.scopes
                })
                db.session.commit()
            else:
                logger.error("Invalid credentials")
                return redirect(url_for('login'))
        
        service = build('gmail', 'v1', credentials=credentials)
        results = service.users().messages().list(userId='me', maxResults=10).execute()
        messages = results.get('messages', [])
        
        email_list = []
        for message in messages:
            msg = service.users().messages().get(userId='me', id=message['id']).execute()
            headers = msg['payload']['headers']
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
            email_list.append({
                'subject': subject,
                'snippet': msg['snippet']
            })
        
        return render_template('gmail.html', emails=email_list)
        
    except Exception as e:
        logger.error(f"Error accessing Gmail: {str(e)}")
        flash('无法访问 Gmail，请重新登录')
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    tags = Tag.query.filter_by(user_id=current_user.id).all()
    
    # 按日期和优先级组织待办事项
    todos_by_date = {}
    
    for todo in todos:
        date_str = todo.due_date.strftime('%Y-%m-%d') if todo.due_date else '无截止日期'
        
        if date_str not in todos_by_date:
            todos_by_date[date_str] = {
                'high': [],
                'medium': [],
                'low': []
            }
        
        todos_by_date[date_str][todo.priority].append(todo)
    
    # 对日期进行排序
    sorted_dates = sorted(todos_by_date.keys())
    sorted_todos = {date: todos_by_date[date] for date in sorted_dates}
    
    return render_template('index.html', 
                         todos_by_date=sorted_todos,
                         today=date.today(),
                         tags=tags)

@app.route('/add', methods=['POST'])
@login_required
def add():
    title = request.form.get('title')
    due_date_str = request.form.get('due_date')
    priority = request.form.get('priority', 'medium')
    tag_id = request.form.get('tag_id')  # 获取标签ID
    
    if title and due_date_str:
        try:
            due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            
            if due_date < date.today():
                flash('不能选择过去的日期')
                return redirect(url_for('index'))
            
            new_todo = Todo(
                title=title,
                due_date=due_date,
                priority=priority,
                user_id=current_user.id,
                tag_id=tag_id if tag_id else None
            )
            db.session.add(new_todo)
            db.session.commit()
            
        except ValueError:
            flash('日期格式无效')
    
    return redirect(url_for('index'))

@app.route('/complete/<int:todo_id>')
@login_required
def complete(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        return redirect(url_for('index'))
    
    todo.complete = not todo.complete
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:todo_id>')
@login_required
def delete(todo_id):
    todo = Todo.query.get_or_404(todo_id)
    if todo.user_id != current_user.id:
        return redirect(url_for('index'))
    
    db.session.delete(todo)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/tags/add', methods=['POST'])
@login_required
def add_tag():
    tag_name = request.form.get('tag_name')
    if tag_name:
        # 检查是否已存在相同标签
        existing_tag = Tag.query.filter_by(user_id=current_user.id, name=tag_name).first()
        if existing_tag:
            flash('标签已存在')
            return redirect(url_for('index'))
        
        new_tag = Tag(name=tag_name, user_id=current_user.id)
        db.session.add(new_tag)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash('添加标签失败')
            logger.error(f"Error adding tag: {str(e)}")
    return redirect(url_for('index'))

@app.route('/tags/delete/<int:tag_id>')
@login_required
def delete_tag(tag_id):
    tag = Tag.query.get_or_404(tag_id)
    if tag.user_id != current_user.id:
        return redirect(url_for('index'))
    
    try:
        # 将使用此标签的待办事项的标签设为 None
        Todo.query.filter_by(tag_id=tag.id).update({Todo.tag_id: None})
        db.session.delete(tag)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash('删除标签失败')
        logger.error(f"Error deleting tag: {str(e)}")
    return redirect(url_for('index'))

def get_google_flow():
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost:5001/callback"]
            }
        },
        scopes=GOOGLE_SCOPES
    )
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    return flow

if __name__ == '__main__':
    logger.info("Starting Flask application...")
    
    try:
        init_db()
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        exit(1)
    
    app.run(debug=True, host='0.0.0.0', port=5001)