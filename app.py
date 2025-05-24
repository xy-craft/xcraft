# app.py

import os
from flask import Flask, render_template, request, redirect, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime, timedelta  # 修改这一行
import markdown2
from functools import wraps
import markdown

app = Flask(__name__, 
          static_folder=os.path.abspath("static"),
          template_folder=os.path.abspath("templates"))
app.config.from_pyfile('config.py')
db = SQLAlchemy(app)

# 在这里注册模板过滤器
@app.template_filter('markdown')
def convert_markdown(text):
    # 使用扩展增强功能（如表格、代码块等）
    return markdown.markdown(
        text, 
        extensions=['extra', 'codehilite'],
        extension_configs={
            'codehilite': {
                'use_pygments': True,
                'css_class': 'codehilite'
            }
        }
    )

# 数据库模型
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 登录管理
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 管理员权限装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# 在 app.py 的适当位置（例如在路由定义之前）添加以下代码：

# 自定义过滤器
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    return value.strftime(format)

# 注册过滤器到Jinja环境
app.jinja_env.filters['datetimeformat'] = datetimeformat

# 路由部分
@app.route('/')
def index():
    welcome_content = """
# Welcome to 『 Xcraft 』

欢迎来到 xuyang 的 blog！

这是一个专注于 **算法竞赛** 与 **学习分享** 的技术博客，主要包含：

- OI 算法解析

- 文化课学习笔记

- 技术杂谈与生活分享

"""
    # 转换 Markdown 内容
    welcome_html = markdown2.markdown(welcome_content, extras=["latex"])

    # 原有的最新文章查询保持不变
    posts = Post.query.order_by(Post.created_at.desc()).limit(5).all()
    
    return render_template('index.html', 
                         posts=posts,
                         welcome_html=welcome_html)  # 新增参数

@app.route('/category/<category>')
def category(category):
    posts = Post.query.filter_by(category=category).order_by(Post.created_at.desc()).all()
    return render_template('category.html', posts=posts, category=category)

@app.route('/post/<int:post_id>')
def show_post(post_id):
    post = Post.query.get_or_404(post_id)
    html_content = markdown2.markdown(post.content, extras=["fenced-code-blocks", "tables", "latex"])
    return render_template('post.html', post=post, content=html_content)

# dashboard

@app.route('/admin/')
@login_required
@admin_required
def admin_dashboard():
    # 总文章数
    total_posts = Post.query.count()
    
    # 按分类统计（前5个分类）
    category_counts = db.session.query(
        Post.category, 
        db.func.count(Post.id).label('count')
    ).group_by(Post.category).order_by(db.desc('count')).limit(5).all()
    
    # 最新文章（最近5篇）
    latest_posts = Post.query.order_by(Post.created_at.desc()).limit(5).all()
    
    # 用户统计
    total_users = User.query.count()
    latest_user = User.query.order_by(User.id.desc()).first()
    
    # 月度文章趋势（最近6个月）
    six_months_ago = datetime.utcnow() - timedelta(days=180)
    
    monthly_posts = db.session.query(
        db.func.strftime('%Y-%m', Post.created_at).label('month'),
        db.func.count(Post.id).label('count')
    ).filter(Post.created_at >= six_months_ago
    ).group_by('month').order_by('month').all()

    # 转换数据结构用于图表
    chart_category_counts = [{'category': c[0], 'count': c[1]} for c in category_counts]
    chart_monthly_posts = [{'month': m[0], 'count': m[1]} for m in monthly_posts]

    return render_template('admin/dashboard.html',
                         total_posts=total_posts,
                         category_counts=chart_category_counts,
                         latest_posts=latest_posts,
                         total_users=total_users,
                         latest_user=latest_user,
                         monthly_posts=chart_monthly_posts)

# 后台分类管理路由
@app.route('/admin/category/<category>')
@login_required
@admin_required
def admin_category(category):
    posts = Post.query.filter_by(category=category).order_by(Post.created_at.desc()).all()
    return render_template('admin/category.html', 
                         posts=posts,
                         category=category)

# 后台文章删除路由
@app.route('/admin/post/delete/<int:post_id>')
@login_required
@admin_required
def admin_delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('admin_category', category=post.category))

# 后台文章编辑路由
@app.route('/admin/post/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.content = request.form['content']
        post.category = request.form['category']
        db.session.commit()
        return redirect(url_for('admin_category', category=post.category))
    return render_template('admin/post_edit.html', post=post)

# 用户认证
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='用户名已存在')
        
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# 管理功能
@app.route('/admin/posts')
@login_required
@admin_required
def manage_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/post_list.html', posts=posts)

class EmptyPost:
    """用于新建文章的默认空值对象"""
    def __init__(self):
        self.title = ""
        self.content = ""
        self.category = ""

@app.route('/admin/post/new', methods=['GET', 'POST'])
@login_required
@admin_required
def new_post():
    if request.method == 'POST':
        # 保持原有提交逻辑不变
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        
        new_post = Post(
            title=title,
            content=content,
            category=category,
            user_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('manage_posts'))
    
    # GET请求时传递初始化对象
    return render_template(
        'admin/post_edit.html', 
        post=EmptyPost(),  # 传递实例而非类
        is_edit_mode=False  # 添加模式标识
    )

@app.route('/admin/post/delete/<int:post_id>')
@login_required
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('manage_posts'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# 新增后台首页重定向
@app.route('/admin')
@login_required
@admin_required
def admin_redirect():
    return redirect(url_for('admin_dashboard'))

@app.route('/upload', methods=['POST'])  # 如果需要图片上传功能需要实现这个路由
@login_required
@admin_required
def upload_file():
    # 这里实现文件上传逻辑
    pass








# 在文件最后添加
application = app