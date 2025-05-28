# app.py

from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, 
    current_user, 
    login_user, 
    logout_user, 
    login_required, 
    UserMixin
)
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import markdown
from sqlalchemy import func, text

app = Flask(__name__)
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

# ========== 模型定义 ========== #

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    username = db.Column(db.String(20), unique=True, nullable=False) # 关闭递增
    id = db.Column(db.Integer, primary_key=True, autoincrement=False)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    permissions = db.Column(db.Integer, default=0)
    reg_date = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship('Post', backref='author', lazy=True)

class AvailableUID(db.Model):
    __tablename__ = 'available_uids'
    uid = db.Column(db.Integer, primary_key=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# 新建文章EmptyPost的类定义
class EmptyPost:
    """用于新建文章的默认空值对象"""
    def __init__(self):
        self.id = None       # 添加id属性
        self.title = ""
        self.content = ""
        self.category = "OI" # 设置默认分类
        self.created_at = datetime.utcnow()  # 可选添加

def has_permission(self, perm):
    if self.is_admin:
        return True
    return (self.permissions & perm) == perm

# 3. 实现UID查找逻辑
def find_available_uid():
    # 优先从回收池获取最小的UID
    recycled_uid = db.session.query(
        db.func.min(AvailableUID.uid)
    ).scalar()
    
    if recycled_uid is not None:
        return recycled_uid
    
    # 查找现有UID中的空缺
    existing_uids = [u[0] for u in User.query.with_entities(User.id).order_by(User.id).all()]
    
    # 如果没有任何用户，返回1
    if not existing_uids:
        return 1
    
    # 查找第一个空缺
    for i in range(1, existing_uids[-1]):
        if i not in existing_uids:
            return i
    
    # 没有空缺则返回最大UID+1
    return existing_uids[-1] + 1

    gap = db.session.query(
        (subquery.c.prev_id + 1).label('available_uid')
    ).filter(
        subquery.c.id > subquery.c.prev_id + 1
    ).order_by(subquery.c.prev_id).first()

    if gap:
        return gap.available_uid
    
    # 没有空缺则返回当前最大值+1
    max_uid = db.session.query(func.max(User.id)).scalar() or 0
    return max_uid + 1

# 4. 带锁的安全查找函数

def find_available_uid_safe():
    """安全获取可用UID（无显式事务）"""
    try:
        # 优先从回收池获取最小UID
        recycled_uid = db.session.query(
            db.func.min(AvailableUID.uid)
        ).scalar()

        if recycled_uid:
            # 立即删除该UID记录
            db.session.query(AvailableUID).filter_by(uid=recycled_uid).delete()
            return recycled_uid

        # 查找现有用户ID的空缺
        existing_uids = [u[0] for u in db.session.query(User.id).order_by(User.id).all()]
        
        # 处理空数据库情况
        if not existing_uids:
            return 1
        
        # 查找第一个空缺
        for i in range(1, existing_uids[-1]):
            if i not in existing_uids:
                return i
        
        # 没有空缺则返回最大值+1
        return existing_uids[-1] + 1

    except Exception as e:
        raise RuntimeError(f"UID分配失败: {str(e)}")
    

migrate = Migrate(app, db)

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

# 自定义过滤器
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return ""
    return value.strftime(format)

# 注册过滤器到Jinja环境
app.jinja_env.filters['datetimeformat'] = datetimeformat

# 路由部分

# 首页路由
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
    welcome_html = markdown.markdown(welcome_content, extras=["latex"])

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
    html_content = markdown.markdown(post.content, extras=["fenced-code-blocks", "tables", "latex"])
    return render_template('post.html', post=post, content=html_content)

# 用户列表路由
@app.route('/user')
@login_required
def user_list():
    users = User.query.order_by(User.reg_date.desc()).all()
    return render_template('user_list.html', users=users)

# 用户详情路由
@app.route('/user/<int:uid>')
@login_required
def user_detail(uid):
    user = User.query.get_or_404(uid)
    # 获取用户最近发布的5篇文章
    posts = Post.query.filter_by(user_id=uid).order_by(Post.created_at.desc()).limit(5).all()
    return render_template('user_detail.html', 
                         user=user,
                         posts=posts)

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
    latest_user = User.query.order_by(User.reg_date.desc()).first()
    
    # 月度文章趋势（最近6个月）
    six_months_ago = datetime.utcnow() - timedelta(days=180)
    
    monthly_posts = db.session.query(
        db.func.date_format(Post.created_at, '%Y-%m').label('month'),
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

# 后台首页重定向
@app.route('/admin')
@login_required
@admin_required
def admin_redirect():
    return redirect(url_for('admin_dashboard'))

# 后台分类管理路由
@app.route('/admin/category/<category>')
@login_required
@admin_required
def admin_category(category):
    posts = Post.query.filter_by(category=category).order_by(Post.created_at.desc()).all()
    return render_template('admin/category.html', 
                         posts=posts,
                         category=category)

# 后台文章展示路由
@app.route('/admin/post/<int:post_id>')
@login_required
@admin_required
def admin_show_post(post_id):
    post = Post.query.get_or_404(post_id)
    html_content = markdown.markdown(post.content, extras=["fenced-code-blocks", "tables", "latex"])
    return render_template('admin/post.html', 
                         post=post, 
                         content=html_content)

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

# 后台文章路由列表
@app.route('/admin/posts')
@login_required
@admin_required
def manage_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    return render_template('admin/post_list.html', posts=posts)



# 新建文章
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
    
    # 获取默认分类（新增代码）
    default_category = request.args.get('default_category', 'OI')  # 从URL参数获取
    
    # 创建带默认分类的空文章对象（修改此处）
    empty_post = EmptyPost()
    empty_post.category = default_category  # 动态设置默认分类
    
    return render_template(
        'admin/post_edit.html', 
        post=empty_post,
        is_edit_mode=False
    )

# 删除文章
@app.route('/admin/post/delete/<int:post_id>')
@login_required
@admin_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('manage_posts'))

# 用户列表路由
@app.route('/admin/user')
@login_required
@admin_required
def admin_user_list():
    users = User.query.order_by(User.reg_date.desc()).all()
    return render_template('admin/user_list.html', users=users)

# 用户详情路由
@app.route('/admin/user/<int:uid>')
@login_required
@admin_required
def admin_user_detail(uid):
    user = User.query.get_or_404(uid)
    # 获取用户最近发布的5篇文章
    posts = Post.query.filter_by(user_id=uid).order_by(Post.created_at.desc()).limit(5).all()
    return render_template('admin/user_detail.html', 
                         user=user,
                         posts=posts)

# 后台用户编辑路由
@app.route('/admin/user/edit/<int:uid>', methods=['GET', 'POST'])
def admin_edit_user(uid):
    user = User.query.get_or_404(uid)
    
    if request.method == 'POST':

        # 基础字段更新
        user.username = request.form['username']
        user.is_admin = True if request.form.get('is_admin') == 'on' else False
        
        # 密码修改逻辑
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if new_password or confirm_password:
            if new_password != confirm_password:
                flash('两次输入的密码不一致', 'danger')
                return redirect(url_for('admin_edit_user', uid=uid))
                
            if len(new_password) < 6:
                flash('密码长度至少6个字符', 'danger')
                return redirect(url_for('admin_edit_user', uid=uid))
                
            user.password = generate_password_hash(new_password)
            flash('密码已更新', 'success')

        # uid修改逻辑，开启事务
        db.session.begin_nested()
        
        # 获取新旧UID
        old_uid = user.id
        new_uid = request.form.get('uid', type=int)
        
        # 验证新UID
        if not new_uid or new_uid < 1:
            raise ValueError("UID必须为正整数")
            
        if new_uid == old_uid:
            raise ValueError("UID未变更")
            
        if User.query.get(new_uid):
            raise ValueError("该UID已被占用")
        
        # 检查回收池是否包含新UID
        if AvailableUID.query.get(new_uid):
            # 从回收池移除新UID
            db.session.execute(
                text("DELETE FROM available_uids WHERE uid = :uid"),
                {"uid": new_uid}
            )
        
        # 更新所有关联数据（示例更新posts表）
        Post.query.filter_by(user_id=old_uid).update(
            {Post.user_id: new_uid},
            synchronize_session=False
        )
        
        # 将旧UID加入回收池
        db.session.execute(
            text("""
                INSERT INTO available_uids (uid) 
                SELECT :old_uid
                WHERE NOT EXISTS (
                    SELECT 1 FROM available_uids WHERE uid = :old_uid
                )
            """),
            {"old_uid": old_uid}
        )
        
        # 更新用户UID
        user.id = new_uid
        
        # 更新其他字段
        user.username = request.form['username']
        user.is_admin = request.form.get('is_admin') == 'on'

        try:
            db.session.commit()
            flash('用户信息更新成功', 'success')
            return redirect(url_for('admin_user_detail', uid=new_uid))
            
        except Exception as e:
            db.session.rollback()
            flash(f'更新失败: {str(e)}', 'danger')

    return render_template('admin/user_edit.html', user=user)

# 后台用户删除路由
@app.route('/admin/user/delete/<int:uid>')
@login_required
@admin_required
def admin_delete_user(uid):
    user = User.query.get_or_404(uid)
    
    if user.is_admin:
        flash('管理员账户受保护，不可删除', 'danger')
        return redirect(url_for('admin_user_list'))
    
    try:
        # 删除用户文章
        Post.query.filter_by(user_id=uid).delete()
        
        # 使用正确的表存在检查方式
        from sqlalchemy import inspect
        inspector = inspect(db.engine)
        
        if inspector.has_table("available_uids"):
            db.session.execute(
                text("INSERT INTO available_uids (uid) VALUES (:uid)"),
                {"uid": uid}
            )
        else:
            app.logger.warning("available_uids 表不存在，跳过UID回收")
        
        # 删除用户
        db.session.delete(user)
        db.session.commit()
        flash('用户已成功删除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'删除失败: {str(e)}', 'danger')
    
    return redirect(url_for('admin_user_list'))

# 用户注册
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 检查用户名是否存在
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error='用户名已存在')
        
        try:
            # 获取可用UID
            new_uid = find_available_uid_safe()
            
            # 判断是否是第一个用户
            is_first_user = User.query.count() == 0
            
            # 创建新用户
            new_user = User(
                id=new_uid,
                username=username,
                password=generate_password_hash(password),
                is_admin=is_first_user  # 第一个用户设为管理员
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"注册失败: {str(e)}")
            return render_template('register.html', error=f'注册失败: {str(e)}')
    
    return render_template('register.html')

# 用户认证
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])  # 如果需要图片上传功能需要实现这个路由
@login_required
@admin_required
def upload_file():
    # 这里实现文件上传逻辑
    pass


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, use_reloader=True)