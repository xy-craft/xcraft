# config.py

import os

# 安全密钥（用于会话加密，务必修改为随机字符串）
SECRET_KEY = 'your-secret-key-123'  # 示例值，请替换成自己的随机字符串

# 数据库配置（自动创建到项目目录下的 database 文件夹）
basedir = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'database/blog.db')

# 关闭SQLAlchemy事件系统警告
SQLALCHEMY_TRACK_MODIFICATIONS = False
