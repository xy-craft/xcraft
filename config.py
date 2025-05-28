# config.py

import os

# 安全密钥（用于会话加密，务必修改为随机字符串）
SECRET_KEY = 'your-secret-key-123'  # 示例值，请替换成自己的随机字符串

# MySQL 数据库配置
SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://xcraft:cmqmtxfmVAqxoS4m@mysql2.sqlpub.com:3307/xcraft'
# 关闭SQLAlchemy事件系统警告
SQLALCHEMY_TRACK_MODIFICATIONS = False

# 可选：连接池配置（根据需求调整）
SQLALCHEMY_ENGINE_OPTIONS = {
    'pool_recycle': 3600,  # 每小时内回收连接
    'pool_size': 10,       # 连接池大小
    'max_overflow': 5      # 最大溢出连接数
}