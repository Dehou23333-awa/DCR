# chat_app/config.py
import os

import pytz
from dotenv import load_dotenv

load_dotenv()


class Config:
    # 设置时区
    TIMEZONE = pytz.timezone('Asia/Shanghai')
    # 从环境变量中获取数据库 URL
    DATABASE = os.environ.get('DATABASE_URL')
    # 从环境变量中获取 SECRET_KEY
    SECRET_KEY = os.environ.get('SECRET_KEY')
    # 设置 Session Cookie 为安全模式
    SESSION_COOKIE_SECURE = True
    # 设置 Session Cookie 为 HTTP Only
    SESSION_COOKIE_HTTPONLY = True