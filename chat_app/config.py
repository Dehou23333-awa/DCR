# chat_app/config.py
from dotenv import load_dotenv
import os
import pytz
load_dotenv()

class Config:
  TIMEZONE = pytz.timezone('Asia/Shanghai')
  DATABASE = os.environ.get('DATABASE_URL')
  SECRET_KEY = os.environ.get('SECRET_KEY')
  SESSION_COOKIE_SECURE = True
  SESSION_COOKIE_HTTPONLY = True