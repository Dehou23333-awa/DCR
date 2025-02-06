# chat_app/__init__.py
import json  # 导入 json 模块
import logging
import os
import secrets
from logging.handlers import RotatingFileHandler

from dotenv import load_dotenv
# 引入 CSRFProtect
from flask import Flask, session, request, send_from_directory
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
# 注册蓝图
from chat_app.config import Config
from chat_app.db.database import init_db, create_default_admin_user_if_not_exists
from chat_app.routes import auth, chat, admin
from chat_app.socket import events
from chat_app.utils.helpers import inject_functions


class JsonFormatter(logging.Formatter):  # 自定义 JSON Formatter
    def format(self, record):
        log_data = {
            'timestamp': self.formatTime(record, self.datefmt),
            'level': record.levelname,
            'logger_name': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'funcName': record.funcName,
            'lineno': record.lineno,
            'threadName': record.threadName,
            'processName': record.processName,
            'extra': record.__dict__.get('extra', {})  # Include extra context
        }
        return json.dumps(log_data, ensure_ascii=False)  # ensure_ascii=False for non-ascii characters


def create_app(config_class=Config):
    # 加载 .env 配置文件
    load_dotenv()

    # 创建 Flask 应用实例
    app = Flask(__name__)

    # 从配置类中加载配置
    app.config.from_object(config_class)

    # 获取 SECRET_KEY 环境变量
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    # 设置 session 的有效期
    app.config['PERMANENT_SESSION_LIFETIME'] = 2 * 60 * 60

    # 配置日志记录到文件，使用 JSON 格式
    log_file = 'chat_app.log'
    file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024 * 10,
                                       backupCount=5)  # 10MB max size, keep 5 backups
    file_handler.setLevel(logging.INFO)  # Set log level to INFO or DEBUG as needed
    formatter = JsonFormatter()  # 使用自定义 JSON Formatter
    file_handler.setFormatter(formatter)

    # 获取 root logger 并添加 handler
    log = logging.getLogger('')
    log.addHandler(file_handler)
    log.setLevel(logging.INFO)  # 设置 root logger level, 确保能捕捉到 INFO 级别日志

    # 初始化数据库
    with app.app_context():
        init_db()
        create_default_admin_user_if_not_exists()

    # 注册蓝图
    app.register_blueprint(auth.auth_bp)
    app.register_blueprint(chat.chat_bp)
    app.register_blueprint(admin.admin_bp)

    # 注入函数到模板上下文
    app.context_processor(inject_functions)

    # 初始化 SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*",
                        ping_interval=10,
                        ping_timeout=8, logger=log, engineio_logger=log)

    # 初始化 SocketIO 事件
    events.init_socketio_events(socketio)

    # 启用 CSRF 保护
    CSRFProtect(app)
    # 应用启动时记录日志
    app.logger.info("App started")

    # 添加 CSP 头部
    @app.after_request
    def add_csp_header(response):
        csp_policy = {
            'default-src': '\'self\'',  # 默认只允许加载来自本站点的资源
            'script-src': [
                '\'self\'',
                '\'unsafe-inline\'',
                #  如果你的 JS 代码中有 inline script, 需要添加 'unsafe-inline'， 生产环境强烈不推荐使用 inline script, 最好将 JS 代码都放在单独的文件中
            ],
            'style-src': [
                '\'self\'',
                '\'unsafe-inline\'',
                # 如果使用了 inline style, 需要添加 'unsafe-inline', 生产环境强烈不推荐使用 inline style
            ],
            'img-src': ['\'self\'', 'data:'],  # 允许加载来自本站和 data URI 的图片
            'font-src': ['\'self\''],  # 允许从 jsdelivr 加载字体 (daisyui)
            'connect-src': ['\'self\'', 'ws:', 'wss:'],  # 允许WebSocket 连接
        }
        csp_header = "; ".join([f"{k} {' '.join(v)}" for k, v in csp_policy.items()])
        response.headers['Content-Security-Policy'] = csp_header
        return response

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

    return app, socketio