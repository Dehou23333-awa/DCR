# Dehou Chat Room (DCR)

## 简介

Dehou Chat Room (DCR) 是一个简洁、实时的在线聊天室应用程序，基于 Flask 和 Socket.IO 构建。它旨在提供流畅的用户体验，支持多聊天室、用户管理和管理员权限等功能。

## 特性

* **实时聊天**: 使用 Socket.IO 实现实时消息传递。
* **多聊天室**: 支持创建和管理多个聊天室。
* **用户认证**: 提供登录、注销、注册功能。
* **用户管理**:
    * 管理员可以设置用户权限、封禁用户、删除用户、强制登出用户、登录到其他用户。
* **权限控制**: 使用 `login_required` 和 `admin_required` 装饰器进行身份验证和权限控制。
* **消息过滤**: 使用 `bleach` 过滤消息，防止 XSS 攻击。
* **日志记录**: 使用结构化日志记录应用程序的运行状态，方便调试和排查问题。
* **分页加载**: 聊天记录分页加载，优化性能。
* **用户面板**: 用户可以修改昵称和密码。
* **"记住用户名"**: 登录页面可以记住用户名。
* **内容安全策略 (CSP)**: 应用程序使用 CSP header 来增强安全性。

## 技术栈

* Python
* Flask
* Flask-SocketIO
* SQLite
* Werkzeug
* python-dotenv
* bleach
* daisyui
* tailwindcss
* pytz

## 快速开始

### 1. 克隆代码

```bash
git clone https://github.com/Dehou23333-awa/DCR.git
cd DCR
```

### 2. 创建并激活虚拟环境

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows
```

### 3. 安装依赖

```bash
pip install -r requirements.txt
```

### 4. 配置环境变量

创建 .env 文件，并添加以下环境变量 (示例):

```bash
DATABASE_URL=./chat.db
SECRET_KEY=YOUR_SECRET_KEY  # 请务必修改成你自己的安全密钥
```

### 5. 初始化数据库

```python
# 应用会自动初始化数据库，无需手动执行。
# 但如果需要手动初始化，可以运行以下代码：
# python
# from chat_app import create_app
# app, _ = create_app()
# with app.app_context():
#     from chat_app.db import database
#     database.init_db()
```

### 6. 运行应用程序

```bash
python main.py
```

### 7. 打开浏览器，访问 `http://127.0.0.1:5000/`。

## 管理员登录

* 默认管理员用户名: admin
* 默认管理员密码: CHANGEME （请务必在首次登录后立即修改密码！）

## 注意事项

* 安全性: 请务必修改 .env 文件中的 SECRET_KEY，以确保应用程序的安全性。

## 贡献

欢迎提交 Pull Request!