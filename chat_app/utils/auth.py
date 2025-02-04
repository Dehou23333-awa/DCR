# chat_app/utils/auth.py
from flask import session, render_template, redirect, url_for
from functools import wraps
from chat_app.db.database import get_user_by_username


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session.permanent = True # Make session permanent for lifetime setting to work
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        else:
            username = session['username']
            user = get_user_by_username(username)
            if not user:
                session.clear()
                return redirect(url_for('auth.login'))
            if user['session_id'] != session.get('session_id_db'):
                session.clear()
                return render_template('message.html', title="登录状态失效", message="你的登录状态已失效，请重新登录")
            if user['is_banned']:
                session.clear()
                return render_template('message.html', title="账户已封禁", message="你的账户已被封禁，无法进行任何操作")
            return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session.permanent = True  # Make session permanent for lifetime setting to work
        admin_username = session.get('original_admin_session', {}).get('username') or session.get('username')  # 优先使用原始管理员用户名，如果存在模拟登录 session
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        else:
            username = session['username']
            user = get_user_by_username(admin_username)  # 使用原始管理员用户名获取用户信息
            if not user:
                session.clear()
                return redirect(url_for('auth.login'))
            if user['session_id'] != session.get('session_id_db'):
                session.clear()
                return render_template('message.html', title="登录状态失效", message="你的账号已在其他设备登录，请重新登录")
            if user['is_banned']:
                session.clear()
                return render_template('message.html', title="账户已封禁", message="你的账户已被封禁，无法进行任何操作")
            if not user['is_admin']:
               return render_template('message.html', title="权限错误", message="你没有管理员权限！")
            if not session.get('admin_confirmed'):
                return redirect(url_for('admin.admin_login'))
            return f(*args, **kwargs)

    return decorated_function