# chat_app/utils/auth.py
from functools import wraps

from flask import session, render_template, redirect, url_for

from chat_app.db.database import get_user_by_username


def login_required(f):
    """
    登录验证装饰器。
    用于保护需要登录才能访问的路由。

    如果用户未登录，则重定向到登录页面。
    如果用户已登录但会话无效或已被封禁，则清除会话并显示相应的错误消息。
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        session.permanent = True  # Make session permanent for lifetime setting to work

        if 'username' not in session:  # 如果用户未登录
            return redirect(url_for('auth.login'))  # 重定向到登录页面

        username = session['username']
        user = get_user_by_username(username)

        if not user:  # 用户不存在
            session.clear()
            return redirect(url_for('auth.login'))

        if user['session_id'] != session.get('session_id_db'):  # session ID 不匹配，说明用户已在其他地方登录
            session.clear()
            return render_template('message.html', title="登录状态失效", message="你的登录状态已失效，请重新登录")  # 显示登录状态失效消息

        if user['is_banned']:
            session.clear()
            return render_template('message.html', title="账户已封禁", message="你的账户已被封禁，无法进行任何操作")  # 显示账户已封禁消息

        return f(*args, **kwargs)  # 用户验证成功，执行被装饰的函数

    return decorated_function


def admin_required(f):
    """
    管理员权限验证装饰器。
    用于保护只有管理员才能访问的路由。

    如果用户未登录或不是管理员，则重定向到登录页面或显示权限错误消息。
    此外，还会检查管理员是否已经通过管理员密码验证，如果没有，重定向到管理员登录页面。
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        session.permanent = True  # Make session permanent for lifetime setting to work
        admin_username = session.get('original_admin_session', {}).get('username') or session.get(
            'username')  # 优先使用原始管理员用户名，如果存在模拟登录 session

        if 'username' not in session:  # 如果用户未登录
            return redirect(url_for('auth.login'))  # 重定向到登录页面

        username = session['username']
        user = get_user_by_username(admin_username)  # 使用原始管理员用户名获取用户信息

        if not user:  # 用户不存在
            session.clear()
            return redirect(url_for('auth.login'))

        if user['session_id'] != session.get('session_id_db'):  # session ID 不匹配，说明用户已在其他地方登录
            session.clear()
            return render_template('message.html', title="登录状态失效", message="你的账号已在其他设备登录，请重新登录")  # 显示登录状态失效消息

        if user['is_banned']:
            session.clear()
            return render_template('message.html', title="账户已封禁", message="你的账户已被封禁，无法进行任何操作")  # 显示账户已封禁消息

        if not user['is_admin']:  # 如果不是管理员
            return render_template('message.html', title="权限错误", message="你没有管理员权限！")  # 显示权限错误消息

        if not session.get('admin_confirmed'): # 管理员未验证，跳转到验证页面
            return redirect(url_for('admin.admin_login')) # 重定向到管理员登录页面

        return f(*args, **kwargs)  # 管理员验证成功，执行被装饰的函数

    return decorated_function