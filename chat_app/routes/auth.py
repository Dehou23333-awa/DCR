from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from chat_app.db.database import register_user, validate_user, set_user_online, get_user_by_username, \
    update_user_password, get_db_connection
from chat_app.utils.auth import login_required, admin_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    用户登录页面。
    """
    error = None
    if 'username' in session: # 如果已经登录，重定向到聊天室
        return redirect(url_for('chat.chat'))

    if request.method == 'POST':
        username = request.form['username'] # 获取用户名
        password = request.form['password']  # 获取密码
        is_valid, message = validate_user(username, password)  # 验证用户
        if is_valid:
            session['username'] = username  # 将用户名存储到 session 中
            set_user_online(username, True)  # 设置用户在线状态

            if message == "请修改您的初始密码":  # 检查提示消息是否是 "请修改您的初始密码"
                return redirect(url_for('auth.change_password',
                                        first_login=True))  # 重定向到 change_password 页面，并传递 first_login=True 参数

            return redirect(url_for('chat.chat'))  # 正常登录成功，重定向到 chat 页面
        else:
            error = message if message else "用户名或密码错误" # 设置错误信息
    return render_template('login.html', error=error) # 显示登录页面


@auth_bp.route('/logout')
def logout():
    """
    用户注销.
    """
    if 'username' in session:
        username = session['username'] # 获取用户名
        set_user_online(username, False) # 设置用户离线状态

        # 登出时，将数据库中的 session_id 设置为 NULL, 使session失效
        conn = get_db_connection()
        conn.execute('UPDATE users SET session_id = NULL WHERE username = ?', (username,))
        conn.commit()
        conn.close()

        session.pop('username', None)  # 从 session 中移除用户名
        session.pop('session_id_db', None) # 从session 中移除 session id
        session.pop('is_impersonating', None) # 从session 中移除模拟登录标识
        session.pop('original_admin_session', None) # 从session 中移除管理员登录信息
        session.pop('admin_confirmed', None) # 从session 中移除管理员验证状态

    return redirect(url_for('auth.login')) # 重定向到登录页面


@auth_bp.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    """
    用户注册页面 (仅管理员可以访问).
    """
    if request.method == 'POST':
        username = request.form['username'] # 获取用户名
        password = request.form['password'] # 获取密码
        password_hash = generate_password_hash(password) # 生成密码哈希值
        if register_user(username, password_hash):  # 注册用户
            return redirect(url_for('admin.admin')) # 注册成功，重定向到管理员面板
        else:
            return render_template('message.html', title="注册失败", message="用户名已存在") # 注册失败，用户名已存在

    return render_template('register.html') # 显示注册页面


@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """
    修改密码页面.
    需要用户登录才能访问。
    """
    error = None
    success = None
    first_login = request.args.get('first_login', False)  # 获取是否是第一次登录
    is_impersonating = session.get('is_impersonating', False) # 获取当前是否是模拟登录状态

    if request.method == 'POST':
        new_password = request.form['new_password'] # 获取新密码
        confirm_password = request.form['confirm_password']  # 获取确认密码

        if len(new_password) == 0:
            error = "新密码不能为空"  # 新密码为空
        elif new_password != confirm_password:
            error = "两次输入的新密码不一致" # 两次输入的新密码不一致
        else:
            if is_impersonating:  # 管理员模拟登录
                admin_password = request.form['admin_password']  # 获取管理员密码
                admin_user = get_user_by_username(session.get('original_admin_session', {}).get('username'))  # 获取管理员用户信息

                if not admin_user or not check_password_hash(admin_user['password'], admin_password): # 管理员密码错误
                    error = "管理员密码错误"
                else:
                    password_hash = generate_password_hash(new_password)  # 生成密码哈希值
                    update_user_password(session['username'], password_hash) # 更新密码
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (session['username'],))
                    conn.commit()
                    conn.close()
                    success = "密码修改成功！"
                    return render_template('message.html', title="密码修改成功", message="您的密码已成功修改！",
                                           redirect_url=url_for('chat.chat'))  # 修改成功，重定向到聊天室
            else:  # 普通用户修改密码
                current_password = request.form['current_password'] # 获取当前密码
                user = get_user_by_username(session['username'])  # 获取当前用户信息

                if not user or not check_password_hash(user['password'], current_password):  # 当前密码错误
                    error = "当前密码错误"
                else:
                    password_hash = generate_password_hash(new_password) # 生成密码哈希值
                    update_user_password(session['username'], password_hash)  # 更新密码
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (session['username'],))
                    conn.commit()
                    conn.close()
                    success = "密码修改成功！"
                    return render_template('message.html', title="密码修改成功", message="您的密码已成功修改！",
                                           redirect_url=url_for('chat.chat'))  # 修改成功，重定向到聊天室

    return render_template('change_password.html', error=error, success=success, first_login=first_login,
                           is_impersonating=is_impersonating) # 显示修改密码页面