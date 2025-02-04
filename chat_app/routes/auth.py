from flask import Blueprint, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from chat_app.db.database import register_user, validate_user, set_user_online, get_user_by_username, update_user_password, get_db_connection
from chat_app.utils.auth import login_required, admin_required

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if 'username' in session:
        return redirect(url_for('chat.chat'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_valid, message = validate_user(username, password) #  validate_user() 函数现在可能返回提示消息
        if is_valid:
            session['username'] = username
            set_user_online(username, True)
            if message == "请修改您的初始密码": #  检查提示消息是否是 "请修改您的初始密码"
                return redirect(url_for('auth.change_password', first_login=True)) # 重定向到 change_password 页面，并传递 first_login=True 参数
            return redirect(url_for('chat.chat')) #  正常登录成功，重定向到 chat 页面
        else:
            error = message if message else "用户名或密码错误"
    return render_template('login.html', error=error)


@auth_bp.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        set_user_online(username, False)

        # 登出时，将数据库中的 session_id 设置为 NULL
        conn = get_db_connection()
        conn.execute('UPDATE users SET session_id = NULL WHERE username = ?', (username,))
        conn.commit()
        conn.close()

        session.pop('username', None)
        session.pop('session_id_db', None)
        session.pop('is_impersonating', None) # remove impersonating session
        session.pop('original_admin_session', None)
        session.pop('admin_confirmed', None)
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        if register_user(username, password_hash):
            return redirect(url_for('admin.admin'))
        else:
            return render_template('message.html', title="注册失败", message="用户名已存在")
    return render_template('register.html')

@auth_bp.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    error = None
    success = None
    first_login = request.args.get('first_login', False)
    is_impersonating = session.get('is_impersonating', False)
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if len(new_password) == 0:
              error = "新密码不能为空"
        elif new_password != confirm_password:
                error = "两次输入的新密码不一致"
        else:
             if is_impersonating: # 管理员模拟登录
                 admin_password = request.form['admin_password']
                 admin_user = get_user_by_username(session.get('original_admin_session', {}).get('username'))
                 if not admin_user or not check_password_hash(admin_user['password'], admin_password):
                        error = "管理员密码错误"
                 else:
                   password_hash = generate_password_hash(new_password)
                   update_user_password(session['username'], password_hash)
                   conn = get_db_connection()
                   conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (session['username'],))
                   conn.commit()
                   conn.close()
                   success = "密码修改成功！"
                   return render_template('message.html', title="密码修改成功", message="您的密码已成功修改！", redirect_url=url_for('chat.chat'))
             else: # 普通用户修改密码
                current_password = request.form['current_password']
                user = get_user_by_username(session['username'])
                if not user or not check_password_hash(user['password'], current_password):
                    error = "当前密码错误"
                else:
                    password_hash = generate_password_hash(new_password)
                    update_user_password(session['username'], password_hash)
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (session['username'],))
                    conn.commit()
                    conn.close()
                    success = "密码修改成功！"
                    return render_template('message.html', title="密码修改成功", message="您的密码已成功修改！", redirect_url=url_for('chat.chat'))

    return render_template('change_password.html', error=error, success=success, first_login=first_login, is_impersonating=is_impersonating)