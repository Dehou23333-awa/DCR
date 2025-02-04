# chat_app/routes/chat.py
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from chat_app.utils.auth import login_required, admin_required
from chat_app.db.database import get_all_messages, delete_message, get_user_by_username, get_user_rooms, is_user_in_room, get_online_users, update_user_nickname, update_user_password
from werkzeug.security import check_password_hash, generate_password_hash
from chat_app.db.database import get_db_connection


chat_bp = Blueprint('chat', __name__)

MESSAGES_PER_PAGE = 10 # 定义每页消息数量

@chat_bp.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('chat.introduction'))
    return redirect(url_for('chat.chat'))

@chat_bp.route('/introduction')
def introduction():
    return render_template('introduction.html')


@chat_bp.route('/chat')
@login_required
def chat():
    user = get_user_by_username(session['username'])
    room_id = request.args.get('room_id', None, type=int)
    page = request.args.get('page', 1, type=int)
    offset = (page - 1) * MESSAGES_PER_PAGE
    messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE, offset=offset)
    user_rooms = get_user_rooms(session['username'])
    return render_template('chat_room.html', username=session['username'], user=user, online_users=get_online_users(), messages=messages, is_admin=user['is_admin'],  current_room_id=room_id, is_user_in_room=is_user_in_room(room_id, session['username']), rooms=user_rooms, page=page, messages_per_page=MESSAGES_PER_PAGE)


@chat_bp.route('/chat/delete_message', methods=['POST'])
@admin_required
def chat_delete_message():
    message_id = request.form['message_id']
    room_id = request.args.get('room_id', None, type=int)
    delete_message(message_id)
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        page = request.args.get('page', 1, type=int) # 获取当前页码
        offset = (page - 1) * MESSAGES_PER_PAGE # 计算 offset
        messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE, offset=offset) # 重新获取当前页消息
        return jsonify({'status': 'success', 'messages': messages})
    return redirect(url_for('chat.chat', room_id=room_id))


@chat_bp.route('/chat/load_more_messages') # 新的加载更多消息路由
@login_required
def load_more_messages():
    room_id = request.args.get('room_id', type=int)
    page = request.args.get('page', type=int)
    if not room_id or not page:
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400

    offset = (page - 1) * MESSAGES_PER_PAGE
    messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE, offset=offset)
    if not messages: # 如果没有更多消息，返回空列表
        return jsonify({'status': 'no_more', 'messages': []})
    return jsonify({'status': 'success', 'messages': messages, 'next_page': page + 1}) # 返回消息和下一页页码

@chat_bp.route('/user_panel', methods=['GET'])
@login_required
def user_panel():
    error = None
    success = None
    user = get_user_by_username(session['username'])
    is_impersonating = session.get('is_impersonating', False)

    return render_template('user_panel.html', user=user, error=error, success=success, is_impersonating = is_impersonating)

@chat_bp.route('/user_panel/nickname', methods=['POST'])
@login_required
def user_panel_nickname():
    error = None
    success = None
    user = get_user_by_username(session['username'])
    is_impersonating = session.get('is_impersonating', False)
    if 'nickname' in request.form:  # 处理昵称修改
        nickname = request.form['nickname']
        update_user_nickname(session['username'], nickname)
        success = "昵称修改成功！"

    return render_template('user_panel.html', user=user, error=error, success=success, is_impersonating = is_impersonating)


@chat_bp.route('/user_panel/password', methods=['POST'])
@login_required
def user_panel_password():
    error = None
    success = None
    user = get_user_by_username(session['username'])
    is_impersonating = session.get('is_impersonating', False)
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
                update_user_password(user['username'], password_hash)
                conn = get_db_connection()
                conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (user['username'],))
                conn.commit()
                conn.close()
                success = "密码修改成功！"
        else:  # 普通用户修改密码
            current_password = request.form['current_password']
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
    return render_template('user_panel.html', user=user, error=error, success=success, is_impersonating = is_impersonating)
