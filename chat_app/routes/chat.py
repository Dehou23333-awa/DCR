# chat_app/routes/chat.py
from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from chat_app.db.database import get_all_messages, delete_message, get_user_by_username, get_user_rooms, \
    is_user_in_room, get_online_users, update_user_nickname, update_user_password, get_db_connection
from chat_app.utils.auth import login_required, admin_required

chat_bp = Blueprint('chat', __name__)

MESSAGES_PER_PAGE = 10  # 定义每页消息数量


@chat_bp.route('/')
def index():
    """
    重定向到介绍页或聊天室。
    如果用户已登录，重定向到聊天室。否则，重定向到介绍页。
    """
    if 'username' not in session:
        return redirect(url_for('chat.introduction'))  # 重定向到介绍页
    return redirect(url_for('chat.chat'))  # 重定向到聊天室


@chat_bp.route('/introduction')
def introduction():
    """
    显示介绍页面.
    """
    return render_template('introduction.html')


@chat_bp.route('/chat')
@login_required
def chat():
    """
    显示聊天室页面。
    需要用户登录才能访问。
    """
    user = get_user_by_username(session['username'])  # 获取当前用户信息
    room_id = request.args.get('room_id', None, type=int)  # 获取聊天室 ID
    page = request.args.get('page', 1, type=int)  # 获取当前页码
    offset = (page - 1) * MESSAGES_PER_PAGE  # 计算消息偏移量
    messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE,
                                offset=offset)  # 获取当前页的消息
    user_rooms = get_user_rooms(session['username'])  # 获取用户所在的聊天室列表

    return render_template('chat_room.html',
                           username=session['username'],
                           user=user,
                           online_users=get_online_users(),  # 获取在线用户列表
                           messages=messages,
                           is_admin=user['is_admin'],
                           current_room_id=room_id,
                           is_user_in_room=is_user_in_room(room_id, session['username']),
                           rooms=user_rooms,  # 用户所在的聊天室列表
                           page=page,
                           messages_per_page=MESSAGES_PER_PAGE)


@chat_bp.route('/chat/delete_message', methods=['POST'])
@admin_required
def chat_delete_message():
    """
    删除指定消息。
    只有管理员才能访问。
    """
    message_id = request.form['message_id']  # 获取消息 ID
    room_id = request.args.get('room_id', None, type=int) # 获取房间 ID
    delete_message(message_id)  # 删除消息
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':  # AJAX 请求
        page = request.args.get('page', 1, type=int)  # 获取当前页码
        offset = (page - 1) * MESSAGES_PER_PAGE  # 计算 offset
        messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE,
                                    offset=offset)  # 重新获取当前页消息
        return jsonify({'status': 'success', 'messages': messages})  # 返回成功状态和消息列表

    return redirect(url_for('chat.chat', room_id=room_id))  # 重定向到聊天室


@chat_bp.route('/chat/load_more_messages')  # 新的加载更多消息路由
@login_required
def load_more_messages():
    """
    加载更多消息。
    使用 AJAX 请求。
    """
    room_id = request.args.get('room_id', type=int)  # 获取房间 ID
    page = request.args.get('page', type=int)  # 获取页码
    if not room_id or not page:
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400  # 缺少参数，返回错误

    offset = (page - 1) * MESSAGES_PER_PAGE  # 计算消息偏移量
    messages = get_all_messages(room_id, session['username'], limit=MESSAGES_PER_PAGE,
                                offset=offset)  # 获取消息
    if not messages:  # 如果没有更多消息，返回空列表
        return jsonify({'status': 'no_more', 'messages': []})
    return jsonify({'status': 'success', 'messages': messages, 'next_page': page + 1})  # 返回消息和下一页页码


@chat_bp.route('/user_panel', methods=['GET'])
@login_required
def user_panel():
    """
    显示用户面板.
    用户可以修改昵称和密码。
    """
    error = None
    success = None
    user = get_user_by_username(session['username'])  # 获取当前用户信息
    is_impersonating = session.get('is_impersonating', False) # 获取是否处于模拟登录状态的标识

    return render_template('user_panel.html', user=user, error=error, success=success,
                           is_impersonating=is_impersonating)


@chat_bp.route('/user_panel/nickname', methods=['POST'])
@login_required
def user_panel_nickname():
    """
    处理修改昵称的请求。
    """
    error = None
    success = None
    user = get_user_by_username(session['username']) # 获取当前用户信息
    is_impersonating = session.get('is_impersonating', False)

    if 'nickname' in request.form:  # 处理昵称修改
        nickname = request.form['nickname']  # 获取昵称
        update_user_nickname(session['username'], nickname)  # 更新昵称
        success = "昵称修改成功！"

    return render_template('user_panel.html', user=user, error=error, success=success,
                           is_impersonating=is_impersonating)


@chat_bp.route('/user_panel/password', methods=['POST'])
@login_required
def user_panel_password():
    """
    处理修改密码的请求.
    """
    error = None
    success = None
    user = get_user_by_username(session['username']) # 获取当前用户信息
    is_impersonating = session.get('is_impersonating', False)  # 获取是否处于模拟登录状态
    new_password = request.form['new_password']  # 获取新密码
    confirm_password = request.form['confirm_password'] # 获取确认密码

    if len(new_password) == 0: # 新密码为空
        error = "新密码不能为空"
    elif new_password != confirm_password: # 两次输入的新密码不一致
        error = "两次输入的新密码不一致"
    else:
        if is_impersonating:  # 管理员模拟登录
            admin_password = request.form['admin_password'] # 获取管理员密码
            admin_user = get_user_by_username(session.get('original_admin_session', {}).get('username')) #  获取管理员用户信息
            if not admin_user or not check_password_hash(admin_user['password'], admin_password): # 管理员密码错误
                error = "管理员密码错误"
            else:
                password_hash = generate_password_hash(new_password) # 生成密码哈希值
                update_user_password(user['username'], password_hash)  # 修改密码
                conn = get_db_connection()
                conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (user['username'],))
                conn.commit()
                conn.close()
                success = "密码修改成功！"
        else:  # 普通用户修改密码
            current_password = request.form['current_password']  # 获取当前密码
            if not user or not check_password_hash(user['password'], current_password): # 当前密码错误
                error = "当前密码错误"
            else:
                password_hash = generate_password_hash(new_password)  # 生成密码哈希值
                update_user_password(session['username'], password_hash)  # 修改密码
                conn = get_db_connection()
                conn.execute('UPDATE users SET password_changed_on_first_login = 1 WHERE username = ?', (session['username'],))
                conn.commit()
                conn.close()
                success = "密码修改成功！"

    return render_template('user_panel.html', user=user, error=error, success=success,
                           is_impersonating=is_impersonating)