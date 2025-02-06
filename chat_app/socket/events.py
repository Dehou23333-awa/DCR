# chat_app/socket/events.py
from datetime import datetime

from flask import session, request, current_app  # 导入 current_app
from flask_socketio import emit, join_room, disconnect

from chat_app.config import Config
from chat_app.db.database import set_user_online, get_user_by_username, add_message, format_timestamp


def init_socketio_events(socketio):
    """
    初始化 SocketIO 事件处理函数.

    Args:
        socketio: SocketIO 实例.
    """

    @socketio.on('connect')
    def handle_connect():
        """
        处理客户端连接事件.
        """
        try:
            if 'username' in session: # 如果用户已登录
                username = session['username']
                user = get_user_by_username(username)

                if user and user['is_banned']:  # 如果用户已被封禁
                    emit('banned', {'message': '你的账户已被封禁'}, room=request.sid) # 发送封禁消息
                    disconnect(request.sid)  # 断开连接
                    current_app.logger.warning(f"Banned user tried to connect via WebSocket - username: {username}, session_id: {request.sid}") # 记录警告日志
                    return

                set_user_online(username, True)  # 设置用户在线状态
                room_id = request.args.get('room_id', None, type=int)  # 获取聊天室 ID

                if room_id:
                    join_room(f"room_{room_id}") # 加入聊天室
                    emit('user_online', {'username': username, 'room_id': room_id}, broadcast=True,
                         room=f"room_{room_id}")  # 发送用户上线消息

                current_app.logger.info(f"User connected via WebSocket - username: {username}, session_id: {request.sid}, room_id: {room_id}")# 记录连接日志

        except Exception as e:
            current_app.logger.error("Error in handle_connect", exc_info=True,
                                     extra={'session_id': request.sid}) # 记录错误日志

    @socketio.on('disconnect')
    def handle_disconnect():
        """
        处理客户端断开连接事件.
        """
        try:
            if 'username' in session:
                username = session['username']
                user = get_user_by_username(username)

                if user and not user['is_banned']: # 如果用户未被封禁
                    set_user_online(username, False)  # 设置用户离线状态
                    room_id = request.args.get('room_id', None, type=int)  # 获取聊天室 ID
                    if room_id:
                        emit('user_offline', {'username': username, 'room_id': room_id}, broadcast=True,
                             room=f"room_{room_id}")  # 发送用户离线消息
                    current_app.logger.info(
                        f"User disconnected via WebSocket - username: {username}, session_id: {request.sid}, room_id: {room_id}")# 记录断开连接日志

        except Exception as e:
            current_app.logger.error("Error in handle_disconnect", exc_info=True,
                                     extra={'session_id': request.sid})# 记录错误日志

    @socketio.on('send_message')
    def handle_message(data):
        """
        处理客户端发送消息事件.
        """
        try:
            if 'username' in session:
                username = session['username']
                user = get_user_by_username(username)

                if user and user['is_banned']:  # 如果用户已被封禁
                    emit('banned', {'message': '你的账户已被封禁'}, room=request.sid)  # 发送封禁消息
                    disconnect(request.sid) # 断开连接
                    current_app.logger.warning(
                        f"Banned user tried to send message via WebSocket - username: {username}, session_id: {request.sid}, room_id: {data.get('room_id')}")# 记录警告日志
                    return

                message = data['message'] # 获取消息内容
                if not message or not message.strip():  # 如果消息为空
                    current_app.logger.warning(
                        f"Empty message received via WebSocket - username: {username}, session_id: {request.sid}, room_id: {data.get('room_id')}")# 记录警告日志
                    return

                room_id = data.get('room_id')  # 获取聊天室 ID
                if room_id is None:
                    current_app.logger.error(
                        f"Room ID missing in message data via WebSocket - username: {username}, session_id: {request.sid}, message_content: {message}")# 记录错误日志
                    return

                timestamp = datetime.now(tz=Config.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S') # 生成时间戳
                add_message(username, message, room_id, timestamp)  # 将消息添加到数据库
                display_name = f"{user['nickname']}({username})" if user['nickname'] else username # 获取显示名称

                emit('receive_message',
                     {'username': display_name, 'message': message, 'room_id': room_id,
                      'timestamp': format_timestamp(timestamp), 'is_admin': user['is_admin']},
                     broadcast=True, room=f"room_{room_id}")  # 发送消息

                current_app.logger.info(
                    f"Message sent via WebSocket - username: {username}, room_id: {room_id}, message_length: {len(message)}") # 记录消息发送日志

        except Exception as e:
            current_app.logger.error("Error in handle_message", exc_info=True,
                                     extra={'session_id': request.sid, 'message_data': data}) # 记录错误日志