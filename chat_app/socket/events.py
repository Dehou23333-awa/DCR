# chat_app/socket/events.py
from flask import session, request, current_app  # 导入 current_app
from flask_socketio import emit, join_room, disconnect
from chat_app.db.database import set_user_online, get_user_by_username, add_message, format_timestamp
from chat_app.config import Config
from datetime import datetime

def init_socketio_events(socketio):
    @socketio.on('connect')
    def handle_connect():
        try:
            if 'username' in session:
                username = session['username']
                user = get_user_by_username(username)
                if user and user['is_banned']:
                    emit('banned', {'message': '你的账户已被封禁'}, room=request.sid)
                    disconnect(request.sid)
                    current_app.logger.warning("Banned user tried to connect via WebSocket", extra={'username': username, 'session_id': request.sid})  # 结构化日志
                    print(f'User {username} is banned and disconnected')
                    return
                set_user_online(username, True)
                room_id = request.args.get('room_id', None, type=int)
                if room_id:
                    join_room(f"room_{room_id}")
                    emit('user_online', {'username': username, 'room_id': room_id}, broadcast=True, room=f"room_{room_id}")
                current_app.logger.info("User connected via WebSocket", extra={'username': username, 'session_id': request.sid, 'room_id': room_id})  # 结构化日志
        except Exception as e:
            current_app.logger.error("Error in handle_connect", exc_info=True, extra={'session_id': request.sid})  # 结构化日志
            print(f"Error in handle_connect: {e}")

    @socketio.on('disconnect')
    def handle_disconnect():
        try:
            if 'username' in session:
                username = session['username']
                user = get_user_by_username(username)
                if user and not user['is_banned']:
                    set_user_online(username, False)
                    room_id = request.args.get('room_id', None, type=int)
                    if room_id:
                        emit('user_offline', {'username': username, 'room_id': room_id}, broadcast=True, room=f"room_{room_id}")
                    current_app.logger.info("User disconnected via WebSocket", extra={'username': username, 'session_id': request.sid, 'room_id': room_id})  # 结构化日志
        except Exception as e:
            current_app.logger.error("Error in handle_disconnect", exc_info=True, extra={'session_id': request.sid})  # 结构化日志
            print(f"Error in handle_disconnect: {e}")

    @socketio.on('send_message')
    def handle_message(data):
        try:
            if 'username' in session:
                username = session['username']
                user = get_user_by_username(username)
                if user and user['is_banned']:
                    emit('banned', {'message': '你的账户已被封禁'}, room=request.sid)
                    disconnect(request.sid)
                    current_app.logger.warning("Banned user tried to send message via WebSocket", extra={'username': username, 'session_id': request.sid, 'room_id': data.get('room_id')})
                    print(f'User {username} is banned and disconnected by send message')
                    return
                message = data['message']
                if not message or not message.strip():
                    current_app.logger.warning("Empty message received via WebSocket", extra={'username': username, 'session_id': request.sid, 'room_id': data.get('room_id')})
                    return
                room_id = data.get('room_id')
                if room_id is None:
                    current_app.logger.error("Room ID missing in message data via WebSocket", extra={'username': username, 'session_id': request.sid, 'message_content': message})
                    print("Error: room_id is missing in message data!")
                    return

                timestamp = datetime.now(tz=Config.TIMEZONE).strftime('%Y-%m-%d %H:%M:%S')
                add_message(username, message, room_id, timestamp)
                display_name = f"{user['nickname']}({username})" if user['nickname'] else username
                emit('receive_message',
                    {'username': display_name, 'message': message, 'room_id': room_id, 'timestamp': format_timestamp(timestamp),'is_admin': user['is_admin']},
                    broadcast=True, room=f"room_{room_id}")
                current_app.logger.info("Message sent via WebSocket", extra={'username': username, 'room_id': room_id, 'message_length': len(message)})

        except Exception as e:
            current_app.logger.error("Error in handle_message", exc_info=True, extra={'session_id': request.sid, 'message_data': data})
            print(f"Error in handle_message: {e}")