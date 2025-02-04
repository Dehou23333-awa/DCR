# chat_app/db/database.py
import sqlite3, secrets
from typing import List, Dict, Optional
from flask import current_app, session
from datetime import datetime
from chat_app.config import Config
from werkzeug.security import check_password_hash, generate_password_hash
import bleach

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    with current_app.open_resource('schema.sql', mode='r') as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()


def format_timestamp(timestamp: str) -> str:
    if timestamp:
        return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
    return ''


def get_all_messages(room_id: int, username: str, limit: int = 10, offset: int = 0) -> List[Dict]:
    conn = get_db_connection()
    if room_id and is_user_in_room(room_id, username):
        msgs = conn.execute(
            'SELECT m.id, m.username, m.message, m.timestamp, u.nickname, u.is_admin FROM messages m JOIN users u ON m.username = u.username WHERE m.room_id = ? ORDER BY m.id DESC LIMIT ? OFFSET ?',
            (room_id, limit, offset)
        ).fetchall()
        conn.close()
        formatted_msgs = []
        for msg in reversed(msgs):
                formatted_msg = dict(msg)
                formatted_msg['message'] = bleach.clean(formatted_msg['message']) # 使用 bleach.clean 清理消息
                formatted_msg['timestamp'] = format_timestamp(formatted_msg['timestamp'])
                formatted_msgs.append(formatted_msg)
        return formatted_msgs
    else:
        conn.close()
        return []


def add_message(username: str, message: str, room_id: int, timestamp: str):
    conn = get_db_connection()
    try:
        max_message_length = 500  #  设置消息最大长度为 500 字符 (您可以根据需要调整)
        if len(message) > max_message_length:
            current_app.logger.warning("Message length exceeded limit", extra={'username': username, 'room_id': room_id, 'message_length': len(message), 'max_length': max_message_length}) # 记录警告日志
            return  #  拒绝存储过长消息，并直接返回 (不进行后续数据库操作)

        cleaned_message = bleach.clean(message)
        conn.execute('INSERT INTO messages (username, message, room_id, timestamp) VALUES (?, ?, ?, ?)',
                     (username, cleaned_message, room_id, timestamp))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        current_app.logger.error("Database error adding message", exc_info=True,
                                 extra={'username': username, 'room_id': room_id})
        conn.close()


def delete_message(message_id: int):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        current_app.logger.error("Database error deleting message", exc_info=True, extra={'message_id': message_id}) # 使用结构化日志
        conn.close()


def register_user(username: str, password_hash: str, is_admin: int = 0) -> bool:
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                    (username, password_hash, is_admin))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError as e:
        current_app.logger.warning("Username already exists during registration", extra={'username': username}) # 使用结构化日志
        conn.close()
        return False

def validate_user(username: str, password: str) -> tuple[bool, Optional[str]]:
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], password):
        if user and user['is_banned']:
            current_app.logger.warning("Banned user tried to login", extra={'username': username}) # 使用结构化日志
            return False, "账户已被封禁"
        session_id_new = secrets.token_urlsafe(16)
        conn = get_db_connection()
        conn.execute('UPDATE users SET session_id = ? WHERE username = ?', (session_id_new, username))
        conn.commit()
        conn.close()
        session['session_id_db'] = session_id_new
        current_app.logger.info("User logged in", extra={'username': username}) # 使用结构化日志

        if not user['password_changed_on_first_login']: #  检查 password_changed_on_first_login 字段
            return True, "请修改您的初始密码" # 返回成功登录状态，并提示修改密码
        return True, None #  正常登录成功，没有提示信息
    else:
        current_app.logger.warning("Invalid login attempt", extra={'username': username}) # 使用结构化日志
        return False, "用户名或密码错误"


def ban_user(username: str):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_banned = 1 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        current_app.logger.info("User banned", extra={'username': username}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error banning user", exc_info=True, extra={'username': username}) # 使用结构化日志
        conn.close()


def unban_user(username: str):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_banned = 0 WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        current_app.logger.info("User unbanned", extra={'username': username}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error unbanning user", exc_info=True, extra={'username': username}) # 使用结构化日志
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    conn = get_db_connection()
    user = conn.execute('SELECT id, username, is_admin, is_banned, nickname, session_id, password_changed_on_first_login, password FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user


def set_user_online(username: str, online: bool):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET online = ? WHERE username = ?', (int(online), username))
        conn.commit()
        conn.close()
        if online:
            current_app.logger.info("User set online", extra={'username': username}) # 使用结构化日志
        else:
            current_app.logger.info("User set offline", extra={'username': username}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error setting user online status", exc_info=True, extra={'username': username, 'online_status': online}) # 使用结构化日志
        conn.close()



def get_online_users() -> List[str]:
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM users WHERE online = 1').fetchall()
    conn.close()
    return [user['username'] for user in users]


def get_all_users() -> List[Dict]:
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, is_admin, is_banned FROM users').fetchall()
    conn.close()
    return users


def update_user_password(username: str, password_hash: str):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET password = ?, session_id = NULL WHERE username = ?', #  密码修改时，同时将 session_id 设置为 NULL
                     (password_hash, username))
        conn.commit()
        conn.close()
        current_app.logger.info("User password updated, session invalidated", extra={'username': username}) # 日志中记录 session_id 已失效
    except sqlite3.Error as e:
        current_app.logger.error("Database error updating user password", exc_info=True, extra={'username': username})
        conn.close()


def set_user_admin(username: str, is_admin: int):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET is_admin = ? WHERE username = ?', (is_admin, username))
        conn.commit()
        conn.close()
        current_app.logger.info("User admin status updated", extra={'username': username, 'is_admin': is_admin}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error setting user admin status", exc_info=True,  extra={'username': username, 'is_admin': is_admin}) # 使用结构化日志
        conn.close()


def create_room(room_name: str) -> Optional[int]:
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO rooms (name) VALUES (?)', (room_name,))
        conn.commit()
        room_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        conn.close()
        current_app.logger.info("Room created", extra={'room_name': room_name, 'room_id': room_id}) # 使用结构化日志
        return room_id
    except sqlite3.IntegrityError as e:
        current_app.logger.warning("Room name already exists", extra={'room_name': room_name}) # 使用结构化日志
        conn.close()
        return None
    except sqlite3.Error as e:
        current_app.logger.error("Database error creating room", exc_info=True, extra={'room_name': room_name}) # 使用结构化日志
        conn.close()
        return None


def delete_room(room_id: int):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        conn.close()
        current_app.logger.info("Room deleted", extra={'room_id': room_id}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error deleting room", exc_info=True, extra={'room_id': room_id}) # 使用结构化日志
        conn.close()


def get_all_rooms() -> List[Dict]:
    conn = get_db_connection()
    rooms = conn.execute('SELECT id, name FROM rooms').fetchall()
    conn.close()
    return rooms


def add_user_to_room(room_id: int, username: str) -> bool:
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO room_members (room_id, username) VALUES (?, ?)', (room_id, username))
        conn.commit()
        conn.close()
        current_app.logger.info("User added to room", extra={'username': username, 'room_id': room_id}) # 使用结构化日志
        return True
    except sqlite3.IntegrityError as e:
        current_app.logger.warning("User already in room", extra={'username': username, 'room_id': room_id}) # 使用结构化日志
        conn.close()
        return False
    except sqlite3.Error as e:
        current_app.logger.error("Database error adding user to room", exc_info=True, extra={'username': username, 'room_id': room_id}) # 使用结构化日志
        conn.close()
        return False


def remove_user_from_room(room_id: int, username: str):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM room_members WHERE room_id = ? AND username = ?', (room_id, username))
        conn.commit()
        conn.close()
        current_app.logger.info("User removed from room", extra={'username': username, 'room_id': room_id}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error removing user from room", exc_info=True, extra={'username': username, 'room_id': room_id}) # 使用结构化日志
        conn.close()


def get_users_in_room(room_id: int) -> List[str]:
    conn = get_db_connection()
    users = conn.execute('SELECT username FROM room_members WHERE room_id = ?', (room_id,)).fetchall()
    conn.close()
    return [user['username'] for user in users]


def is_user_in_room(room_id: int, username: str) -> bool:
    conn = get_db_connection()
    member = conn.execute('SELECT * FROM room_members WHERE room_id = ? AND username = ?', (room_id, username)).fetchone()
    conn.close()
    return member is not None


def get_user_rooms(username: str) -> List[Dict]:
    conn = get_db_connection()
    rooms = conn.execute(
        'SELECT r.id, r.name FROM rooms r INNER JOIN room_members rm ON r.id = rm.room_id WHERE rm.username = ?',
        (username,)).fetchall()
    conn.close()
    return rooms


def delete_user(username: str):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        current_app.logger.info("User deleted", extra={'username': username}) # 使用结构化日志
        remove_user_from_all_rooms(username)
    except sqlite3.Error as e:
        current_app.logger.error("Database error deleting user", exc_info=True, extra={'username': username}) # 使用结构化日志
        conn.close()


def remove_user_from_all_rooms(username: str):
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM room_members WHERE username = ?', (username,))
        conn.commit()
        conn.close()
        current_app.logger.info("User removed from all rooms", extra={'username': username}) # 使用结构化日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error removing user from all rooms", exc_info=True, extra={'username': username}) # 使用结构化日志
        conn.close()


def get_available_users_for_room(room_id: int) -> List[str]:
    conn = get_db_connection()
    users_in_room = get_users_in_room(room_id)
    all_users = conn.execute('SELECT username FROM users').fetchall()
    conn.close()
    available_users = [user['username'] for user in all_users if user['username'] not in users_in_room]
    return available_users

def force_logout_user(username: str):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET session_id = NULL WHERE username = ?', (username,)) # 将 session_id 设置为 NULL
        conn.commit()
        conn.close()
        current_app.logger.info("User forced logout", extra={'username': username}) # 记录日志
    except sqlite3.Error as e:
        current_app.logger.error("Database error forcing user logout", exc_info=True, extra={'username': username}) # 记录错误日志
        conn.close()

def create_default_admin_user_if_not_exists():
    conn = get_db_connection()
    try:
        # 检查是否已存在管理员用户
        admin_user = conn.execute('SELECT * FROM users WHERE is_admin = 1').fetchone()
        if not admin_user:
            default_admin_username = "admin"  # 默认管理员用户名
            default_admin_password = "CHANGEME" # 默认管理员密码 (!!! 生产环境务必修改 !!!)
            password_hash = generate_password_hash(default_admin_password)

            if register_user(default_admin_username, password_hash, is_admin=1):
                current_app.logger.info("Default admin user created", extra={'username': default_admin_username}) # 记录日志
                print(f"Default admin user '{default_admin_username}' created with password '{default_admin_password}'. 请立即修改密码！") # 打印提示信息 (仅在首次运行时显示)
            else:
                current_app.logger.warning("Failed to create default admin user (username might exist)") # 记录警告日志
        conn.close()
    except sqlite3.Error as e:
        current_app.logger.error("Database error checking/creating default admin user", exc_info=True) # 记录错误日志
        conn.close()

def impersonate_user(admin_username: str, target_username: str) -> Optional[Dict]:
    """管理员模拟登录到指定用户账户"""
    conn = get_db_connection()
    try:
        admin_user = get_user_by_username(admin_username)
        target_user = get_user_by_username(target_username)

        if not admin_user or not admin_user['is_admin']:
            current_app.logger.warning("Non-admin user attempted impersonation", extra={'username': admin_username, 'target_username': target_username}) # 记录警告日志
            return None  # 只有管理员才能模拟登录

        if not target_user:
            current_app.logger.warning("Admin tried to impersonate non-existent user", extra={'admin_username': admin_username, 'target_username': target_username}) # 记录警告日志
            return None # 目标用户不存在

        # 存储原始管理员 session 信息 (用于稍后恢复)
        session['original_admin_session'] = {
            'username': admin_username,
            'session_id_db': session.get('session_id_db')
        }

        # 创建新的 session，模拟目标用户登录
        session_id_new = secrets.token_urlsafe(16)
        conn.execute('UPDATE users SET session_id = ? WHERE username = ?', (session_id_new, target_username))
        conn.commit()
        conn.close()
        session['username'] = target_username
        session['session_id_db'] = session_id_new
        current_app.logger.info("Admin impersonated user", extra={'admin_username': admin_username, 'target_username': target_username}) # 记录日志
        current_app.logger.info("Session switched to user", extra={'username': target_username, 'session_id': session_id_new}) # 记录日志
        return target_user
    except sqlite3.Error as e:
        current_app.logger.error("Database error during user impersonation", exc_info=True, extra={'admin_username': admin_username, 'target_username': target_username}) # 记录错误日志
        conn.close()
        return None

def update_user_nickname(username: str, nickname: str):
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET nickname = ? WHERE username = ?', (nickname, username))
        conn.commit()
        conn.close()
        current_app.logger.info("User nickname updated", extra={'username': username, 'nickname': nickname})
    except sqlite3.Error as e:
        current_app.logger.error("Database error updating user nickname", exc_info=True, extra={'username': username, 'nickname': nickname})
        conn.close()
