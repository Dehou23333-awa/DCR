# chat_app/db/database.py
import sqlite3
import secrets
from datetime import datetime
from typing import List, Dict, Optional

import bleach
from flask import current_app, session
from werkzeug.security import check_password_hash, generate_password_hash

from chat_app.config import Config


def get_db_connection():
    """
    获取数据库连接。
    """
    try:
        conn = sqlite3.connect(Config.DATABASE)
        conn.row_factory = sqlite3.Row  # 将查询结果转换为字典
        return conn
    except sqlite3.Error as e:
        current_app.logger.error("Failed to connect to database.", exc_info=True)
        return None # 返回None，便于调用者进行错误处理


def init_db():
    """
    初始化数据库，创建表。
    从 schema.sql 文件中读取 SQL 脚本并执行。
    """
    conn = get_db_connection()
    if conn is None: # 数据库连接失败, 无法初始化
        return
    try:
        with current_app.open_resource('schema.sql', mode='r') as f:
            conn.executescript(f.read())
        conn.commit()
        current_app.logger.info("Database initialized successfully.")
    except sqlite3.Error as e:
        current_app.logger.error("Failed to initialize database.", exc_info=True)
    finally:
        conn.close()


def format_timestamp(timestamp: str) -> str:
    """
    格式化时间戳字符串。
    将时间戳字符串从 '%Y-%m-%d %H:%M:%S' 格式转换为 '%Y-%m-%d %H:%M:%S' 格式。
    """
    try:
        if timestamp:
            return datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
        return ''
    except ValueError as e:
        current_app.logger.warning(f"Invalid timestamp format: {timestamp}", exc_info=True)
        return ''  # 返回空字符串, 并记录警告信息


def get_all_messages(room_id: int, username: str, limit: int = 10, offset: int = 0) -> List[Dict]:
    """
    获取指定聊天室的消息，支持分页。

    Args:
        room_id: 聊天室 ID.
        username: 用户名.
        limit: 每页消息数量，默认为 10.
        offset: 偏移量，用于分页.

    Returns:
        消息列表，每个消息是一个字典。如果用户不在聊天室中，返回空列表.
    """
    conn = get_db_connection()
    if conn is None:
        return []  # 数据库连接失败, 返回空列表
    try:
        if room_id and is_user_in_room(room_id, username):
            msgs = conn.execute(
                'SELECT m.id, m.username, m.message, m.timestamp, u.nickname, u.is_admin FROM messages m JOIN users u ON m.username = u.username WHERE m.room_id = ? ORDER BY m.id DESC LIMIT ? OFFSET ?',
                (room_id, limit, offset)
            ).fetchall()
            formatted_msgs = []
            for msg in reversed(msgs):
                formatted_msg = dict(msg)
                formatted_msg['message'] = bleach.clean(formatted_msg['message'])  # 使用 bleach.clean 清理消息，防止 XSS 攻击
                formatted_msg['timestamp'] = format_timestamp(formatted_msg['timestamp'])
                formatted_msgs.append(formatted_msg)
            return formatted_msgs
        else:
            return []  # 用户不在聊天室中, 返回空列表
    except sqlite3.Error as e:
        current_app.logger.error(f"Error fetching messages for room_id: {room_id}, username: {username}", exc_info=True)
        return []
    finally:
        conn.close()


def add_message(username: str, message: str, room_id: int, timestamp: str):
    """
    添加消息到数据库。

    Args:
        username: 发送消息的用户名.
        message: 消息内容.
        room_id: 聊天室 ID.
        timestamp: 消息发送时间戳.
    """
    conn = get_db_connection()
    if conn is None:
        return # 数据库连接失败, 直接返回

    try:
        max_message_length = 500  # 设置消息最大长度为 500 字符 (您可以根据需要调整)
        if len(message) > max_message_length:
            current_app.logger.warning("Message length exceeded limit",
                                     extra={'username': username, 'room_id': room_id, 'message_length': len(message),
                                            'max_length': max_message_length})  # 记录警告日志
            return  # 拒绝存储过长消息，并直接返回 (不进行后续数据库操作)

        cleaned_message = bleach.clean(message) # 清理消息内容，防止 XSS 攻击
        conn.execute('INSERT INTO messages (username, message, room_id, timestamp) VALUES (?, ?, ?, ?)',
                     (username, cleaned_message, room_id, timestamp))
        conn.commit()
        current_app.logger.info(f"Message added to room_id: {room_id} by user: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error adding message to room_id: {room_id} by user: {username}", exc_info=True)

    finally:
        conn.close()


def delete_message(message_id: int):
    """
    从数据库中删除指定 ID 的消息。

    Args:
        message_id: 消息 ID.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
        current_app.logger.info(f"Message deleted with id: {message_id}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error deleting message with id: {message_id}", exc_info=True)

    finally:
        conn.close()


def register_user(username: str, password_hash: str, is_admin: int = 0) -> bool:
    """
    注册用户。

    Args:
        username: 用户名.
        password_hash: 密码哈希值.
        is_admin: 是否为管理员，默认为 0 (False).

    Returns:
        注册成功返回 True，用户名已存在返回 False.
    """
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                     (username, password_hash, is_admin))
        conn.commit()
        current_app.logger.info(f"User registered: {username}, is_admin: {is_admin}")
        return True

    except sqlite3.IntegrityError as e:
        current_app.logger.warning(f"Username already exists: {username}", exc_info=True)
        return False

    finally:
        conn.close()


def validate_user(username: str, password: str) -> tuple[bool, Optional[str]]:
    """
    验证用户登录，返回验证结果和消息。

    Args:
        username: 用户名.
        password: 密码.

    Returns:
        A tuple containing:
            - A boolean indicating whether the validation was successful.
            - An optional string containing a message to display to the user.
    """
    conn = get_db_connection()
    if conn is None:
        return False, "数据库连接失败"

    try:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            if user['is_banned']:
                current_app.logger.warning(f"Banned user tried to login: {username}")
                return False, "账户已被封禁"

            # 创建新的 session
            session_id_new = secrets.token_urlsafe(16)
            conn = get_db_connection() # 获取一个新的数据库连接, 避免事务冲突
            if conn is None:
              return False, "数据库连接失败"
            conn.execute('UPDATE users SET session_id = ? WHERE username = ?', (session_id_new, username))
            conn.commit()
            session['session_id_db'] = session_id_new # session id 写入到flask session

            current_app.logger.info(f"User logged in: {username}")

            if not user['password_changed_on_first_login']:
                return True, "请修改您的初始密码"  # 提示用户修改初始密码

            return True, None # 登录成功，没有提示信息

        else:
            current_app.logger.warning(f"Invalid login attempt for user: {username}")
            return False, "用户名或密码错误"

    except sqlite3.Error as e:
        current_app.logger.error(f"Error validating user: {username}", exc_info=True)
        return False, "服务器错误"

    finally:
        conn.close()


def ban_user(username: str):
    """
    封禁用户。

    Args:
        username: 要封禁的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET is_banned = 1 WHERE username = ?', (username,))
        conn.commit()
        current_app.logger.info(f"User banned: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error banning user: {username}", exc_info=True)

    finally:
        conn.close()


def unban_user(username: str):
    """
    解封用户.

    Args:
        username: 要解封的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET is_banned = 0 WHERE username = ?', (username,))
        conn.commit()
        current_app.logger.info(f"User unbanned: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error unbanning user: {username}", exc_info=True)

    finally:
        conn.close()


def get_user_by_username(username: str) -> Optional[Dict]:
    """
    根据用户名获取用户信息。

    Args:
        username: 要获取信息的用户名.

    Returns:
        用户信息字典，如果用户不存在返回 None.
    """
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        user = conn.execute(
            'SELECT id, username, is_admin, is_banned, nickname, session_id, password_changed_on_first_login, password FROM users WHERE username = ?',
            (username,)).fetchone()
        return user
    except sqlite3.Error as e:
        current_app.logger.error(f"Error getting user by username: {username}", exc_info=True)
        return None
    finally:
        conn.close()


def set_user_online(username: str, online: bool):
    """
    设置用户在线状态。

    Args:
        username: 要设置在线状态的用户名.
        online: 在线状态，True 表示在线，False 表示离线.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET online = ? WHERE username = ?', (int(online), username))
        conn.commit()
        current_app.logger.info(f"User set online status - username: {username}, online: {online}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error setting user online status - username: {username}, online: {online}", exc_info=True)

    finally:
        conn.close()


def get_online_users() -> List[str]:
    """
    获取所有在线用户的用户名。

    Returns:
        在线用户名的列表.
    """
    conn = get_db_connection()
    if conn is None:
        return []
    try:
        users = conn.execute('SELECT username FROM users WHERE online = 1').fetchall()
        return [user['username'] for user in users]
    except sqlite3.Error as e:
         current_app.logger.error(f"Database error 获取所有在线用户的用户名", exc_info=True)
         return []

    finally:
        conn.close()


def get_all_users() -> List[Dict]:
    """
    获取所有用户信息 (id, username, is_admin, is_banned).

    Returns:
        用户信息列表，每个用户是一个字典。
    """
    conn = get_db_connection()
    if conn is None:
        return []
    try:
        users = conn.execute('SELECT id, username, is_admin, is_banned FROM users').fetchall()
        return users
    except sqlite3.Error as e:
         current_app.logger.error(f"Database error 获取所有用户信息", exc_info=True)
         return []

    finally:
        conn.close()


def update_user_password(username: str, password_hash: str):
    """
    更新用户密码。

    Args:
        username: 要更新密码的用户名.
        password_hash: 新密码的哈希值.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET password = ?, session_id = NULL, password_changed_on_first_login = 1 WHERE username = ?',
                     #  密码修改时，同时将 session_id 设置为 NULL, 并设置 password_changed_on_first_login = 1
                     (password_hash, username))
        conn.commit()
        current_app.logger.info(f"User password updated, session invalidated - username: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error updating user password - username: {username}", exc_info=True)

    finally:
        conn.close()


def set_user_admin(username: str, is_admin: int):
    """
    设置用户的管理员状态。

    Args:
        username: 要设置管理员状态的用户名.
        is_admin: 管理员状态，1 表示是管理员，0 表示不是管理员.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET is_admin = ? WHERE username = ?', (is_admin, username))
        conn.commit()
        current_app.logger.info(f"User admin status updated - username: {username}, is_admin: {is_admin}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error setting user admin status - username: {username}, is_admin: {is_admin}", exc_info=True)

    finally:
        conn.close()


def create_room(room_name: str) -> Optional[int]:
    """
    创建聊天室.

    Args:
        room_name: 聊天室名称.

    Returns:
        成功创建则返回聊天室ID, 否则返回 None.
    """
    conn = get_db_connection()
    if conn is None:
        return None

    try:
        conn.execute('INSERT INTO rooms (name) VALUES (?)', (room_name,))
        conn.commit()
        room_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        current_app.logger.info(f"Room created - room_name: {room_name}, room_id: {room_id}")
        return room_id

    except sqlite3.IntegrityError as e:
        current_app.logger.warning(f"Room name already exists: {room_name}", exc_info=True)
        return None
    except sqlite3.Error as e:
        current_app.logger.error(f"Database error creating room - room_name: {room_name}", exc_info=True)
        return None

    finally:
        conn.close()


def delete_room(room_id: int):
    """
    删除聊天室。

    Args:
        room_id: 要删除的聊天室 ID.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
        current_app.logger.info(f"Room deleted - room_id: {room_id}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error deleting room - room_id: {room_id}", exc_info=True)

    finally:
        conn.close()


def get_all_rooms() -> List[Dict]:
    """
    获取所有聊天室信息.

    Returns:
        聊天室信息列表，每个聊天室是一个字典。
    """
    conn = get_db_connection()
    if conn is None:
        return []

    try:
        rooms = conn.execute('SELECT id, name FROM rooms').fetchall()
        return rooms
    except sqlite3.Error as e:
        current_app.logger.error(f"Database error 获取所有聊天室", exc_info=True)
        return []

    finally:
        conn.close()


def add_user_to_room(room_id: int, username: str) -> bool:
    """
    添加用户到聊天室.

    Args:
        room_id: 要添加用户的聊天室 ID.
        username: 要添加到聊天室的用户名.

    Returns:
        添加成功返回 True, 用户已存在返回 False.
    """
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        conn.execute('INSERT INTO room_members (room_id, username) VALUES (?, ?)', (room_id, username))
        conn.commit()
        current_app.logger.info(f"User added to room - username: {username}, room_id: {room_id}")
        return True

    except sqlite3.IntegrityError as e:
        current_app.logger.warning(f"User already in room - username: {username}, room_id: {room_id}", exc_info=True)
        return False

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error adding user to room - username: {username}, room_id: {room_id}", exc_info=True)
        return False

    finally:
        conn.close()


def remove_user_from_room(room_id: int, username: str):
    """
    从聊天室中移除用户。

    Args:
        room_id: 要移除用户的聊天室 ID.
        username: 要移除的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('DELETE FROM room_members WHERE room_id = ? AND username = ?', (room_id, username))
        conn.commit()
        current_app.logger.info(f"User removed from room - username: {username}, room_id: {room_id}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error removing user from room - username: {username}, room_id: {room_id}", exc_info=True)

    finally:
        conn.close()


def get_users_in_room(room_id: int) -> List[str]:
    """
    获取聊天室中的所有用户名.

    Args:
        room_id: 聊天室 ID.

    Returns:
        聊天室中所有用户名的列表.
    """
    conn = get_db_connection()
    if conn is None:
        return []

    try:
        users = conn.execute('SELECT username FROM room_members WHERE room_id = ?', (room_id,)).fetchall()
        return [user['username'] for user in users]
    except sqlite3.Error as e:
         current_app.logger.error(f"Database error 获取聊天室所有用户", exc_info=True)
         return []

    finally:
        conn.close()


def is_user_in_room(room_id: int, username: str) -> bool:
    """
    判断用户是否在聊天室中.

    Args:
        room_id: 聊天室 ID.
        username: 用户名.

    Returns:
        如果用户在聊天室中返回 True, 否则返回 False.
    """
    conn = get_db_connection()
    if conn is None:
        return False

    try:
        member = conn.execute('SELECT * FROM room_members WHERE room_id = ? AND username = ?',
                              (room_id, username)).fetchone()
        return member is not None
    except sqlite3.Error as e:
         current_app.logger.error(f"Database error 判断用户是否在聊天室", exc_info=True)
         return False

    finally:
        conn.close()


def get_user_rooms(username: str) -> List[Dict]:
    """
    获取用户所在的所有聊天室.

    Args:
        username: 用户名.

    Returns:
        用户所在的所有聊天室的列表，每个聊天室是一个字典，包含 id 和 name。
    """
    conn = get_db_connection()
    if conn is None:
        return []

    try:
        rooms = conn.execute(
            'SELECT r.id, r.name FROM rooms r INNER JOIN room_members rm ON r.id = rm.room_id WHERE rm.username = ?',
            (username,)).fetchall()
        return rooms
    except sqlite3.Error as e:
        current_app.logger.error(f"Database error 获取用户所在的所有聊天室", exc_info=True)
        return []

    finally:
        conn.close()


def delete_user(username: str):
    """
    删除用户。

    Args:
        username: 要删除的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('DELETE FROM users WHERE username = ?', (username,))
        conn.commit()
        current_app.logger.info(f"User deleted - username: {username}")
        remove_user_from_all_rooms(username)  # 同时移除该用户所在的所有聊天室

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error deleting user - username: {username}", exc_info=True)

    finally:
        conn.close()


def remove_user_from_all_rooms(username: str):
    """
    将用户从所有聊天室中移除.

    Args:
        username: 要移除的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('DELETE FROM room_members WHERE username = ?', (username,))
        conn.commit()
        current_app.logger.info(f"User removed from all rooms - username: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error removing user from all rooms - username: {username}", exc_info=True)

    finally:
        conn.close()


def get_available_users_for_room(room_id: int) -> List[str]:
    """
    获取可以添加到指定聊天室的用户列表 (不在该聊天室中的用户).

    Args:
        room_id: 聊天室 ID.

    Returns:
        可以添加到指定聊天室的用户名列表.
    """
    conn = get_db_connection()
    if conn is None:
        return []

    try:
        users_in_room = get_users_in_room(room_id) #获取已在房间的用户
        all_users = conn.execute('SELECT username FROM users').fetchall()
        available_users = [user['username'] for user in all_users if user['username'] not in users_in_room]
        return available_users

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error getting available users for room - room_id: {room_id}", exc_info=True)
        return []
    finally:
        conn.close()


def force_logout_user(username: str):
    """
    强制用户登出 (将 session_id 设置为 NULL).

    Args:
        username: 要强制登出的用户名.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET session_id = NULL WHERE username = ?', (username,))  # 将 session_id 设置为 NULL
        conn.commit()
        current_app.logger.info(f"User forced logout - username: {username}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error forcing user logout - username: {username}", exc_info=True)

    finally:
        conn.close()


def create_default_admin_user_if_not_exists():
    """
    如果不存在管理员用户, 则创建一个默认管理员账户.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        admin_user = conn.execute('SELECT * FROM users WHERE is_admin = 1').fetchone()
        if not admin_user: # 不存在管理员用户，则创建
            default_admin_username = "admin"  # 默认管理员用户名
            default_admin_password = "CHANGEME"  # 默认管理员密码 (!!! 生产环境务必修改 !!!)
            password_hash = generate_password_hash(default_admin_password) # 哈希加密

            if register_user(default_admin_username, password_hash, is_admin=1):
                current_app.logger.info(f"Default admin user created - username: {default_admin_username}")
                print(
                    f"Default admin user '{default_admin_username}' created with password '{default_admin_password}'. 请立即修改密码！")
                return # 创建成功, 返回
            else:
                current_app.logger.warning(f"Failed to create default admin user (username might exist)") # 记录创建失败信息
                return

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error checking/creating default admin user", exc_info=True)

    finally:
        conn.close()


def impersonate_user(admin_username: str, target_username: str) -> Optional[Dict]:
    """
    管理员模拟登录到指定用户账户。

    Args:
        admin_username: 执行模拟操作的管理员用户名.
        target_username: 要模拟登录的目标用户名.

    Returns:
        模拟登录成功，返回目标用户信息字典，否则返回 None.

    """
    conn = get_db_connection()
    if conn is None:
        return None

    try:
        admin_user = get_user_by_username(admin_username)
        target_user = get_user_by_username(target_username)

        if not admin_user or not admin_user['is_admin']: # 非管理员, 拒绝操作
            current_app.logger.warning(
                f"Non-admin user attempted impersonation - admin_username: {admin_username}, target_username: {target_username}")
            return None

        if not target_user: # 目标用户不存在
            current_app.logger.warning(
                f"Admin tried to impersonate non-existent user - admin_username: {admin_username}, target_username: {target_username}")
            return None

        # 存储原始管理员 session 信息 (用于稍后恢复)
        session['original_admin_session'] = {
            'username': admin_username,
            'session_id_db': session.get('session_id_db')
        }

        # 创建新的 session，模拟目标用户登录
        session_id_new = secrets.token_urlsafe(16)
        conn.execute('UPDATE users SET session_id = ? WHERE username = ?', (session_id_new, target_username))
        conn.commit()
        session['username'] = target_username # 设置 session username
        session['session_id_db'] = session_id_new # 更新session id

        current_app.logger.info(f"Admin impersonated user - admin_username: {admin_username}, target_username: {target_username}")
        return target_user # 成功返回目标用户信息

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error during user impersonation - admin_username: {admin_username}, target_username: {target_username}", exc_info=True)
        return None

    finally:
        conn.close()


def update_user_nickname(username: str, nickname: str):
    """
    更新用户昵称。

    Args:
        username: 要更新昵称的用户名.
        nickname: 新的昵称.
    """
    conn = get_db_connection()
    if conn is None:
        return

    try:
        conn.execute('UPDATE users SET nickname = ? WHERE username = ?', (nickname, username))
        conn.commit()
        current_app.logger.info(f"User nickname updated - username: {username}, nickname: {nickname}")

    except sqlite3.Error as e:
        current_app.logger.error(f"Database error updating user nickname - username: {username}, nickname: {nickname}", exc_info=True)

    finally:
        conn.close()