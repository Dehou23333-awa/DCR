CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    message TEXT NOT NULL,
    room_id INTEGER NOT NULL,
    timestamp TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    online INTEGER NOT NULL DEFAULT 0,
    is_admin INTEGER NOT NULL DEFAULT 0,
    is_banned INTEGER NOT NULL DEFAULT 0,
    session_id TEXT,
    password_changed_on_first_login INTEGER NOT NULL DEFAULT 0,
    nickname TEXT  -- 添加昵称列
);

CREATE TABLE IF NOT EXISTS rooms (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT UNIQUE NOT NULL
 );

 CREATE TABLE IF NOT EXISTS room_members (
 room_id INTEGER NOT NULL,
 username TEXT NOT NULL,
 PRIMARY KEY(room_id, username),
     FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
     FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
 );