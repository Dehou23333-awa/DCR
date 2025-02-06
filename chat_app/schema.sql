-- 创建消息表，用于存储聊天消息
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,     -- 消息 ID，自增长
    username TEXT NOT NULL,                  -- 发送消息的用户名
    message TEXT NOT NULL,                   -- 消息内容
    room_id INTEGER NOT NULL,                  -- 聊天室 ID
    timestamp TEXT NOT NULL                   -- 消息发送时间戳
);

-- 创建用户表，用于存储用户信息
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,     -- 用户 ID，自增长
    username TEXT UNIQUE NOT NULL,           -- 用户名，唯一
    password TEXT NOT NULL,                  -- 密码（哈希值）
    online INTEGER NOT NULL DEFAULT 0,      -- 用户在线状态，0 表示离线，1 表示在线
    is_admin INTEGER NOT NULL DEFAULT 0,       -- 是否为管理员，0 表示否，1 表示是
    is_banned INTEGER NOT NULL DEFAULT 0,      -- 是否被封禁，0 表示否，1 表示是
    session_id TEXT,                         -- Session ID，用于验证用户登录状态
    password_changed_on_first_login INTEGER NOT NULL DEFAULT 0,  -- 标识用户是否已修改初始密码
    nickname TEXT                             -- 用户昵称
);

-- 创建聊天室表，用于存储聊天室信息
CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,     -- 聊天室 ID，自增长
    name TEXT UNIQUE NOT NULL                -- 聊天室名称，唯一
);

-- 创建聊天室成员表，用于存储聊天室成员关系
CREATE TABLE IF NOT EXISTS room_members (
    room_id INTEGER NOT NULL,                  -- 聊天室 ID
    username TEXT NOT NULL,                  -- 用户名
    PRIMARY KEY(room_id, username),            -- 联合主键，确保同一用户不能在同一聊天室中多次加入
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,  -- 外键，关联聊天室表
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE   -- 外键，关联用户表
);