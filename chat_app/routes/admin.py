from flask import Blueprint, render_template, request, redirect, url_for, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from chat_app.db.database import get_all_users, get_all_rooms, get_users_in_room, create_room, delete_room, \
    add_user_to_room, remove_user_from_room, set_user_admin, ban_user, unban_user, delete_user, get_user_by_username, \
    get_available_users_for_room, force_logout_user, impersonate_user
from chat_app.utils.auth import admin_required, login_required

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin_login', methods=['GET', 'POST'])
@login_required
def admin_login():
    """
    管理员登录验证页面。
    需要先登录才能访问。
    """
    error = None
    if request.method == 'POST':
        password = request.form['password']  # 获取密码
        admin_user = get_user_by_username(session['username'])  # 获取管理员用户信息

        if admin_user and check_password_hash(admin_user['password'], password) and admin_user['is_admin']:  # 如果是管理员，且密码正确
            session['admin_confirmed'] = True  # 设置管理员确认状态
            return redirect(url_for('admin.admin')) # 重定向到管理员面板
        else:
            error = "管理员密码错误" # 密码错误
    return render_template('admin_login.html', error=error)


@admin_bp.route('/admin', methods=['GET'])
@admin_required
def admin():
    """
    显示管理员面板。
    只有管理员才能访问.
    """
    rooms = get_all_rooms() # 获取所有聊天室
    room_members = {} # 存储聊天室成员信息
    for room in rooms:
        room_members[room['id']] = get_users_in_room(room['id']) # 获取每个聊天室的成员
    return render_template('admin.html', users=get_all_users(), rooms=rooms, room_members=room_members)


@admin_bp.route('/admin/create_room', methods=['POST'])
@admin_required
def admin_create_room():
    """
    创建聊天室。
    只有管理员才能访问。
    """
    room_name = request.form['room_name'] # 获取聊天室名称
    room_id = create_room(room_name) # 创建聊天室
    if room_id:
        add_user_to_room(room_id, session['username']) # 将当前用户添加到聊天室
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/delete_room', methods=['POST'])
@admin_required
def admin_delete_room():
    """
    删除聊天室。
    只有管理员才能访问。
    """
    room_id = request.form['room_id'] # 获取聊天室 ID
    delete_room(room_id)  # 删除聊天室
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/add_user_to_room', methods=['POST'])
@admin_required
def admin_add_user_to_room():
    """
    添加用户到聊天室。
    只有管理员才能访问。
    """
    room_id = request.form['room_id']  # 获取聊天室 ID
    username = request.form['username']  # 获取要添加的用户名
    add_user_to_room(room_id, username)  # 添加用户到聊天室
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/remove_user_from_room', methods=['POST'])
@admin_required
def admin_remove_user_from_room():
    """
    从聊天室中移除用户。
    只有管理员才能访问。
    """
    room_id = request.form['room_id']  # 获取聊天室 ID
    username = request.form['username'] # 获取要移除的用户名
    remove_user_from_room(room_id, username) # 移除用户
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/set_admin', methods=['POST'])
@admin_required
def admin_set_admin():
    """
    设置用户为管理员。
    只有管理员才能访问。
    """
    username = request.form['username'] # 获取用户名
    is_admin = int(request.form['is_admin']) # 获取是否设置为管理员
    set_user_admin(username, is_admin) # 设置用户管理员状态
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/ban_user', methods=['POST'])
@admin_required
def admin_ban_user():
    """
    封禁用户。
    只有管理员才能访问。
    """
    username = request.form['username'] # 获取要封禁的用户名
    ban_user(username)  # 封禁用户
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/unban_user', methods=['POST'])
@admin_required
def admin_unban_user():
    """
    解封用户。
    只有管理员才能访问。
    """
    username = request.form['username'] # 获取要解封的用户名
    unban_user(username)  # 解封用户
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    """
    删除用户。
    只有管理员才能访问。
    """
    username = request.form['username']  # 获取要删除的用户名
    if username == 'admin':
        return render_template('message.html', title="操作错误", message="不能删除管理员用户！") # 不能删除管理员用户

    delete_user(username) # 删除用户
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/force_logout_user', methods=['POST'])
@admin_required
def admin_force_logout_user():
    """
    强制用户登出。
    只有管理员才能访问.
    """
    username = request.form['username'] # 获取用户名
    if username == 'admin':  # 防止管理员自己登出自己
        return render_template('message.html', title="操作错误", message="不能强制登出管理员用户！") # 提示不能登出管理员

    force_logout_user(username)  # 调用数据库函数强制用户登出
    return redirect(url_for('admin.admin')) # 重定向到管理员面板


@admin_bp.route('/admin/impersonate_user', methods=['POST'])
@admin_required
def admin_impersonate_user():
    """
    模拟登录到指定用户。
    只有管理员才能访问。
    """
    target_username = request.form['username'] # 要模拟登录的用户名
    if target_username == 'admin':  # 防止管理员模拟登录到管理员自己
        return render_template('message.html', title="操作错误", message="不能模拟登录到管理员用户！") # 提示不能模拟登录管理员

    user = impersonate_user(session['username'], target_username)  # 调用 impersonate_user 函数
    if user:
        session['is_impersonating'] = True  # 设置 session 标记，表示当前处于模拟登录状态
        current_app.logger.info(f"管理员模拟登录成功 - 管理员：{session['username']}, 目标：{target_username}") # 记录模拟登录成功日志

        return redirect(url_for('chat.chat')) # 模拟登录成功后，重定向到聊天室
    else:
        current_app.logger.warning(f"管理员模拟登录失败 - 管理员：{session['username']}, 目标：{target_username}")  # 记录模拟登录失败日志
        return render_template('message.html', title="操作错误", message="模拟登录用户失败！") # 模拟登录失败