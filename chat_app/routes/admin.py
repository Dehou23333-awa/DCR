from flask import Blueprint, render_template, request, redirect, url_for, session, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from chat_app.db.database import get_all_users, get_all_rooms, get_users_in_room, create_room, delete_room, add_user_to_room, remove_user_from_room, set_user_admin, ban_user, unban_user, delete_user, get_user_by_username, get_available_users_for_room, force_logout_user, impersonate_user
from chat_app.utils.auth import admin_required, login_required
admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/admin_login', methods=['GET', 'POST'])
@login_required
def admin_login():
    error = None
    if request.method == 'POST':
        password = request.form['password']
        admin_user = get_user_by_username(session['username'])
        if admin_user and check_password_hash(admin_user['password'], password) and admin_user['is_admin']:# 如果是管理员，且密码正确
            session['admin_confirmed'] = True
            return redirect(url_for('admin.admin'))
        else:
            error = "管理员密码错误"
    return render_template('admin_login.html', error=error)


@admin_bp.route('/admin', methods=['GET'])
@admin_required
def admin():
    rooms = get_all_rooms()
    room_members = {}
    for room in rooms:
        room_members[room['id']] = get_users_in_room(room['id'])
    return render_template('admin.html', users=get_all_users(), rooms=rooms, room_members=room_members)


@admin_bp.route('/admin/create_room', methods=['POST'])
@admin_required
def admin_create_room():
    room_name = request.form['room_name']
    room_id = create_room(room_name)
    if room_id:
        add_user_to_room(room_id, session['username'])
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/delete_room', methods=['POST'])
@admin_required
def admin_delete_room():
    room_id = request.form['room_id']
    delete_room(room_id)
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/add_user_to_room', methods=['POST'])
@admin_required
def admin_add_user_to_room():
    room_id = request.form['room_id']
    available_users = get_available_users_for_room(room_id)
    if not available_users:
        return redirect(url_for('admin.admin'))
    username = request.form['username']
    add_user_to_room(room_id, username)
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/remove_user_from_room', methods=['POST'])
@admin_required
def admin_remove_user_from_room():
    room_id = request.form['room_id']
    room_users = get_users_in_room(room_id)
    if not room_users:
        return redirect(url_for('admin.admin'))
    username = request.form['username']
    remove_user_from_room(room_id, username)
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/set_admin', methods=['POST'])
@admin_required
def admin_set_admin():
    username = request.form['username']
    is_admin = int(request.form['is_admin'])
    set_user_admin(username, is_admin)
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/ban_user', methods=['POST'])
@admin_required
def admin_ban_user():
    username = request.form['username']
    ban_user(username)
    return redirect(url_for('admin.admin'))

@admin_bp.route('/admin/unban_user', methods=['POST'])
@admin_required
def admin_unban_user():
    username = request.form['username']
    unban_user(username)
    return redirect(url_for('admin.admin'))


@admin_bp.route('/admin/delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    username = request.form['username']
    if username == 'admin':
        return render_template('message.html', title="操作错误", message="不能删除管理员用户！")
    delete_user(username)
    return redirect(url_for('admin.admin'))

@admin_bp.route('/admin/force_logout_user', methods=['POST'])
@admin_required
def admin_force_logout_user():
    username = request.form['username']
    if username == 'admin': #  防止管理员自己登出自己
        return render_template('message.html', title="操作错误", message="不能强制登出管理员用户！")
    force_logout_user(username) # 调用数据库函数强制用户登出
    return redirect(url_for('admin.admin'))

@admin_bp.route('/admin/impersonate_user', methods=['POST'])
@admin_required
def admin_impersonate_user():
    target_username = request.form['username']
    if target_username == 'admin': #  防止管理员模拟登录到管理员自己
        return render_template('message.html', title="操作错误", message="不能模拟登录到管理员用户！")
    user = impersonate_user(session['username'], target_username) # 调用 impersonate_user 函数
    if user:
        session['is_impersonating'] = True # 设置 session 标记，表示当前处于模拟登录状态
        current_app.logger.info("Admin impersonation successful, redirecting to chat", extra={'admin_username': session['username'], 'target_username': target_username}) # 记录日志
        return redirect(url_for('chat.chat')) #  模拟登录成功后，重定向到聊天室
    else:
        current_app.logger.warning("Admin impersonation failed", extra={'admin_username': session['username'], 'target_username': target_username}) # 记录警告日志
        return render_template('message.html', title="操作错误", message="模拟登录用户失败！")