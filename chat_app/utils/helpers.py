from flask import current_app


def inject_functions():
    """
    将自定义函数注入到模板上下文中。
    这样可以在模板中直接使用这些函数。
    """
    from chat_app.db.database import get_available_users_for_room # 导入函数
    return dict(get_available_users_for_room=get_available_users_for_room) # 返回包含函数的字典