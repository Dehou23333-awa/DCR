from flask import current_app

def inject_functions():
     from chat_app.db.database import get_available_users_for_room
     return dict(get_available_users_for_room=get_available_users_for_room)