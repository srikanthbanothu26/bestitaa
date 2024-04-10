# app/extensions/login_manager.py

from flask_login import LoginManager
from app.models.models import User, Faculty

login_manager = LoginManager()

@login_manager.user_loader

def load_user(user_id):
    # Assuming User and Faculty models have an 'id' attribute
    user = User.query.get(user_id)
    if not user:
        user = Faculty.query.get(user_id)
    return user
