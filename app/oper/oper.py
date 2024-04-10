# app/routes/oper.py

from app.models.models import db, User, Faculty
from flask import current_app

def add_user(username,email, password, course,profile_image):
    new_user = User(username=username, email=email,password_hash=password, course=course,profile_image=profile_image)
    db.session.add(new_user)
    db.session.commit()

def check_user_exists(username,email,course):
    with current_app.app_context():
        return User.query.filter_by(username=username,email=email,course=course).first() is not None

def check_user_with_id(id, username, password):
    return User.query.filter_by(id=id, username=username, password_hash=password).first() is not None

def get_user_course(username):
    user = User.query.filter_by(username=username).first()
    return user.course if user else None

def add_faculty(email, password, course):
    new_faculty = Faculty(email=email, password_hash=password, course=course)
    db.session.add(new_faculty)
    db.session.commit()

def check_faculty_exists(email):
    return Faculty.query.filter_by(email=email).first() is not None

def authenticate_faculty(email, password, course):
    faculty = Faculty.query.filter_by(email=email).first()
    if faculty and faculty.course == course and faculty.check_password(password):
        return faculty
    return None

def get_user(email):
    user = User.query.filter_by(email=email).first()
    if user:
        return {
            'id': user.id,
            'username': user.username,
            'course': user.email,
            'password':user.password,
            'password':user.course
        }
    return None

def authenticate_user(email, password, course):
    user = User.query.filter_by(email=email, course=course).first()
    if user and user.check_password(password):
        return user
    return None
