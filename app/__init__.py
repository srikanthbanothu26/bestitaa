# app/__init__.py
from flask import Flask
from app.extensions.db import db
from app.configure import Config
from app.extensions.login_manager import login_manager
from app.routes import main, student, faculty, stu_course, uploads,assessments

def create_app():
    server = Flask(__name__)
    server.config.from_object(Config)
    login_manager.init_app(server)  # Initialize login manager
    db.init_app(server)
    with server.app_context():
        db.create_all()
    register_blueprints(server)
    return server

def register_blueprints(app):
    app.register_blueprint(main.main_bp)
    app.register_blueprint(student.student_bp)
    app.register_blueprint(faculty.faculty_bp)
    app.register_blueprint(stu_course.course_bp)
    app.register_blueprint(uploads.uploads_bp)
    app.register_blueprint(assessments.assessment_bp)