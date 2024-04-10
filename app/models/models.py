from app.extensions.db import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))  # Changed field name to password_hash
    course = db.Column(db.String(64))  # Add course column
    profile_image = db.Column(db.String(100), default='default.png')

    def __repr__(self):
        return f'<User {self.username}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # Hash password

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)  # Check hashed password
    
    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.id)

class Faculty(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)  # Changed field name to password_hash
    course = db.Column(db.String(64))  # Add course column

    def __repr__(self):
        return f'<email {self.email}>'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)  # Hash password

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)  # Check hashed password
    
    def is_active(self):
        return True
    
    def get_id(self):
        return str(self.id)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)  # New column for storing file path
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'), nullable=False)
    day = db.Column(db.String(300), nullable=False)  # Changed to DateTime type for including time

    def __repr__(self):
        # Format the datetime in Indian standard format # %I for 12-hour clock, %p for AM/PM
        return f"File(filename='{self.filename}', day='{self.day}')"

class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    option1 = db.Column(db.String(255), nullable=False)
    option2 = db.Column(db.String(255), nullable=False)
    option3 = db.Column(db.String(255), nullable=False)
    option4 = db.Column(db.String(255), nullable=False)
    correct_answer = db.Column(db.String(255), nullable=False)
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'), nullable=False)
    course = db.Column(db.String(64), nullable=False)  # Add course column

    def __repr__(self):
        return f"<Assessment {self.id}>"
    
    
 
class placement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Date =  db.Column(db.Date, nullable=False)
    placement_company_name = db.Column(db.String(255), nullable=False)
    company_details=db.Column(db.String(600), nullable=False)   
    last_date_to_apply = db.Column(db.Date, nullable=False)
    course = db.Column(db.String(64), nullable=False)
    link = db.Column(db.String(400), nullable=False)
    
    
    def __repr__(self):
        return f"<Placement {self.id}>"
    
    
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    filepath = db.Column(db.String(255))
    
    def __repr__(self):
        return f"<Image id={self.id}, filename={self.filename}, filepath={self.filepath}>"
 
from sqlalchemy import Text

class Person(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(Text)
    name = db.Column(db.String(50), nullable=False)
    qualification = db.Column(db.String(50))
    description = db.Column(Text)