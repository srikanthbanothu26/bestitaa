#app/forms/form.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField,SubmitField,DateField,TextAreaField
from wtforms.validators import InputRequired, Email, EqualTo, Length,DataRequired,ValidationError
import re
from app.models.models import User
from app.models.models import Faculty
from flask_wtf.file import FileField, FileAllowed

class Student_RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password= PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    course = SelectField('Select Course', choices=[('python', 'Python'),('java', 'Java'),('testingtools','testingtools'),('digitalmarketing','digitalmarketing')], validators=[DataRequired()])
    profile_image = FileField('Profile Image', validators=[FileAllowed(['jpg', 'png', 'jpeg'])])
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email is already taken")
        
class StudentLoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password= PasswordField('Password', validators=[DataRequired()])
    course = SelectField('Select Course', choices=[('python', 'Python'),('java', 'Java'),('testingtools','testingtools'),('digitalmarketing','digitalmarketing')], validators=[DataRequired()])
    
class forget_passwordform(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    
class update_passwordForm(FlaskForm):
    password= PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    
    


class FacultyForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    course = SelectField('Choose Course', choices=[('python', 'Python'),('java', 'Java'),('testingtools','testingtools'),('digitalmarketing','digitalmarketing')], validators=[InputRequired()])
    
    def validate_email(self, email):
        email_pattern = r"\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?"

        if not re.match(email_pattern, email.data):
            raise ValidationError("Invalid email")

        faculty = Faculty.query.filter_by(email=email.data).first()

        if faculty:
            raise ValidationError("Email is already taken")
    
        
class FacultyLoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired()])
    course = SelectField('Choose Course', choices=[('python', 'Python'),('java', 'Java'),('testingtools','testingtools'),('digitalmarketing','digitalmarketing')], validators=[InputRequired()])
    
    

class AssessmentForm(FlaskForm):
    question = StringField('Question', validators=[DataRequired()])
    option1 = StringField('Option 1', validators=[DataRequired()])
    option2 = StringField('Option 2', validators=[DataRequired()])
    option3 = StringField('Option 3', validators=[DataRequired()])
    option4 = StringField('Option 4', validators=[DataRequired()])
    correct_answer = StringField('Correct Answer', validators=[DataRequired()])
    submit = SubmitField('Upload')


class PlacementForm(FlaskForm):
    Date=DateField('today', validators=[DataRequired()], format='%Y-%m-%d')
    placement_company_name = StringField('Company Name', validators=[DataRequired()])
    placement_company_details=StringField('Company details', validators=[DataRequired()])
    last_date_to_apply = DateField('Last Date to Apply', validators=[DataRequired()], format='%Y-%m-%d')
    course = SelectField('Choose Course', choices=[('python', 'Python'),('java', 'Java'),('testingtools','testingtools'),('digitalmarketing','digitalmarketing')], validators=[InputRequired()])
    link= StringField('apply link', validators=[DataRequired()])
    submit = SubmitField('Upload')

class PersonForm(FlaskForm):
    image_path = StringField('Image Path')
    name = StringField('Name', validators=[DataRequired()])
    qualification = StringField('Qualification')
    description = TextAreaField('Description')