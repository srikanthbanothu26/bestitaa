from flask import Blueprint, render_template, redirect, flash, request,session,jsonify,url_for,current_app
from app.forms.forms import Student_RegistrationForm, StudentLoginForm
from app.oper.oper import check_user_exists, add_user
from flask_bcrypt import Bcrypt
from app.models.models import User
from flask_login import login_user,login_required,current_user
import os
from app.extensions.db import db
from werkzeug.utils import secure_filename
from flask_wtf.csrf import generate_csrf

bcrypt = Bcrypt() 
student_bp = Blueprint('student', __name__)


PROFILE_PICS_FOLDER = 'static/profile_pics'

@student_bp.route('/student_registration', methods=["GET", "POST"])
def registration():
    form = Student_RegistrationForm(request.form)
    csrf_token = generate_csrf()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        course = form.course.data
        profile_image = form.profile_image.data
        filename = None

        if profile_image:
        # Generate a secure filename based on user ID
            filename = f"{current_user.id}.png"  # Assuming user ID is available after registration
            # Save the profile image to the upload folder
            profile_image_path = os.path.join(PROFILE_PICS_FOLDER, filename)
            profile_image.save(profile_image_path)
            
            # Update the user's profile image path in the database
            current_user.profile_image = filename
            db.session.commit()
            
        if not check_user_exists(username, email, course):
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            add_user(username, email, hashed_password, course,profile_image=filename)
            flash("Registration successful. Please log in.")
            return redirect('/student_login')
        else:
            flash("Username or email already exists. Please choose different credentials.")
            
    return render_template('student_reg.html', form=form,csrf_token=csrf_token)

@student_bp.route("/student_login", methods=["GET", "POST"])
def login():
    form = StudentLoginForm(request.form)
    csrf_token = generate_csrf()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        course=form.course.data
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password_hash, password) and course==user.course:
            login_user(user)
            session['username'] =user.username  # Store username in session
            session['course'] =user.course  # Store user course in session
            return redirect("/main")
        else:
            flash("Invalid credentials. Please try again.", "error")
    return render_template("student_login.html", form=form,csrf_token =csrf_token )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg'}

@student_bp.route('/upload_profile_image', methods=['POST'])
@login_required
def upload_profile_image():
    try:
        if 'profile_image' not in request.files:
            return jsonify({'success': False, 'message': 'No file part'}), 400
        
        file = request.files['profile_image']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No selected file'}), 400
        
        if file:
            filename = secure_filename(f"{current_user.id}.png")
            file_path = os.path.join(current_app.root_path, 'static', 'profile_pics', filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as f:
                f.write(file.read())
            current_user.profile_image = filename
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'File uploaded successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to upload profile image'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500