from flask import flash, session, redirect, render_template, Blueprint, current_app
import os
from flask_wtf.csrf import generate_csrf
from flask_login import login_required
from app.models.models import placement

course_bp = Blueprint("course", __name__)

@course_bp.route("/python_course", methods=["GET", "POST"])
def python_course():
    csrf_token = generate_csrf()
    if 'username' not in session:
        flash("Please log in first.")
        return redirect('/student_login')
    
    username = session.get('username')
    course = session.get('course')
    
    # Retrieve upload folder paths from the Flask application configuration
    upload_folders = current_app.config.get('UPLOAD_FOLDERS', {}).get('python', {})
    
    # Ensure that all upload folders exist; if not, create them
    for folder_name, folder_path in upload_folders.items():
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
    
    # Get the list of files in each upload folder
    file_notes = os.listdir(upload_folders.get('notes', ''))
    file_recordings = os.listdir(upload_folders.get('recordings', ''))
    file_assignments = os.listdir(upload_folders.get('assignments', ''))
    file_assessments = os.listdir(upload_folders.get('assessments', ''))
    # Query placements related to the Python course
    python_course_placements = placement.query.filter_by(course='python').all()

    
    return render_template("python_course.html", username=username, course=course, 
                           file_notes=file_notes, file_recordings=file_recordings, 
                           file_assignments=file_assignments, file_assessments=file_assessments, csrf_token=csrf_token,python_course_placements=python_course_placements)

@course_bp.route("/java_course", methods=["GET", "POST"])
def java_course():
    csrf_token = generate_csrf()
    if 'username' not in session:
        flash("Please log in first.")
        return redirect('/student_login')
    
    username = session.get('username')
    course = session.get('course')
    
    # Retrieve upload folder paths from the Flask application configuration
    upload_folders = current_app.config.get('UPLOAD_FOLDERS', {}).get('java', {})
    
    # Ensure that all upload folders exist; if not, create them
    for folder_name, folder_path in upload_folders.items():
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
    
    # Get the list of files in each upload folder
    file_notes = os.listdir(upload_folders.get('notes', ''))
    file_recordings = os.listdir(upload_folders.get('recordings', ''))
    file_assignments = os.listdir(upload_folders.get('assignments', ''))
    file_assessments = os.listdir(upload_folders.get('assessments', ''))
    java_course_placements = placement.query.filter_by(course='java').all()
    
    return render_template("java_course.html", username=username, course=course, 
                           file_notes=file_notes, file_recordings=file_recordings, 
                           file_assignments=file_assignments, file_assessments=file_assessments, csrf_token=csrf_token,java_course_placements=java_course_placements)

@course_bp.route("/digitalmarketing_course", methods=["GET", "POST"])
def DM_course():
    csrf_token = generate_csrf()
    if 'username' not in session:
        flash("Please log in first.")
        return redirect('/student_login')
    
    username = session.get('username')
    course = session.get('course')
    
    # Retrieve upload folder paths from the Flask application configuration
    upload_folders = current_app.config.get('UPLOAD_FOLDERS', {}).get('digitalmarketing', {})
    
    # Ensure that all upload folders exist; if not, create them
    for folder_name, folder_path in upload_folders.items():
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
    
    # Get the list of files in each upload folder
    file_notes = os.listdir(upload_folders.get('notes', ''))
    file_recordings = os.listdir(upload_folders.get('recordings', ''))
    file_assignments = os.listdir(upload_folders.get('assignments', ''))
    file_assessments = os.listdir(upload_folders.get('assessments', ''))
    digitalmarketing_course_placements = placement.query.filter_by(course='digitalmarketing').all()
    
    return render_template("DM_course.html", username=username, course=course, 
                           file_notes=file_notes, file_recordings=file_recordings, 
                           file_assignments=file_assignments, file_assessments=file_assessments, csrf_token=csrf_token,digitalmarketing_course_placements=digitalmarketing_course_placements)
    
    
    
    
@course_bp.route("/testingtools_course", methods=["GET", "POST"])
def TT_course():
    csrf_token = generate_csrf()
    if 'username' not in session:
        flash("Please log in first.")
        return redirect('/student_login')
    
    username = session.get('username')
    course = session.get('course')
    
    # Retrieve upload folder paths from the Flask application configuration
    upload_folders = current_app.config.get('UPLOAD_FOLDERS', {}).get('testingtools', {})
    
    # Ensure that all upload folders exist; if not, create them
    for folder_name, folder_path in upload_folders.items():
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
    
    # Get the list of files in each upload folder
    file_notes = os.listdir(upload_folders.get('notes', ''))
    file_recordings = os.listdir(upload_folders.get('recordings', ''))
    file_assignments = os.listdir(upload_folders.get('assignments', ''))
    file_assessments = os.listdir(upload_folders.get('assessments', ''))
    testingtools_course_placements = placement.query.filter_by(course='testingtools').all()
    
    return render_template("TT_course.html", username=username, course=course, 
                           file_notes=file_notes, file_recordings=file_recordings, 
                           file_assignments=file_assignments, file_assessments=file_assessments, csrf_token=csrf_token,testingtools_course_placements=testingtools_course_placements)
    
    

from flask import make_response

@course_bp.route('/<course>/<file_type>/<filename>', methods=["GET", "POST"])
@login_required
def course_file(course, file_type, filename):
    course_folders = current_app.config.get('UPLOAD_FOLDERS', {}).get(course)
    if not course_folders:
        return "Course not found", 404

    upload_folder = course_folders.get(file_type)
    if not upload_folder:
        return "File type not found", 404

    file_path = os.path.join(upload_folder, filename)

    if os.path.exists(file_path):
        # Read the file content and strip any trailing whitespace or newline characters
        with open(file_path, 'rb') as file:
            content = file.read().strip()
        # Create a Flask response object with the file content and appropriate headers
        response = make_response(content)
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    else:
        return "File not found", 404
