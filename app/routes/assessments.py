from flask import Blueprint, render_template, redirect, flash, request, session,jsonify
from app.forms.forms import AssessmentForm
from app.models.models import Assessment, Faculty
from app.extensions.db import db
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

assessment_bp=Blueprint("assessment",__name__)

@assessment_bp.route('/upload_assessment', methods=['GET', 'POST'])
def upload_assessment():
    
    form = AssessmentForm()

    if request.method == 'POST':
        # Validate the form
        email = session.get('email')  # Retrieve email from the session
        logger.debug(f"Email from session: {email}")
        faculty = Faculty.query.filter_by(email=email).first()
        logger.debug(f"Faculty: {faculty}")

        if faculty:
            faculty_id = faculty.id
            course = faculty.course

            # Iterate through each question in the form
            for i in range(10):  # Assuming up to 10 questions
                question_key = f'question{i}'
                option1_key = f'option1{i}'
                option2_key = f'option2{i}'
                option3_key = f'option3{i}'
                option4_key = f'option4{i}'
                correct_answer_key = f'correct_answer{i}'

                # Check if the question exists
                if question_key in request.form:
                    # Create a new assessment instance for each question and add it to the database
                    assessment = Assessment(
                        question=request.form[question_key],
                        option1=request.form[option1_key],
                        option2=request.form[option2_key],
                        option3=request.form[option3_key],
                        option4=request.form[option4_key],
                        correct_answer=request.form[correct_answer_key],
                        faculty_id=faculty_id,
                        course=course
                    )
                    db.session.add(assessment)
            
            try:
                db.session.commit()  # Commit changes after adding all assessments
            except Exception as e:
                logger.exception("Error committing assessments to the database.")
                db.session.rollback()  # Rollback changes if an error occurs
                flash('An error occurred while uploading assessments. Please try again later.', 'error')
                return redirect(url_for('/'))  # Redirect to the home page or an error page

            flash('Assessment(s) uploaded successfully!', 'success')
            return redirect(f"""/{course.lower()}_upload""")
        else:
            flash('Faculty not found in the database!', 'error')
            logger.error("Faculty not found in the database.")
            return redirect(url_for('/'))  # Redirect to the home page or an error page

    return render_template('upload_assessment.html', form=form)



from datetime import datetime, timedelta
from flask import request, redirect, url_for, flash

@assessment_bp.route('/assessments/<course>', methods=['GET', 'POST'])
def display_assessments(course):
    if request.method == 'GET':
        # Query assessments based on the course
        assessments = Assessment.query.filter_by(course=course).all()
        # Pass the assessments and their indices to the template, along with the enumerate function
        return render_template('displayassessments.html', assessments=assessments, index_start=1, enumerate=enumerate)
    elif request.method == 'POST':
        # Handle form submission
        now = datetime.now()
        end_time = now + timedelta(minutes=2)  # Assuming 10 minutes time limit
        submitted_time = datetime.strptime(request.form.get('submitted_time'), '%Y-%m-%d %H:%M:%S')
        
        if now <= end_time <= submitted_time:
            # Process the submitted answers
            # Here you should handle the submitted answers, calculate scores, etc.
            flash('Answers submitted successfully!')
            return redirect('/submit_answers/<course>')  # Redirect to assessment results page
        else:
            # Submission occurred after the time limit
            flash('Time limit exceeded! Answers not submitted.')
            return redirect(url_for('/'))


@assessment_bp.route('/uploaded_questions/<int:faculty_id>', methods=['GET'])
def get_uploaded_questions(faculty_id):
    faculty = Faculty.query.get(faculty_id)
    if not faculty:
        return jsonify({'error': 'Faculty not found'}), 404

    # Query the Assessment table to fetch questions based on faculty_id
    uploaded_questions = Assessment.query.filter_by(faculty_id=faculty_id).all()
    # Convert the list of Assessment objects to a list of dictionaries
    questions = []
    for question in uploaded_questions:
        questions.append({
            'id': question.id,  # assuming each question has an ID
            'question': question.question,
            'option1': question.option1,
            'option2': question.option2,
            'option3': question.option3,
            'option4': question.option4,
            'correct_answer': question.correct_answer
        })
    print(questions)
    return jsonify(questions)


@assessment_bp.route('/delete_question', methods=['POST'])
def delete_question():
    question_id = request.json.get('question_id')

    # Query the Assessment table by question_id
    question = Assessment.query.get(question_id)

    if question:
        # Delete the question record from the database
        db.session.delete(question)
        db.session.commit()
        return '', 204
    else:
        # Question record not found in the database
        return jsonify({'error': 'Question record not found in the database'}), 404
    

from flask import render_template, request
@assessment_bp.route('/submit_answers/<course>', methods=['POST'])
def submit_answers(course):
    if request.method == 'POST':
        # Process submitted answers
        print("Form data received:", request.form)
        user_answers = {}  # Initialize an empty dictionary to store user answers
        for key, value in request.form.items():
            if key.startswith('answer'):
                question_id = key.split('answer')[1]  # Extract question ID from form field name
                user_answers[question_id] = value  # Store answer with question ID

        print("Processed user answers:", user_answers)

        # Get questions and correct answers from the database
        questions = Assessment.query.filter_by(course=course).all()

        results = []
        total_marks = 1
        
        for question in questions:
            selected_option = user_answers.values()  # Get the selected option for the current question
            print(selected_option)
            correct_option = question.correct_answer
            
            for x in selected_option:
                if x == correct_option:
                    total_marks =total_marks*2      
            results.append({
                'question': question.question,
                'selected_option': selected_option,
                'correct_option': correct_option,
                'options': [question.option1, question.option2, question.option3, question.option4]
            })

            template_context = {
                'results': results,
                'total_marks': total_marks,
                'enumerate': enumerate  
            }

        return render_template("assessmentresult.html", **template_context)
