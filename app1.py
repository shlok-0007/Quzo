from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from datetime import datetime
from config import Config
from models import db, User, Quiz, Question, Result, QuizSession
import google.generativeai as genai
import json
import re
from flask_migrate import Migrate
from api_utils import generate_quiz_questions

from functools import wraps
import traceback # For debugging
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
from models import StudentAnswer
import csv
from io import StringIO
from flask import make_response
import io
import random
import traceback

# If using Flask-Login:
# from flask_login import LoginManager, login_user, logout_user, current_user, login_required

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

# Configure Gemini API
try:
    genai.configure(api_key=app.config['GEMINI_API_KEY'])
except Exception as e:
    print(f"Error configuring Gemini API: {e}")

# If using Flask-Login:
# login_manager = LoginManager()
# login_manager.init_app(app)
# login_manager.login_view = 'login' # Redirect here if login required

# --- Database Setup ---
# Create database tables if they don't exist
with app.app_context():
    try:
        db.create_all()
        print("Database tables created (if they didn't exist).")
    except Exception as e:
        print(f"Error creating database tables: {e}")
        traceback.print_exc() # Print detailed traceback

# --- Decorators for Role-Based Access Control ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        # Optionally load user object here if needed frequently
        # user = User.query.get(session['user_id'])
        # if not user: # Handle case where user ID in session doesn't exist anymore
        #     session.pop('user_id', None)
        #     session.pop('user_role', None)
        #     flash('User not found, please log in again.', 'warning')
        #     return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def professor_required(f):
    @wraps(f)
    @login_required # Ensure user is logged in first
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'professor':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index')) # Or student dashboard?
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    @login_required # Ensure user is logged in first
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'student':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index')) # Or professor dashboard?
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/home')
def home():
    if 'user_id' in session:
        if session['user_role'] == 'professor':
            return redirect(url_for('professor_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('home.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        feedback = request.form.get('feedback')
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"""[{timestamp}] Feedback from: {name} ({email})
{feedback}
-------------------------------------\n"""
        
        with open('feedback.log', 'a', encoding='utf-8') as f:
            f.write(log_entry)
            
        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('about'))
        
    return render_template('about.html')

@app.route('/')
def index():
    if 'user_id' in session:
        if session['user_role'] == 'professor':
            return redirect(url_for('professor_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return redirect(url_for('home'))

# -- Authentication Routes --
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        security_question = request.form.get('security_question')
        security_answer = request.form.get('security_answer')

        # Basic Validation
        if not all([username, email, password, confirm_password, role, security_question, security_answer]):
            flash('All fields are required.', 'danger')
            return redirect(url_for('register'))
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        if role not in ['student', 'professor']:
             flash('Invalid role selected.', 'danger')
             return redirect(url_for('register'))
        if not security_question.isdigit() or int(security_question) < 1 or int(security_question) > 5:
             flash('Please select a valid security question.', 'danger')
             return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            flash('Username or email already exists.', 'warning')
            return redirect(url_for('register'))

        # Create new user with security question and answer
        new_user = User(
            username=username, 
            email=email, 
            role=role,
            security_question=security_question
        )
        new_user.set_password(password)
        new_user.set_security_answer(security_answer)
        
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred during registration: {e}', 'danger')
            print(f"Registration Error: {e}")
            traceback.print_exc()
            return redirect(url_for('register'))
    
    # For GET request, pass security questions to the template
    from models import SECURITY_QUESTIONS
    return render_template('register.html', security_questions=SECURITY_QUESTIONS)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    from models import SECURITY_QUESTIONS
    
    if request.method == 'POST':
        username = request.form.get('username')
        security_answer = request.form.get('security_answer')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Get the user and store in session
        user = None
        if username:
            user = User.query.filter_by(username=username).first()
            session['reset_username'] = username  # Store username in session
        
        # If coming from first form (username submission)
        if username and not security_answer and not new_password:
            if not user:
                flash('No account found with that username.', 'danger')
                return render_template('forgot_password.html')
                
            if not user.security_question:
                flash('No security question set for this account. Please contact support.', 'danger')
                return render_template('forgot_password.html')
                
            return render_template('forgot_password.html',
                               show_security_question=True,
                               username=username,
                               security_question=next((q[1] for q in SECURITY_QUESTIONS if q[0] == user.security_question), ''))
        
        # If coming from security answer form
        if security_answer and 'reset_username' in session:
            user = User.query.filter_by(username=session['reset_username']).first()
            if not user:
                session.pop('reset_username', None)
                flash('Session expired. Please start over.', 'danger')
                return redirect(url_for('forgot_password'))
                
            if not user.check_security_answer(security_answer):
                flash('Incorrect answer to security question.', 'danger')
                return render_template('forgot_password.html',
                                   show_security_question=True,
                                   username=user.username,
                                   security_question=next((q[1] for q in SECURITY_QUESTIONS if q[0] == user.security_question), ''))
            
            # Store verification in session
            session['security_verified'] = True
            return render_template('forgot_password.html',
                               show_security_question=True,
                               show_new_password=True,
                               username=user.username,
                               security_question=next((q[1] for q in SECURITY_QUESTIONS if q[0] == user.security_question), ''))
        
        # If submitting new password
        if new_password and 'reset_username' in session and session.get('security_verified'):
            user = User.query.filter_by(username=session['reset_username']).first()
            if not user:
                session.pop('reset_username', None)
                session.pop('security_verified', None)
                flash('Session expired. Please start over.', 'danger')
                return redirect(url_for('forgot_password'))
            
            if new_password != confirm_password:
                flash('Passwords do not match.', 'danger')
            else:
                # Validate password strength
                import re
                if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\'\":\\|,.<>\/?]).{8,}$', new_password):
                    flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'danger')
                else:
                    user.set_password(new_password)
                    try:
                        db.session.commit()
                        # Clear session data
                        session.pop('reset_username', None)
                        session.pop('security_verified', None)
                        flash('Your password has been reset successfully! You can now log in with your new password.', 'success')
                        return redirect(url_for('login'))
                    except Exception as e:
                        db.session.rollback()
                        flash('An error occurred while resetting your password. Please try again.', 'danger')
                        print(f"Password reset error: {e}")
                        traceback.print_exc()
            
            return render_template('forgot_password.html',
                               show_security_question=True,
                               show_new_password=True,
                               username=user.username,
                               security_question=next((q[1] for q in SECURITY_QUESTIONS if q[0] == user.security_question), ''))
    
    # Clear any existing session data on initial load
    if 'reset_username' in session:
        session.pop('reset_username', None)
    if 'security_verified' in session:
        session.pop('security_verified', None)
        
    return render_template('forgot_password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
             flash('Username and password are required.', 'danger')
             return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Store user info in session (Flask's secure session)
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            # Redirect based on role
            if user.role == 'professor':
                return redirect(url_for('professor_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
            # If using Flask-Login: login_user(user) # Handles session management
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html', title='Login')

@app.route('/ai_quiz_generator', methods=['GET', 'POST'])
@login_required
@professor_required
def ai_quiz_generator():
    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            try:
                topic = request.form.get('topic')
                num_questions = int(request.form.get('num_questions', 10))
                difficulty = request.form.get('difficulty', 'medium')
                
                # Use the new API management system
                questions_list = generate_quiz_questions(topic, num_questions, difficulty=difficulty)
                
                if not questions_list:
                    flash('No valid questions were generated. Please try again with a different topic.', 'warning')
                    return redirect(url_for('ai_quiz_generator'))
                
                print("--- GENERATED QUESTIONS ---")
                for i, q in enumerate(questions_list):
                    print(f"Q{i+1}: {q['question_text']}")
                    print(f"Options: {q['options']}")
                    print(f"Correct: {q['correct_answer']}")
                    print("---")

                return render_template('ai_quiz_generator.html', questions=questions_list, topic=topic)

            except Exception as e:
                flash(f'An error occurred while generating questions: {str(e)}', 'danger')
                print(f"AI Generation Error: {e}")
                traceback.print_exc()
                return redirect(url_for('ai_quiz_generator'))

        elif action == 'create_quiz':
            try:
                quiz_title = request.form.get('quiz_title')
                time_limit = request.form.get('time_limit')
                marks_correct = float(request.form.get('marks_correct', 4))
                marks_incorrect = float(request.form.get('marks_incorrect', -1))
                selected_indices = request.form.getlist('selected_questions')

                if not selected_indices:
                    flash('You must select at least one question to create a quiz.', 'warning')
                    return redirect(url_for('ai_quiz_generator'))

                # Create the new quiz
                access_code = request.form.get('access_code')
                new_quiz = Quiz(
                    title=quiz_title,
                    time_limit=int(time_limit),
                    professor_id=session['user_id'],
                    access_code=access_code if access_code else None,
                    marks_correct=marks_correct,
                    marks_incorrect=marks_incorrect
                )
                db.session.add(new_quiz)
                db.session.flush() # Flush to get the new_quiz.id

                # Process and save the selected questions
                questions_added = 0
                for index in selected_indices:
                    question_json = request.form.get(f'question_data_{index}')
                    if question_json:
                        try:
                            question_data = json.loads(question_json)
                            
                            # The AI sometimes returns options as a dict instead of a list. Handle this.
                            options = question_data.get('options', [])
                            if isinstance(options, dict):
                                options = list(options.values())
                            
                            # Ensure we have exactly 4 options
                            while len(options) < 4:
                                options.append("No option")
                            options = options[:4]  # Take only first 4

                            # Find the correct option index ('a', 'b', 'c', 'd')
                            correct_option_text = question_data.get('correct_answer')
                            correct_option_char = 'a'
                            for i, option_text in enumerate(options):
                                if option_text.strip() == correct_option_text.strip():
                                    correct_option_char = chr(ord('a') + i)
                                    break

                            new_question = Question(
                                quiz_id=new_quiz.id,
                                text=question_data.get('question_text'),
                                option_a=options[0] if len(options) > 0 else '',
                                option_b=options[1] if len(options) > 1 else '',
                                option_c=options[2] if len(options) > 2 else '',
                                option_d=options[3] if len(options) > 3 else '',
                                correct_option=correct_option_char
                            )
                            db.session.add(new_question)
                            questions_added += 1
                        except json.JSONDecodeError as e:
                            print(f"Error parsing question data for index {index}: {e}")
                            continue
                
                if questions_added == 0:
                    db.session.rollback()
                    flash('No valid questions could be processed. Please try again.', 'danger')
                    return redirect(url_for('ai_quiz_generator'))
                
                db.session.commit()
                flash(f'Quiz "{quiz_title}" created successfully with {questions_added} questions!', 'success')
                return redirect(url_for('professor_dashboard'))

            except Exception as e:
                db.session.rollback()
                flash(f'An error occurred while creating the quiz: {e}', 'danger')
                print(f"Quiz Creation Error: {e}")
                traceback.print_exc()
                return redirect(url_for('ai_quiz_generator'))

    return render_template('ai_quiz_generator.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))



@app.route('/professor/quiz/<int:quiz_id>/download/<string:username>')
@professor_required
def download_student_pdf(quiz_id, username):
    quiz = Quiz.query.get_or_404(quiz_id)
    user = User.query.filter_by(username=username).first_or_404()
    result = Result.query.filter_by(quiz_id=quiz.id, student_id=user.id).first()

    if not result:
        flash("No result found for this student.", "warning")
        return redirect(url_for('view_quiz_results', quiz_id=quiz.id))

    percentage = (result.score / (quiz.marks_correct * result.total_questions)) * 100
    incorrect = result.total_questions - result.score

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 800, f"Quiz Result Report")
    p.setFont("Helvetica", 12)
    p.drawString(100, 770, f"Quiz Title: {quiz.title}")
    p.drawString(100, 750, f"Student: {user.username}")
    p.drawString(100, 730, f"Score: {result.score}/{result.total_questions}")
    p.drawString(100, 710, f"Correct: {result.score}")
    p.drawString(100, 690, f"Incorrect: {incorrect}")
    p.drawString(100, 670, f"Percentage: {percentage:.2f}%")
    p.drawString(100, 650, f"Submitted At: {result.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}")

    p.showPage()
    p.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={user.username}_quiz_{quiz.id}_result.pdf'
    return response



# -- Professor Routes --
@app.route('/professor/dashboard')
@professor_required
def professor_dashboard():
    quizzes = Quiz.query.filter_by(professor_id=session['user_id']).all()

    quiz_analytics = []
    for quiz in quizzes:
        results = Result.query.filter_by(quiz_id=quiz.id).all()
        attempts = len(results)
        avg_score = round(sum(r.score for r in results) / attempts, 2) if attempts > 0 else 0
        quiz_analytics.append({
            'quiz_id': quiz.id,
            'quiz_title': quiz.title,
            'attempts': attempts,
            'avg_score': avg_score
        })

    return render_template('professor_dashboard.html', quizzes=quizzes, quiz_analytics=quiz_analytics)

# @app.route('/debug/results')
# def debug_results():
#     results = Result.query.all()
#     return "<br>".join(str(r) for r in results)

@app.route('/debug/quiz/<int:quiz_id>')
def debug_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return f"Quiz ID: {quiz.id} — Report Released: {quiz.report_released}"


@app.route('/professor/quiz/<int:quiz_id>/update_access_code', methods=['POST'])
@professor_required
def update_access_code(quiz_id):
    data = request.get_json()
    new_code = data.get('access_code')
    quiz = Quiz.query.filter_by(id=quiz_id, professor_id=session['user_id']).first_or_404()
    quiz.access_code = new_code
    db.session.commit()
    return jsonify({'success': True})

@app.route('/student/quiz/<int:quiz_id>/access', methods=['GET', 'POST'])
@student_required
def access_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # If quiz has a code, show code form
    if quiz.access_code:
        if request.method == 'POST':
            entered_code = request.form.get('access_code', '').strip()
            if entered_code == quiz.access_code:
                return redirect(url_for('take_quiz', quiz_id=quiz_id))
            else:
                flash("Incorrect access code.", "danger")
        return render_template('enter_quiz_code.html', quiz=quiz)

    # No access code → redirect to quiz
    return redirect(url_for('take_quiz', quiz_id=quiz_id))


@app.route('/professor/quiz/<int:quiz_id>/export')
@professor_required
def export_quiz_results(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if quiz.professor_id != session['user_id']:
        flash("Unauthorized access to export.", "danger")
        return redirect(url_for('professor_dashboard'))

    results = db.session.query(
        User.username,
        Result.score,
        Result.total_questions,
        Result.submitted_at
    ).join(Result, Result.student_id == User.id
    ).filter(Result.quiz_id == quiz.id).all()

    if not results:
        flash("No results to export.", "warning")
        return redirect(url_for('view_quiz_results', quiz_id=quiz_id))

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'Score', 'Total Questions', 'Percentage', 'Submitted At'])

    for username, score, total, submitted_at in results:
        percentage = round((score / total) * 100, 1) if total > 0 else 0
        writer.writerow([username, score, total, f"{percentage}%", submitted_at.strftime('%Y-%m-%d %H:%M')])

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename=quiz_{quiz_id}_results.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# @app.route('/professor/quiz/create', methods=['GET', 'POST'])
# @professor_required
# def create_quiz():
#     if request.method == 'POST':
#         title = request.form.get('quiz_title')
#         if not title:
#             flash('Quiz title is required.', 'danger')
#             return redirect(url_for('create_quiz'))

#         try:
#             # Parse time limit
#             time_limit_raw = request.form.get('time_limit')
#             time_limit = int(time_limit_raw) if time_limit_raw and time_limit_raw.isdigit() else None
#             deadline = None
#             deadline_str = request.form.get('deadline')
#             access_code = request.form.get('access_code') or None

#             # ✅ New: Parse marking scheme
#             marks_correct = float(request.form.get('marks_correct', 1.0))
#             marks_incorrect = float(request.form.get('marks_incorrect', 0.0))

#             if deadline_str:
#                 try:
#                     deadline = datetime.strptime(deadline_str, "%Y-%m-%dT%H:%M")
#                 except ValueError:
#                     flash("Invalid deadline format.", "danger")
#                     return redirect(url_for('create_quiz'))

#             # ✅ Create the Quiz object with marking scheme
#             new_quiz = Quiz(
#                 title=title,
#                 professor_id=session['user_id'],
#                 time_limit=time_limit,
#                 deadline=deadline,
#                 access_code=access_code,
#                 marks_correct=marks_correct,
#                 marks_incorrect=marks_incorrect
#             )
#             db.session.add(new_quiz)
#             db.session.flush()  # Get new_quiz.id

#             # Process questions
#             question_count = 0
#             i = 1
#             while True:
#                 q_text = request.form.get(f'q{i}_text')
#                 q_image_file = request.files.get(f'q{i}_image')

#                 # Skip blank questions (but allow partial questions to be validated properly)
#                 if not q_text and (not q_image_file or q_image_file.filename == ''):
#                     i += 1
#                     continue

#                 image_filename = None
#                 if q_image_file and q_image_file.filename != '':
#                     image_filename = secure_filename(q_image_file.filename)
#                     image_path = os.path.join('static/uploads', image_filename)
#                     os.makedirs(os.path.dirname(image_path), exist_ok=True)
#                     q_image_file.save(image_path)

#                 # ✅ Ensure question isn't totally empty
#                 if not q_text and not image_filename:
#                     flash(f"Question {i} must have either text, image, or both.", 'danger')
#                     db.session.rollback()
#                     return redirect(url_for('create_quiz'))

#                 opt_a = request.form.get(f'q{i}_opt_a')
#                 opt_b = request.form.get(f'q{i}_opt_b')
#                 opt_c = request.form.get(f'q{i}_opt_c')
#                 opt_d = request.form.get(f'q{i}_opt_d')
#                 correct = request.form.get(f'q{i}_correct')

#                 if not all([opt_a, opt_b, opt_c, opt_d, correct]):
#                     flash(f'All options and correct answer are required for Question {i}.', 'danger')
#                     db.session.rollback()
#                     return redirect(url_for('create_quiz'))

#                 if correct not in ['a', 'b', 'c', 'd']:
#                     flash(f'Invalid correct option for Question {i}.', 'danger')
#                     db.session.rollback()
#                     return redirect(url_for('create_quiz'))

#                 new_question = Question(
#                     quiz_id=new_quiz.id,
#                     text=q_text if q_text else None,
#                     image=image_filename if image_filename else None,
#                     option_a=opt_a,
#                     option_b=opt_b,
#                     option_c=opt_c,
#                     option_d=opt_d,
#                     correct_option=correct.lower()
#                 )
#                 db.session.add(new_question)
#                 question_count += 1
#                 i += 1


#             if question_count == 0:
#                 flash('A quiz must have at least one question.', 'danger')
#                 db.session.rollback()
#                 return redirect(url_for('create_quiz'))

#             db.session.commit()
#             flash('Quiz created successfully!', 'success')
#             return redirect(url_for('professor_dashboard'))

#         except Exception as e:
#             db.session.rollback()
#             flash(f'Error while creating quiz: {str(e)}', 'danger')
#             traceback.print_exc()
#             return redirect(url_for('create_quiz'))

#     return render_template('create_quiz.html', title='Create Quiz')


@app.route('/professor/quiz/create', methods=['GET', 'POST'])
@professor_required
def create_quiz():
    if request.method == 'POST':
        title = request.form.get('quiz_title')
        if not title:
            flash('Quiz title is required.', 'danger')
            return redirect(url_for('create_quiz'))

        try:
            # Parse time limit
            time_limit_raw = request.form.get('time_limit')
            time_limit = int(time_limit_raw) if time_limit_raw and time_limit_raw.isdigit() else None
            deadline = None
            deadline_str = request.form.get('deadline')
            access_code = request.form.get('access_code') or None

            # ✅ New: Parse marking scheme
            marks_correct = float(request.form.get('marks_correct', 1.0))
            marks_incorrect = float(request.form.get('marks_incorrect', 0.0))

            if deadline_str:
                try:
                    deadline = datetime.strptime(deadline_str, "%Y-%m-%dT%H:%M")
                except ValueError:
                    flash("Invalid deadline format.", "danger")
                    return redirect(url_for('create_quiz'))

            # ✅ Create the Quiz object with marking scheme
            new_quiz = Quiz(
                title=title,
                professor_id=session['user_id'],
                time_limit=time_limit,
                deadline=deadline,
                access_code=access_code,
                marks_correct=marks_correct,
                marks_incorrect=marks_incorrect
            )
            db.session.add(new_quiz)
            db.session.flush()  # Get new_quiz.id

            # Process questions
            question_count = 0
            i = 1
            while True:
                q_text = request.form.get(f'q{i}_text')
                q_image_file = request.files.get(f'q{i}_image')

                if not q_text and (not q_image_file or q_image_file.filename == ''):
                    break

                image_filename = None
                if q_image_file and q_image_file.filename != '':
                    image_filename = secure_filename(q_image_file.filename)
                    image_path = os.path.join('static/uploads', image_filename)
                    os.makedirs(os.path.dirname(image_path), exist_ok=True)
                    q_image_file.save(image_path)

                opt_a = request.form.get(f'q{i}_opt_a')
                opt_b = request.form.get(f'q{i}_opt_b')
                opt_c = request.form.get(f'q{i}_opt_c')
                opt_d = request.form.get(f'q{i}_opt_d')
                correct = request.form.get(f'q{i}_correct')

                if not all([opt_a, opt_b, opt_c, opt_d, correct]):
                    flash(f'All options and correct answer are required for Question {i}.', 'danger')
                    db.session.rollback()
                    return redirect(url_for('create_quiz'))

                if correct not in ['a', 'b', 'c', 'd']:
                    flash(f'Invalid correct option for Question {i}.', 'danger')
                    db.session.rollback()
                    return redirect(url_for('create_quiz'))

                new_question = Question(
                    quiz_id=new_quiz.id,
                    text=q_text if q_text else None,
                    image=image_filename if image_filename else None,
                    option_a=opt_a,
                    option_b=opt_b,
                    option_c=opt_c,
                    option_d=opt_d,
                    correct_option=correct.lower()
                )
                db.session.add(new_question)
                question_count += 1
                i += 1

            if question_count == 0:
                flash('A quiz must have at least one question.', 'danger')
                db.session.rollback()
                return redirect(url_for('create_quiz'))

            db.session.commit()
            flash('Quiz created successfully!', 'success')
            return redirect(url_for('professor_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error while creating quiz: {str(e)}', 'danger')
            traceback.print_exc()
            return redirect(url_for('create_quiz'))

    return render_template('create_quiz.html', title='Create Quiz')




@app.route('/test_quiz_creator/<int:quiz_id>')
def test_creator(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    return f"Quiz created by: {quiz.creator.username}"

# @app.route('/quiz/<int:quiz_id>/check_update')
# @student_required
# def check_quiz_update(quiz_id):
#     user_id = session.get("user_id")
#     quiz = Quiz.query.get_or_404(quiz_id)
#     quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()

#     if not quiz_session or not quiz.last_updated or not quiz_session.quiz_last_updated:
#         return jsonify({'reload': False})

#     # ✅ Check if professor updated quiz after student started
#     if quiz.last_updated > quiz_session.quiz_last_updated:
#         return jsonify({'reload': True})

#     return jsonify({'reload': False})

@app.route('/quiz/<int:quiz_id>/check_update')
@student_required
def check_quiz_update(quiz_id):
    user_id = session.get("user_id")
    quiz = Quiz.query.get_or_404(quiz_id)
    session_obj = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()

    if not session_obj:
        return jsonify({'reload': False})

    question_changes = []
    question_indexes = []  # <-- new

    if not session_obj.question_last_seen:
        session_obj.question_last_seen = {}

    for idx, q in enumerate(quiz.questions):  # Use enumerate to get index
        q_id = str(q.id)
        seen_time = session_obj.question_last_seen.get(q_id)
        if q.last_updated:
            if not seen_time or q.last_updated > datetime.fromisoformat(seen_time):
                question_changes.append(q_id)
                question_indexes.append(idx + 1)  # index starts at 0, so +1

    if question_changes:
        return jsonify({
            'reload': True,
            'changed_questions': question_changes,
            'changed_indexes': question_indexes  # <-- send question numbers
        })

    return jsonify({'reload': False})


@app.route('/quiz/<int:quiz_id>/mark_seen', methods=["POST"])
@student_required
def mark_seen_questions(quiz_id):
    data = request.get_json()
    seen_qids = data.get("questions_seen", [])
    user_id = session.get("user_id")
    
    quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    quiz = Quiz.query.get_or_404(quiz_id)

    if not quiz_session or not seen_qids:
        return jsonify(success=False)

    if not quiz_session.question_last_seen:
        quiz_session.question_last_seen = {}

    for q in quiz.questions:
        if str(q.id) in seen_qids and q.last_updated:
            quiz_session.question_last_seen[str(q.id)] = q.last_updated.isoformat()

    db.session.commit()
    return jsonify(success=True)


@app.route('/professor/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@professor_required
def edit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = quiz.questions

    if request.method == 'POST':
        try:
            quiz.title = request.form.get('quiz_title')
            time_limit = request.form.get('time_limit')
            quiz.time_limit = int(time_limit) if time_limit and time_limit.isdigit() else None
            
            # Update access code (empty string means remove access code)
            access_code = request.form.get('access_code', '').strip()
            quiz.access_code = access_code if access_code else None

            updated_questions = []

            # 1. Update existing questions
            for question in questions:
                q_id = question.id
                if f'q{q_id}_text' not in request.form:
                    continue  # This question was removed in the form (e.g., deleted)

                question.text = request.form.get(f'q{q_id}_text') or None
                question.option_a = request.form.get(f'q{q_id}_opt_a')
                question.option_b = request.form.get(f'q{q_id}_opt_b')
                question.option_c = request.form.get(f'q{q_id}_opt_c')
                question.option_d = request.form.get(f'q{q_id}_opt_d')
                correct_val = request.form.get(f'q{q_id}_correct')
                question.correct_option = correct_val.lower() if correct_val else None

                image_file = request.files.get(f'q{q_id}_image')
                if image_file and image_file.filename != '':
                    image_filename = secure_filename(image_file.filename)
                    image_path = os.path.join('static/uploads', image_filename)
                    os.makedirs(os.path.dirname(image_path), exist_ok=True)
                    image_file.save(image_path)
                    question.image = image_filename

                if not all([question.option_a, question.option_b, question.option_c, question.option_d, question.correct_option]):
                    flash(f"All fields required for question ID {q_id}.", 'danger')
                    return redirect(request.url)

                updated_questions.append(question.id)


            # 2. Add new questions
            i = 1
            while True:
                new_q_text = request.form.get(f'new_q{i}_text')
                new_q_image = request.files.get(f'new_q{i}_image')
                if not new_q_text and (not new_q_image or new_q_image.filename == ''):
                    break

                image_filename = None
                if new_q_image and new_q_image.filename != '':
                    image_filename = secure_filename(new_q_image.filename)
                    image_path = os.path.join('static/uploads', image_filename)
                    os.makedirs(os.path.dirname(image_path), exist_ok=True)
                    new_q_image.save(image_path)

                opt_a = request.form.get(f'new_q{i}_opt_a')
                opt_b = request.form.get(f'new_q{i}_opt_b')
                opt_c = request.form.get(f'new_q{i}_opt_c')
                opt_d = request.form.get(f'new_q{i}_opt_d')
                correct = request.form.get(f'new_q{i}_correct')

                if not all([opt_a, opt_b, opt_c, opt_d, correct]):
                    flash(f"All options and correct answer are required for new question {i}.", 'danger')
                    return redirect(request.url)

                new_question = Question(
                    quiz_id=quiz.id,
                    text=new_q_text if new_q_text else None,
                    image=image_filename if image_filename else None,
                    option_a=opt_a,
                    option_b=opt_b,
                    option_c=opt_c,
                    option_d=opt_d,
                    correct_option=correct.lower() if correct else None
                )
                db.session.add(new_question)
                i += 1

            db.session.commit()
            flash('Quiz and questions updated successfully.', 'success')

            # ✅ 3. REGRADING all answers after question changes
            all_answers = StudentAnswer.query.filter_by(quiz_id=quiz.id).all()
            for ans in all_answers:
                q = Question.query.get(ans.question_id)
                if q and q.correct_option:
                    ans.is_correct = (
                        ans.selected_option and
                        ans.selected_option.lower() == q.correct_option.lower()
                    )

            db.session.commit()

            # ✅ 4. Update Result scores based on updated answers
            student_ids = db.session.query(StudentAnswer.student_id).filter(
                StudentAnswer.quiz_id == quiz.id
            ).distinct().all()

            for (student_id,) in student_ids:
                result = Result.query.filter_by(student_id=student_id, quiz_id=quiz.id).first()
                if result:
                    marks_correct = quiz.marks_correct or 1.0
                    marks_incorrect = quiz.marks_incorrect or 0.0

                    answers = StudentAnswer.query.filter_by(
                        quiz_id=quiz.id,
                        student_id=student_id
                    ).all()

                    score = 0
                    for ans in answers:
                        if ans.selected_option:
                            if ans.is_correct:
                                score += marks_correct
                            else:
                                score += marks_incorrect
                        # skipped → 0 marks

                    result.score = score
                    result.total_questions = len(quiz.questions)
            quiz.last_updated = datetime.utcnow()  # ✅ Force update timestamp
            db.session.add(quiz)
            db.session.commit()
            flash("All student answers have been regraded.", "info")


        except Exception as e:
            db.session.rollback()
            flash(f'Error updating quiz: {e}', 'danger')
            traceback.print_exc()
            return redirect(request.url)

    return render_template('edit_quiz.html', quiz=quiz, questions=questions)




@app.route('/professor/quiz/<int:quiz_id>/delete', methods=['POST'])
@professor_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # ✅ Security check
    if quiz.professor_id != session['user_id']:
        flash('You do not have permission to delete this quiz.', 'danger')
        return redirect(url_for('professor_dashboard'))

    try:
        # ✅ Delete related data in proper order (children first)
        StudentAnswer.query.filter_by(quiz_id=quiz.id).delete()
        QuizSession.query.filter_by(quiz_id=quiz.id).delete()
        Result.query.filter_by(quiz_id=quiz.id).delete()
        Question.query.filter_by(quiz_id=quiz.id).delete()
        db.session.delete(quiz)

        db.session.commit()
        flash('Quiz deleted successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting quiz: {e}', 'danger')

    return redirect(url_for('professor_dashboard'))



@app.route('/professor/question/<int:question_id>/delete', methods=['POST'])
@professor_required
def delete_question(question_id):
    question = Question.query.get_or_404(question_id)

    # Check: is this question part of the logged-in professor's quiz?
    quiz = Quiz.query.get(question.quiz_id)
    if quiz.professor_id != session['user_id']:
        flash("Unauthorized to delete this question.", "danger")
        return redirect(url_for('professor_dashboard'))

    try:
        db.session.delete(question)
        db.session.commit()
        flash("Question deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting question: {e}", "danger")

    return redirect(url_for('edit_quiz', quiz_id=quiz.id))

@app.route('/student/quiz/<int:quiz_id>/report', endpoint='quiz_report')
@student_required
def student_quiz_report(quiz_id):
    print("✅ student_quiz_report ROUTE HIT")

    user_id = session.get('user_id')
    quiz = Quiz.query.get_or_404(quiz_id)

    if not quiz.report_released:
        flash("Report not yet released by professor.", "warning")
        return redirect(url_for('student_dashboard'))

    result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first_or_404()
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    answers = StudentAnswer.query.filter_by(student_id=user_id, quiz_id=quiz_id).all()
    answer_map = {a.question_id: a.selected_option for a in answers}

    report = []
    for q in questions:
        report.append({
            "text": q.text,
            "image": q.image,
            "options": [q.option_a, q.option_b, q.option_c, q.option_d],
            "correct": q.correct_option.lower(),
            "selected": answer_map.get(q.id, None)
        })
    print("Checking if report released:", quiz.report_released)
    return render_template("student_result_report.html", quiz=quiz, result=result, report=report)



@app.route('/professor/quiz/<int:quiz_id>/release_report', methods=['POST'])
@professor_required
def release_report(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    quiz.report_released = True
    db.session.commit()
    flash("Quiz report has been released to students.", "success")
    return redirect(url_for('view_quiz_results', quiz_id=quiz.id))

@app.route('/professor/quiz/<int:quiz_id>/regrade', methods=['POST'])
@professor_required
def regrade_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    results = Result.query.filter_by(quiz_id=quiz_id).all()
    professor_id = session['user_id']

    for result in results:
        student_id = result.student_id
        answers = StudentAnswer.query.filter_by(quiz_id=quiz_id, student_id=student_id).all()
        correct_count = sum(1 for ans in answers if ans.is_correct)
        
        if result.score != correct_count:
            # Save change to log
            log = RegradeLog(
                quiz_id=quiz_id,
                student_id=student_id,
                old_score=result.score,
                new_score=correct_count,
                regraded_by=professor_id
            )
            db.session.add(log)

        # Update score
        result.score = correct_count
        result.total_questions = len(answers)

    db.session.commit()
    flash('Regrading and logging completed.', 'success')
    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))

@app.route('/professor/quiz/<int:quiz_id>/regrade_logs')
@professor_required
def view_regrade_logs(quiz_id):
    logs = RegradeLog.query.filter_by(quiz_id=quiz_id).order_by(RegradeLog.timestamp.desc()).all()
    quiz = Quiz.query.get_or_404(quiz_id)
    return render_template('regrade_logs.html', logs=logs, quiz=quiz)


@app.route('/professor/quiz/<int:quiz_id>/student/<int:student_id>/report')
@professor_required
def professor_view_student_report(quiz_id, student_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    result = Result.query.filter_by(student_id=student_id, quiz_id=quiz_id).first_or_404()
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    answers = StudentAnswer.query.filter_by(student_id=student_id, quiz_id=quiz_id).all()
    answer_map = {a.question_id: a.selected_option for a in answers}

    report = []
    for q in questions:
        report.append({
            "text": q.text,
            "image": q.image,
            "options": [q.option_a, q.option_b, q.option_c, q.option_d],
            "correct": q.correct_option.lower(),
            "selected": answer_map.get(q.id, None)
        })

    return render_template(
        'student_result_report.html',
        quiz=quiz,
        result=result,
        report=report,
        professor_view=True  # 👈 Set this flag

    )


@app.route('/professor/quiz/<int:quiz_id>/release_report', methods=['POST'])
@professor_required
def release_quiz_report(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    quiz.report_released = True
    db.session.commit()
    flash("Reports successfully released to all students!", "success")
    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))


@app.route('/professor/quiz/<int:quiz_id>/results')
@professor_required
def view_quiz_results(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    # Get results with username, score, total_questions, submitted_at
    results = db.session.query(
        User.id.label("student_id"),
        User.username,
        Result.score,
        Result.total_questions,
        Result.submitted_at
    ).join(Result, Result.student_id == User.id).filter(Result.quiz_id == quiz_id).all()

    chart_data = []
    for r in results:
        student_id = r.student_id
        score = r.score
        total = r.total_questions
        max_possible = total * quiz.marks_correct
        percentage = (score * 100 / max_possible) if max_possible > 0 else 0

        # Answer stats
        answers = StudentAnswer.query.filter_by(quiz_id=quiz_id, student_id=student_id).all()
        correct_count = sum(1 for ans in answers if ans.is_correct is True)
        incorrect_count = sum(1 for ans in answers if ans.is_correct is False)
        answered_count = len(answers)
        unanswered = total - answered_count

        grade = (
            'A' if percentage >= 90 else
            'B' if percentage >= 75 else
            'C' if percentage >= 60 else
            'D' if percentage >= 40 else
            'F'
        )

        chart_data.append({
            "student_id": student_id,  # ✅ This is the missing key
            "username": r.username,
            "score": score,
            "correct": correct_count,
            "incorrect": incorrect_count,
            "unanswered": unanswered,
            "percentage": percentage,
            "total_questions": total,
            "submitted_at": r.submitted_at.strftime("%Y-%m-%d %H:%M"),
            "grade": grade
        })

    # Per-question stats
    question_stats = []
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    total_students = db.session.query(Result).filter_by(quiz_id=quiz_id).count()

    for q in questions:
        answers = StudentAnswer.query.filter_by(quiz_id=quiz_id, question_id=q.id).all()
        correct = sum(1 for a in answers if a.is_correct is True)
        incorrect = sum(1 for a in answers if a.is_correct is False)
        answered_students = {a.student_id for a in answers}
        unanswered = total_students - len(answered_students)

        question_stats.append({
            'id': q.id,
            'text': q.text,
            'correct': correct,
            'incorrect': incorrect,
            'unanswered': unanswered
        })

    return render_template(
        'view_quiz_results.html',
        quiz=quiz,
        results=results,
        chart_data=chart_data,
        question_stats=question_stats
    )




# -- Student Routes --
@app.route('/student/dashboard')
@student_required
def student_dashboard():
    user_id = session.get('user_id')
    active_session = QuizSession.query.filter_by(student_id=user_id, submitted=False).first()
    if active_session:
        flash("You have an ongoing quiz. Complete it before accessing the dashboard.", "warning")
        return redirect(url_for('take_quiz', quiz_id=active_session.quiz_id))

    
    # Get all quizzes and mark which ones the student has taken
    quizzes = Quiz.query.order_by(Quiz.created_at.desc()).all()
    results = Result.query.filter_by(student_id=user_id).all()

    # Set of quiz IDs already taken by the student
    taken_quiz_ids = set(r.quiz_id for r in results)

    return render_template(
        'student_dashboard.html',
        quizzes=quizzes,
        results=results,
        taken_quiz_ids=taken_quiz_ids
    )



@app.route('/professor/quiz/<int:quiz_id>/reset/<string:student_username>', methods=['POST'])
@professor_required
def reset_student_quiz(quiz_id, student_username):
    student = User.query.filter_by(username=student_username).first()
    if not student:
        flash("❌ Student not found.", "danger")
        return redirect(url_for('view_quiz_results', quiz_id=quiz_id))

    try:
        # Delete result
        Result.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete()

        # Delete all student answers
        StudentAnswer.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete()

        # Delete quiz session
        QuizSession.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete()

        db.session.commit()
        flash(f"✅ Quiz reset successfully for {student_username}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error resetting quiz for {student_username}: {str(e)}", "danger")

    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))





@app.route('/professor/quiz/<int:quiz_id>/reset_all', methods=['POST'])
@professor_required
def reset_all_students(quiz_id):
    try:
        # Delete all results for the quiz
        Result.query.filter_by(quiz_id=quiz_id).delete()

        # Delete all answers for the quiz
        StudentAnswer.query.filter_by(quiz_id=quiz_id).delete()

        # Delete all quiz sessions for the quiz
        QuizSession.query.filter_by(quiz_id=quiz_id).delete()

        db.session.commit()
        flash("✅ All student attempts have been fully reset.", "success")

    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))
@app.route('/student/quiz/<int:quiz_id>/enter_code', methods=['GET', 'POST'])
@student_required
def enter_quiz_code(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if request.method == 'POST':
        entered_code = request.form.get('access_code', '').strip()
        if quiz.access_code and entered_code == quiz.access_code:
            # Mark code as passed in session and redirect to quiz
            session[f'quiz_code_passed_{quiz_id}'] = True
            return redirect(url_for('take_quiz', quiz_id=quiz_id))
        else:
            flash("Incorrect access code.", "danger")

    return render_template("enter_quiz_code.html", quiz=quiz)



@app.route('/student/quiz/<int:quiz_id>/take', methods=['GET', 'POST'])
@student_required
def take_quiz(quiz_id):
    user_id = session.get("user_id")
    quiz = Quiz.query.get_or_404(quiz_id)

    # Block if already submitted
    result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if result:
        flash("You have already taken this quiz.", "warning")
        return redirect(url_for("student_dashboard"))

    # Deadline check
    if quiz.deadline and datetime.utcnow() > quiz.deadline:
        flash("The quiz deadline has passed.", "danger")
        return redirect(url_for("student_dashboard"))

    all_questions = quiz.questions
    total_questions = len(all_questions)

    # Get/Create QuizSession
    quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if not quiz_session:
        quiz_session = QuizSession(
            student_id=user_id,
            quiz_id=quiz_id,
            start_time=datetime.utcnow(),
            saved_answers={},
            submitted=False,
            quiz_last_updated=quiz.last_updated,
            question_last_seen={str(q.id): q.last_updated.isoformat() if q.last_updated else datetime.utcnow().isoformat() for q in quiz.questions}
        )
        db.session.add(quiz_session)
        db.session.commit()


    # Prevent retake
    if quiz_session.submitted:
        flash("You have already submitted this quiz.", "warning")
        return redirect(url_for("student_dashboard"))

    # Remaining time logic
    elapsed = (datetime.utcnow() - quiz_session.start_time).total_seconds()
    remaining_seconds = max(0, int((quiz.time_limit * 60) - elapsed)) if quiz.time_limit else None

    # Auto-submit if time over
    if remaining_seconds == 0:
        submitted_answers = quiz_session.saved_answers or {}
        score = 0

        for q in all_questions:
            selected = submitted_answers.get(str(q.id))
            if selected:
                is_correct = selected.lower() == q.correct_option.lower()
                db.session.add(StudentAnswer(
                    student_id=user_id,
                    quiz_id=quiz_id,
                    question_id=q.id,
                    selected_option=selected.lower(),
                    is_correct=is_correct
                ))
                score += quiz.marks_correct if is_correct else quiz.marks_incorrect

        result = Result(
            student_id=user_id,
            quiz_id=quiz_id,
            score=score,
            total_questions=total_questions,
            submitted_at=datetime.utcnow()
        )
        db.session.add(result)
        quiz_session.submitted = True
        quiz_session.submitted_at = datetime.utcnow()
        db.session.commit()

        flash("Time is up! Your quiz was auto-submitted.", "info")
        return redirect(url_for("student_quiz_report", quiz_id=quiz_id))

    # Get or initialize question order
    if not quiz_session.shuffled_question_ids:
        # First time taking the quiz - shuffle and save the order
        question_ids = [q.id for q in random.sample(all_questions, total_questions)]
        quiz_session.shuffled_question_ids = ",".join(map(str, question_ids))
        db.session.commit()
    else:
        # Load existing question order
        question_ids = [int(qid) for qid in quiz_session.shuffled_question_ids.split(",") if qid]
    
    # Get questions in the saved order
    questions = [Question.query.get(qid) for qid in question_ids]
    
    # Ensure we have all questions (in case of quiz modifications)
    existing_question_ids = {q.id for q in all_questions}
    questions = [q for q in questions if q and q.id in existing_question_ids]
    
    # Add any new questions that weren't in the original order
    existing_ids_in_questions = {q.id for q in questions if q}
    new_questions = [q for q in all_questions if q.id not in existing_ids_in_questions]
    questions.extend(new_questions)

    if request.method == "POST":
        submitted_answers = {}
        score = 0

        for q in questions:
            selected = request.form.get(f"q_{q.id}") or quiz_session.saved_answers.get(str(q.id))
            submitted_answers[str(q.id)] = selected

            if selected:
                is_correct = selected.lower() == q.correct_option.lower()
                db.session.add(StudentAnswer(
                    student_id=user_id,
                    quiz_id=quiz_id,
                    question_id=q.id,
                    selected_option=selected.lower(),
                    is_correct=is_correct
                ))
                score += quiz.marks_correct if is_correct else quiz.marks_incorrect

        result = Result(
            student_id=user_id,
            quiz_id=quiz_id,
            score=score,
            total_questions=total_questions,
            submitted_at=datetime.utcnow(),
        )
        db.session.add(result)

        quiz_session.submitted = True
        quiz_session.submitted_at = datetime.utcnow()
        quiz_session.saved_answers = submitted_answers
        quiz_session.last_saved = datetime.utcnow()

        db.session.commit()

        flash("Quiz submitted successfully!", "success")
        return redirect(url_for("quiz_results", quiz_id=quiz_id))

    # Option map for rendering
    option_map = {
        q.id: {
            'a': q.option_a,
            'b': q.option_b,
            'c': q.option_c,
            'd': q.option_d
        } for q in questions
    }

    # ✅ Update seen timestamps to prevent reload loop
    for q in questions:
        quiz_session.question_last_seen[str(q.id)] = q.last_updated.isoformat() if q.last_updated else datetime.utcnow().isoformat()

    quiz_session.quiz_last_updated = quiz.last_updated
    db.session.commit()

    return render_template(
        "take_quiz.html",
        quiz=quiz,
        questions=questions,
        remaining_seconds=remaining_seconds,
        saved_answers=quiz_session.saved_answers,
        option_map=option_map
    )


# @app.route('/student/quiz/<int:quiz_id>/take', methods=['GET', 'POST'])
# @student_required
# def take_quiz(quiz_id):
#     user_id = session.get("user_id")
#     quiz = Quiz.query.get_or_404(quiz_id)

#     # Block if already submitted
#     result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
#     if result:
#         flash("You have already taken this quiz.", "warning")
#         return redirect(url_for("student_dashboard"))

#     # Deadline check
#     if quiz.deadline and datetime.utcnow() > quiz.deadline:
#         flash("The quiz deadline has passed.", "danger")
#         return redirect(url_for("student_dashboard"))

#     all_questions = quiz.questions
#     total_questions = len(all_questions)

#     # Get/Create QuizSession
#     quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
#     if not quiz_session:
#         shuffled_ids = [q.id for q in random.sample(all_questions, total_questions)]
#         quiz_session = QuizSession(
#             student_id=user_id,
#             quiz_id=quiz_id,
#             start_time=datetime.utcnow(),
#             saved_answers={},
#             submitted=False,
#             quiz_last_updated=quiz.last_updated,
#             question_last_seen={str(q.id): q.last_updated.isoformat() if q.last_updated else datetime.utcnow().isoformat() for q in all_questions},
#             shuffled_question_ids=",".join(map(str, shuffled_ids))  # Convert list to comma-separated string

#         )

        
#         db.session.add(quiz_session)
#         db.session.commit()

#     # Prevent retake
#     if quiz_session.submitted:
#         flash("You have already submitted this quiz.", "warning")
#         return redirect(url_for("student_dashboard"))

#     # Remaining time logic
#     elapsed = (datetime.utcnow() - quiz_session.start_time).total_seconds()
#     remaining_seconds = max(0, int((quiz.time_limit * 60) - elapsed)) if quiz.time_limit else None

#     # Auto-submit if time over
#     if remaining_seconds == 0:
#         submitted_answers = quiz_session.saved_answers or {}
#         score = 0

#         for q in all_questions:
#             selected = submitted_answers.get(str(q.id))
#             if selected:
#                 is_correct = selected.lower() == q.correct_option.lower()
#                 db.session.add(StudentAnswer(
#                     student_id=user_id,
#                     quiz_id=quiz_id,
#                     question_id=q.id,
#                     selected_option=selected.lower(),
#                     is_correct=is_correct
#                 ))
#                 score += quiz.marks_correct if is_correct else quiz.marks_incorrect

#         result = Result(
#             student_id=user_id,
#             quiz_id=quiz_id,
#             score=score,
#             total_questions=total_questions,
#             submitted_at=datetime.utcnow()
#         )
#         db.session.add(result)
#         quiz_session.submitted = True
#         quiz_session.submitted_at = datetime.utcnow()
#         db.session.commit()

#         flash("Time is up! Your quiz was auto-submitted.", "info")
#         return redirect(url_for("student_quiz_report", quiz_id=quiz_id))

#     # Use shuffled order stored in session
#     question_ids = quiz_session.shuffled_question_ids or [q.id for q in all_questions]
#     question_ids = [qid for qid in question_ids if Question.query.get(qid)]

#     questions = [Question.query.get(qid) for qid in question_ids if Question.query.get(qid)]

#     if request.method == "POST":
#         submitted_answers = {}
#         score = 0

#         for q in questions:
#             selected = request.form.get(f"q_{q.id}") or quiz_session.saved_answers.get(str(q.id))
#             submitted_answers[str(q.id)] = selected

#             if selected:
#                 is_correct = selected.lower() == q.correct_option.lower()
#                 db.session.add(StudentAnswer(
#                     student_id=user_id,
#                     quiz_id=quiz_id,
#                     question_id=q.id,
#                     selected_option=selected.lower(),
#                     is_correct=is_correct
#                 ))
#                 score += quiz.marks_correct if is_correct else quiz.marks_incorrect

#         result = Result(
#             student_id=user_id,
#             quiz_id=quiz_id,
#             score=score,
#             total_questions=total_questions,
#             submitted_at=datetime.utcnow(),
#         )
#         db.session.add(result)

#         quiz_session.submitted = True
#         quiz_session.submitted_at = datetime.utcnow()
#         quiz_session.saved_answers = submitted_answers
#         quiz_session.last_saved = datetime.utcnow()

#         db.session.commit()

#         return redirect(url_for("student_quiz_report", quiz_id=quiz_id))

#     # Option map for rendering
#     option_map = {
#         q.id: {
#             'a': q.option_a,
#             'b': q.option_b,
#             'c': q.option_c,
#             'd': q.option_d
#         } for q in questions
#     }

#     # ✅ Track what version of the quiz the student is seeing
#     quiz_session.quiz_last_updated = quiz.last_updated
#     db.session.commit()

#     return render_template(
#         "take_quiz.html",
#         quiz=quiz,
#         questions=questions,
#         remaining_seconds=remaining_seconds,
#         saved_answers=quiz_session.saved_answers,
#         option_map=option_map
#     )



def reconcile_session_with_current_questions(quiz_id):
    """Ensure session['question_order'] and saved_answers remain valid after quiz is edited."""
    q_order_key = f"question_order_{quiz_id}"
    saved_answers_key = f"saved_answers_{quiz_id}"

    current_q_ids = {q.id for q in Question.query.filter_by(quiz_id=quiz_id).all()}

    # Reconcile question order
    session_order = session.get(q_order_key, [])
    filtered_order = [qid for qid in session_order if qid in current_q_ids]
    session[q_order_key] = filtered_order

    # Reconcile saved answers
    saved = session.get(saved_answers_key, {})
    filtered_answers = {qid: ans for qid, ans in saved.items() if int(qid) in current_q_ids}
    session[saved_answers_key] = filtered_answers

    session.modified = True



@app.route("/quiz/<int:quiz_id>/auto_submit")
@student_required
def auto_submit_quiz(quiz_id):
    user_id = session.get("user_id")
    quiz = Quiz.query.get_or_404(quiz_id)
    session_obj = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if not session_obj or session_obj.submitted:
        return redirect(url_for("student_dashboard"))

    saved = session_obj.saved_answers or {}
    correct = 0
    for q in quiz.questions:
        sel = saved.get(str(q.id))
        if sel:
            is_correct = sel.lower() == q.correct_option.lower()
            answer = StudentAnswer(student_id=user_id, quiz_id=quiz_id,
                                   question_id=q.id, selected_option=sel.lower(),
                                   is_correct=is_correct)
            db.session.add(answer)
            if is_correct:
                correct += 1

    marks_correct = quiz.marks_correct or 1
    marks_incorrect = quiz.marks_incorrect or 0
    score = 0
    for q in quiz.questions:
        sel = saved.get(str(q.id))
        if sel:
            score += marks_correct if sel.lower() == q.correct_option.lower() else marks_incorrect

    result = Result(student_id=user_id, quiz_id=quiz_id, score=score,
                    total_questions=len(quiz.questions), submitted_at=datetime.utcnow())
    session_obj.submitted = True
    session_obj.submitted_at = datetime.utcnow()

    db.session.add(result)
    db.session.commit()

    flash("Time is up! Your quiz was auto-submitted.", "info")
    return redirect(url_for("student_quiz_report", quiz_id=quiz_id))

@app.route("/quiz/<int:quiz_id>/autosave", methods=["POST"])
@student_required
def autosave(quiz_id):
    user_id = session.get("user_id")
    data = request.get_json()
    question_id = str(data.get("question_id"))
    selected_option = data.get("selected_option")

    session_obj = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if session_obj and not session_obj.submitted:
        session_obj.saved_answers[question_id] = selected_option
        session_obj.last_saved = datetime.utcnow()
        db.session.commit()
        return jsonify({"status": "saved"})
    return jsonify({"status": "failed"}), 400



@app.route('/quiz_results/<int:quiz_id>')
@login_required
def quiz_results(quiz_id):
    user_id = session.get('user_id')
    quiz = Quiz.query.get_or_404(quiz_id)
    result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first_or_404()

    return render_template("quiz_results.html", quiz=quiz, result=result)



@app.route('/student/quiz/<int:quiz_id>/report')
@student_required
def student_quiz_report(quiz_id):
    print("✅ student_quiz_report ROUTE HIT")
    user_id = session.get('user_id')
    quiz = Quiz.query.get_or_404(quiz_id)

    if not quiz.report_released:
        flash("Report not yet released by professor.", "warning")
        return redirect(url_for('student_dashboard'))

    result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first_or_404()
    questions = Question.query.filter_by(quiz_id=quiz_id).all()
    answers = StudentAnswer.query.filter_by(student_id=user_id, quiz_id=quiz_id).all()
    answer_map = {a.question_id: a.selected_option for a in answers}

    report = []
    for q in questions:
        report.append({
            "text": q.text,
            "image": q.image,
            "options": [q.option_a, q.option_b, q.option_c, q.option_d],
            "correct": q.correct_option.lower(),
            "selected": answer_map.get(q.id, None)
        })
    print("Checking if report released:", quiz.report_released)

    return render_template('student_result_report.html', quiz=quiz, result=result, report=report)



@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    user_id = session.get('user_id')
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = Question.query.filter_by(quiz_id=quiz.id).all()

    correct = 0
    total = len(questions)

    for question in questions:
        # selected_option = request.form.get(str(question.id))  # form key is question ID
        selected_option = request.form.get(f"question_{question.id}") 
        is_correct = selected_option == question.correct_option

        # Save student's answer
        answer = StudentAnswer(
            student_id=user_id,
            quiz_id=quiz.id,
            question_id=question.id,
            selected_option=selected_option,
            is_correct=is_correct
        )
        db.session.add(answer)

        if is_correct:
            correct += 1

    # Save overall result
    result = Result(
        student_id=user_id,
        quiz_id=quiz.id,
        score=correct,
        total_questions=total
    )
    db.session.add(result)
    db.session.commit()

    return redirect(url_for('student_dashboard'))




# @app.route('/save_answer', methods=['POST'])
# @student_required
# def save_answer():
#     data = request.get_json()
#     user_id = session.get("user_id")
#     quiz_id = data.get('quiz_id')
#     question_id = str(data.get('question_id'))
#     selected_option = data.get('selected_option')

#     # Save to Flask session (fallback, not used for final grading)
#     session_key = f'saved_answers_{quiz_id}'
#     session_answers = session.get(session_key, {})
#     session_answers[question_id] = selected_option
#     session[session_key] = session_answers
#     session.modified = True

#     # Save to QuizSession.saved_answers (this is used during auto-submit!)
#     quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
#     if quiz_session:
#         saved = quiz_session.saved_answers or {}
#         saved[question_id] = selected_option
#         quiz_session.saved_answers = saved
#         quiz_session.last_saved = datetime.utcnow()

#     # Save to StudentAnswer table (for preview / optional analytics)
#     answer = StudentAnswer.query.filter_by(
#         student_id=user_id,
#         quiz_id=quiz_id,
#         question_id=question_id
#     ).first()

#     if answer:
#         answer.selected_option = selected_option
#         answer.is_correct = (selected_option.lower() ==
#                              Question.query.get(int(question_id)).correct_option.lower())
#     else:
#         question = Question.query.get(int(question_id))
#         is_correct = selected_option.lower() == question.correct_option.lower()
#         answer = StudentAnswer(
#             student_id=user_id,
#             quiz_id=quiz_id,
#             question_id=question_id,
#             selected_option=selected_option,
#             is_correct=is_correct
#         )
#         db.session.add(answer)

#     # ✅ THIS WAS MISSING:
@app.route('/save_answer', methods=['POST'])
@student_required
def save_answer():
    try:
        data = request.get_json()
        user_id = session.get("user_id")
        quiz_id = data.get('quiz_id')
        question_id = str(data.get('question_id'))
        selected_option = data.get('selected_option')

        # Normalize selected_option (e.g., null → None)
        if not selected_option:
            selected_option = None

        # Save to Flask session (optional)
        session_key = f'saved_answers_{quiz_id}'
        session_answers = session.get(session_key, {})
        if selected_option is not None:
            session_answers[question_id] = selected_option
        elif question_id in session_answers:
            del session_answers[question_id]  # unselected
        session[session_key] = session_answers
        session.modified = True

        # Save to QuizSession
        quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
        if quiz_session:
            saved = quiz_session.saved_answers or {}
            if selected_option is not None:
                saved[question_id] = selected_option
            elif question_id in saved:
                del saved[question_id]
            quiz_session.saved_answers = saved
            quiz_session.last_saved = datetime.utcnow()

        # Save to StudentAnswer table
        answer = StudentAnswer.query.filter_by(
            student_id=user_id,
            quiz_id=quiz_id,
            question_id=question_id
        ).first()

        question = Question.query.get(int(question_id))
        if not question:
            return jsonify({'success': False, 'error': 'Question not found'}), 404

        if answer:
            if selected_option:
                answer.selected_option = selected_option
                answer.is_correct = (selected_option.lower() == question.correct_option.lower())
            else:
                answer.selected_option = None
                answer.is_correct = False  # Skipped
        else:
            if selected_option:
                is_correct = selected_option.lower() == question.correct_option.lower()
                answer = StudentAnswer(
                    student_id=user_id,
                    quiz_id=quiz_id,
                    question_id=question_id,
                    selected_option=selected_option,
                    is_correct=is_correct
                )
                db.session.add(answer)
            # else: do not create an answer row for skipped

        db.session.commit()
        
        # Return success response
        return jsonify({
            'success': True,
            'question_id': question_id,
            'selected_option': selected_option
        })
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving answer: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'An error occurred while saving your answer'
        }), 500

@app.route('/professor/analytics/data')
@professor_required
def get_quiz_analytics():
    quizzes = Quiz.query.filter_by(professor_id=session['user_id']).all()
    analytics = []

    for quiz in quizzes:
        results = Result.query.filter_by(quiz_id=quiz.id).all()
        scores = [r.score for r in results]
        attempts = len(results)
        average_score = round(sum(scores) / attempts, 2) if attempts else 0

        analytics.append({
            'quiz_title': quiz.title,
            'attempts': attempts,
            'average_score': average_score
        })

    return jsonify(analytics)


# --- Error Handlers (Optional but Recommended) ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404 # Create a templates/404.html

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback() # Rollback session in case of DB error
    return render_template('500.html'), 500 # Create a templates/500.html

@app.template_filter('chr')
def chr_filter(value):
    return chr(value)



# --- Main Execution ---
if __name__ == '__main__':
    # Consider using waitress or gunicorn for production instead of app.run
    app.run(debug=True , port=5100) # Enable debug mode for development (auto-reloads, shows errors)
