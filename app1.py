import csv
import io
import json
import os
import random
import re
import traceback
import uuid
from datetime import datetime
from functools import wraps
from io import StringIO

import google.generativeai as genai
from flask import (
    Flask,
    abort,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_migrate import Migrate
from werkzeug.utils import secure_filename

from api_utils import generate_quiz_questions
from config import Config
from models import (
    SECURITY_QUESTIONS,
    Question,
    Quiz,
    QuizSession,
    RegradeLog,
    Result,
    StudentAnswer,
    User,
    db,
)

try:  # PDF export is optional; the rest of the app keeps working without it.
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on deployment environment
    canvas = None
    REPORTLAB_AVAILABLE = False

# If using Flask-Login:
# from flask_login import LoginManager, login_user, logout_user, current_user, login_required

# --- App Initialization ---
app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)

# Configure Gemini API only when a key is actually configured.
if app.config.get('GEMINI_API_KEY'):
    try:
        genai.configure(api_key=app.config['GEMINI_API_KEY'])
    except Exception as e:  # pragma: no cover - network/provider specific
        print(f"Error configuring Gemini API: {e}")

# Make sure the upload directory exists. On Vercel this points at /tmp.
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except OSError as e:  # pragma: no cover - read-only filesystem edge case
    print(f"Could not create upload folder: {e}")

# --- Database Setup ---
with app.app_context():
    try:
        db.create_all()
        print("Database tables created (if they didn't exist).")
    except Exception as e:  # pragma: no cover - deployment/permission specific
        print(f"Error creating database tables: {e}")
        traceback.print_exc()


# --- Small helpers ---
USERNAME_RE = re.compile(r'^[A-Za-z0-9._-]{3,30}$')
PASSWORD_RE = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$'
)


def user_utils_valid_username(username):
    return bool(username and USERNAME_RE.match(username))


def user_utils_valid_password(password):
    return bool(password and PASSWORD_RE.match(password))


def _owned_quiz_or_404(quiz_id):
    """Return the quiz only when it belongs to the logged-in professor."""
    quiz = Quiz.query.get_or_404(quiz_id)
    if quiz.professor_id != session.get('user_id'):
        abort(403)
    return quiz


def _marks_scheme(quiz):
    correct = quiz.marks_correct if quiz.marks_correct is not None else 1.0
    incorrect = quiz.marks_incorrect if quiz.marks_incorrect is not None else 0.0
    return correct, incorrect


def _session_answers(quiz_session):
    """Older rows may have NULL JSON columns; always work with a dict."""
    return dict(quiz_session.saved_answers or {})


def _save_upload(file_storage):
    """Save an uploaded image and return its stored filename."""
    if not file_storage or not file_storage.filename:
        return None
    filename = secure_filename(file_storage.filename)
    if not filename:
        raise ValueError('Invalid file name.')
    # Avoid collisions between professors uploading files with the same name.
    filename = f"{uuid.uuid4().hex[:10]}_{filename}"
    folder = app.config['UPLOAD_FOLDER']
    os.makedirs(folder, exist_ok=True)
    file_storage.save(os.path.join(folder, filename))
    return filename


def _finalize_attempt(student_id, quiz, quiz_session, selected_answers):
    """Grade a submission and persist exactly one answer row per question.

    Autosave/save_answer already write ``StudentAnswer`` rows while the student
    is taking the quiz. Re-inserting them at submit time previously created
    duplicate rows and corrupted the analytics, so we replace them here.
    """
    selected_answers = {
        str(qid): str(opt).lower()
        for qid, opt in (selected_answers or {}).items()
        if opt is not None and str(opt).lower() in ('a', 'b', 'c', 'd')
    }

    StudentAnswer.query.filter_by(
        student_id=student_id, quiz_id=quiz.id
    ).delete(synchronize_session=False)

    marks_correct, marks_incorrect = _marks_scheme(quiz)
    score = 0.0
    questions = list(quiz.questions)

    for question in questions:
        selected = selected_answers.get(str(question.id))
        if not selected:
            continue
        is_correct = bool(
            question.correct_option
            and selected == str(question.correct_option).lower()
        )
        db.session.add(
            StudentAnswer(
                student_id=student_id,
                quiz_id=quiz.id,
                question_id=question.id,
                selected_option=selected,
                is_correct=is_correct,
            )
        )
        score += marks_correct if is_correct else marks_incorrect

    total_questions = len(questions)
    result = Result.query.filter_by(student_id=student_id, quiz_id=quiz.id).first()
    if result is None:
        result = Result(student_id=student_id, quiz_id=quiz.id)
        db.session.add(result)

    result.score = round(score, 2)
    result.total_questions = total_questions
    result.submitted_at = datetime.utcnow()

    quiz_session.submitted = True
    quiz_session.submitted_at = datetime.utcnow()
    quiz_session.saved_answers = selected_answers
    quiz_session.last_saved = datetime.utcnow()

    db.session.commit()
    return result


# --- Decorators for Role-Based Access Control ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))

        # The account may have been deleted while the session was still alive.
        if db.session.get(User, user_id) is None:
            session.clear()
            flash('Your account is no longer available. Please log in again.', 'warning')
            return redirect(url_for('login'))

        return f(*args, **kwargs)

    return decorated_function


def professor_required(f):
    @login_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'professor':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


def student_required(f):
    @login_required
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'student':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


# --- Routes ---

@app.route('/home')
def home():
    if 'user_id' in session:
        if session.get('user_role') == 'professor':
            return redirect(url_for('professor_dashboard'))
        else:
            return redirect(url_for('student_dashboard'))
    return render_template('home.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    if request.method == 'POST':
        name = (request.form.get('name') or '').strip()
        email = (request.form.get('email') or '').strip()
        feedback = (request.form.get('feedback') or '').strip()

        if not name or not email or not feedback:
            flash('Please fill in all feedback fields.', 'danger')
            return redirect(url_for('about'))

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"""[{timestamp}] Feedback from: {name} ({email})
{feedback}
-------------------------------------\n"""

        # Serverless filesystems are read-only; never let feedback logging
        # break the page.
        try:
            with open(os.path.join(app.root_path, 'feedback.log'), 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except OSError:
            print(log_entry)

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('about'))

    return render_template('about.html')

@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('user_role') == 'professor':
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
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''
        role = request.form.get('role')
        security_question = request.form.get('security_question')
        security_answer = (request.form.get('security_answer') or '').strip()

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
        if not user_utils_valid_username(username):
            flash('Username must be 3-30 characters and contain only letters, numbers, dots, dashes or underscores.', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))
        if not user_utils_valid_password(password):
            flash(
                'Password must be at least 8 characters long and include uppercase, '
                'lowercase, number, and special character.',
                'danger',
            )
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
            security_question=security_question,
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
            flash('An error occurred during registration. Please try a different username or email.', 'danger')
            print(f"Registration Error: {e}")
            traceback.print_exc()
            return redirect(url_for('register'))

    # For GET request, pass security questions to the template
    return render_template('register.html', security_questions=SECURITY_QUESTIONS)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if 'user_id' in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        security_answer = (request.form.get('security_answer') or '').strip()
        new_password = request.form.get('new_password') or ''
        confirm_password = request.form.get('confirm_password') or ''
        
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
                if not user_utils_valid_password(new_password):
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
            # Start a clean session on login to avoid carrying over stale state.
            session.clear()
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
                topic = (request.form.get('topic') or '').strip()
                num_questions = int(request.form.get('num_questions', 10))
                difficulty = request.form.get('difficulty', 'medium')
                if not topic:
                    flash('Please enter a topic for the quiz.', 'danger')
                    return redirect(url_for('ai_quiz_generator'))
                num_questions = max(1, min(num_questions, 50))
                if difficulty not in ('easy', 'medium', 'hard', 'mixed'):
                    difficulty = 'medium'

                # Use the new API management system
                questions_list = generate_quiz_questions(topic, num_questions, difficulty=difficulty)

                if not questions_list:
                    flash('No valid questions were generated. Please try again with a different topic.', 'warning')
                    return redirect(url_for('ai_quiz_generator'))

                return render_template('ai_quiz_generator.html', questions=questions_list, topic=topic)

            except Exception as e:
                flash(f'An error occurred while generating questions: {str(e)}', 'danger')
                print(f"AI Generation Error: {e}")
                traceback.print_exc()
                return redirect(url_for('ai_quiz_generator'))

        elif action == 'create_quiz':
            try:
                quiz_title = (request.form.get('quiz_title') or '').strip()
                time_limit = request.form.get('time_limit')
                marks_correct = float(request.form.get('marks_correct', 4))
                marks_incorrect = float(request.form.get('marks_incorrect', -1))
                selected_indices = request.form.getlist('selected_questions')

                if not quiz_title:
                    flash('Quiz title is required.', 'danger')
                    return redirect(url_for('ai_quiz_generator'))
                if not selected_indices:
                    flash('You must select at least one question to create a quiz.', 'warning')
                    return redirect(url_for('ai_quiz_generator'))

                time_limit_value = int(time_limit) if time_limit and str(time_limit).isdigit() else None
                if time_limit_value is not None and time_limit_value < 1:
                    time_limit_value = None
                if marks_correct <= 0:
                    flash('Marks for a correct answer must be greater than zero.', 'danger')
                    return redirect(url_for('ai_quiz_generator'))

                access_code = (request.form.get('access_code') or '').strip() or None
                new_quiz = Quiz(
                    title=quiz_title,
                    time_limit=time_limit_value,
                    professor_id=session['user_id'],
                    access_code=access_code,
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
                            if not isinstance(options, list):
                                continue
                            options = [str(o).strip() for o in options if str(o).strip()]

                            # Ensure we have exactly 4 options
                            while len(options) < 4:
                                options.append("No option")
                            options = options[:4]

                            # Find the correct option index ('a', 'b', 'c', 'd')
                            correct_option_text = str(question_data.get('correct_answer') or '').strip()
                            correct_option_char = None
                            for i, option_text in enumerate(options):
                                if option_text.strip().lower() == correct_option_text.lower():
                                    correct_option_char = chr(ord('a') + i)
                                    break
                            if correct_option_char is None:
                                # Never silently mark a random option as correct.
                                continue

                            new_question = Question(
                                quiz_id=new_quiz.id,
                                text=question_data.get('question_text'),
                                option_a=options[0],
                                option_b=options[1],
                                option_c=options[2],
                                option_d=options[3],
                                correct_option=correct_option_char
                            )
                            db.session.add(new_question)
                            questions_added += 1
                        except (json.JSONDecodeError, TypeError, ValueError) as e:
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
    quiz = _owned_quiz_or_404(quiz_id)
    user = User.query.filter_by(username=username).first_or_404()
    result = Result.query.filter_by(quiz_id=quiz.id, student_id=user.id).first()

    if not result:
        flash("No result found for this student.", "warning")
        return redirect(url_for('view_quiz_results', quiz_id=quiz.id))

    if not REPORTLAB_AVAILABLE:
        flash("PDF export is unavailable because ReportLab is not installed.", "danger")
        return redirect(url_for('view_quiz_results', quiz_id=quiz.id))

    marks_correct, _ = _marks_scheme(quiz)
    max_marks = (result.total_questions or 0) * marks_correct
    percentage = (result.score * 100 / max_marks) if max_marks > 0 else 0

    answers = StudentAnswer.query.filter_by(
        quiz_id=quiz.id, student_id=user.id
    ).all()
    correct_count = sum(1 for a in answers if a.is_correct is True)
    incorrect_count = sum(1 for a in answers if a.is_correct is False)
    unanswered = max(0, (result.total_questions or 0) - len(answers))

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)

    def safe(text):
        """Helvetica cannot render arbitrary Unicode; replace instead of crashing."""
        return str(text).encode('latin-1', 'replace').decode('latin-1')

    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 800, "Quiz Result Report")
    p.setFont("Helvetica", 12)
    p.drawString(100, 770, safe(f"Quiz Title: {quiz.title}"))
    p.drawString(100, 750, safe(f"Student: {user.username}"))
    p.drawString(100, 730, safe(f"Score: {result.score}/{max_marks}"))
    p.drawString(100, 710, f"Correct: {correct_count}")
    p.drawString(100, 690, f"Incorrect: {incorrect_count}")
    p.drawString(100, 670, f"Unanswered: {unanswered}")
    p.drawString(100, 650, f"Percentage: {percentage:.2f}%")
    submitted = result.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if result.submitted_at else 'N/A'
    p.drawString(100, 630, f"Submitted At: {submitted}")

    p.showPage()
    p.save()
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers['Content-Type'] = 'application/pdf'
    safe_name = secure_filename(user.username) or 'student'
    response.headers['Content-Disposition'] = (
        f'attachment; filename={safe_name}_quiz_{quiz.id}_result.pdf'
    )
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


@app.route('/professor/quiz/<int:quiz_id>/update_access_code', methods=['POST'])
@professor_required
def update_access_code(quiz_id):
    data = request.get_json(silent=True) or {}
    new_code = (data.get('access_code') or '').strip()[:50] or None
    quiz = Quiz.query.filter_by(id=quiz_id, professor_id=session['user_id']).first_or_404()
    quiz.access_code = new_code
    db.session.commit()
    return jsonify({'success': True, 'access_code': new_code})


@app.route('/student/quiz/<int:quiz_id>/access', methods=['GET', 'POST'])
@student_required
def access_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)

    if quiz.access_code:
        if request.method == 'POST':
            entered_code = (request.form.get('access_code') or '').strip()
            if entered_code == quiz.access_code:
                session[f'quiz_code_passed_{quiz_id}'] = True
                return redirect(url_for('take_quiz', quiz_id=quiz_id))
            flash("Incorrect access code.", "danger")
        return render_template('enter_quiz_code.html', quiz=quiz)

    return redirect(url_for('take_quiz', quiz_id=quiz_id))


@app.route('/professor/quiz/<int:quiz_id>/export')
@professor_required
def export_quiz_results(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)

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

    marks_correct, _ = _marks_scheme(quiz)
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['Student Name', 'Score', 'Total Questions', 'Percentage', 'Submitted At'])

    for username, score, total, submitted_at in results:
        max_marks = (total or 0) * marks_correct
        percentage = round((score / max_marks) * 100, 1) if max_marks > 0 else 0
        submitted = submitted_at.strftime('%Y-%m-%d %H:%M') if submitted_at else ''
        writer.writerow([username, score, total, f"{percentage}%", submitted])

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
        title = (request.form.get('quiz_title') or '').strip()
        if not title:
            flash('Quiz title is required.', 'danger')
            return redirect(url_for('create_quiz'))

        try:
            # Parse time limit
            time_limit_raw = request.form.get('time_limit')
            time_limit = int(time_limit_raw) if time_limit_raw and time_limit_raw.isdigit() else None
            if time_limit is not None and time_limit < 1:
                time_limit = None
            deadline = None
            deadline_str = request.form.get('deadline')
            access_code = (request.form.get('access_code') or '').strip()[:50] or None

            # ✅ New: Parse marking scheme
            marks_correct = float(request.form.get('marks_correct', 1.0))
            marks_incorrect = float(request.form.get('marks_incorrect', 0.0))
            if marks_correct <= 0:
                flash('Marks for a correct answer must be greater than zero.', 'danger')
                return redirect(url_for('create_quiz'))

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
                q_text = (request.form.get(f'q{i}_text') or '').strip()
                q_image_file = request.files.get(f'q{i}_image')
                has_image = bool(q_image_file and q_image_file.filename)

                if not q_text and not has_image:
                    break

                image_filename = _save_upload(q_image_file) if has_image else None

                opt_a = (request.form.get(f'q{i}_opt_a') or '').strip()
                opt_b = (request.form.get(f'q{i}_opt_b') or '').strip()
                opt_c = (request.form.get(f'q{i}_opt_c') or '').strip()
                opt_d = (request.form.get(f'q{i}_opt_d') or '').strip()
                correct = (request.form.get(f'q{i}_correct') or '').lower()

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
                    text=q_text or None,
                    image=image_filename,
                    option_a=opt_a,
                    option_b=opt_b,
                    option_c=opt_c,
                    option_d=opt_d,
                    correct_option=correct
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




@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """Serve question images from the writable upload folder.

    Falls back to the historical ``static/uploads`` location so already
    uploaded images keep working after a deployment.
    """
    upload_folder = current_app.config['UPLOAD_FOLDER']
    if os.path.exists(os.path.join(upload_folder, filename)):
        return send_from_directory(upload_folder, filename)
    legacy_folder = os.path.join(current_app.static_folder, 'uploads')
    if os.path.exists(os.path.join(legacy_folder, filename)):
        return send_from_directory(legacy_folder, filename)
    abort(404)


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
    question_indexes = []

    if not session_obj.question_last_seen:
        session_obj.question_last_seen = {}

    for idx, q in enumerate(quiz.questions):
        q_id = str(q.id)
        seen_time = session_obj.question_last_seen.get(q_id)
        if not q.last_updated:
            continue
        try:
            seen_dt = datetime.fromisoformat(seen_time) if seen_time else None
        except (TypeError, ValueError):
            seen_dt = None
        if seen_dt is None or q.last_updated > seen_dt:
            question_changes.append(q_id)
            question_indexes.append(idx + 1)

    if question_changes:
        return jsonify({
            'reload': True,
            'changed_questions': question_changes,
            'changed_indexes': question_indexes,
        })

    return jsonify({'reload': False})


@app.route('/quiz/<int:quiz_id>/mark_seen', methods=["POST"])
@student_required
def mark_seen_questions(quiz_id):
    data = request.get_json(silent=True) or {}
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
    quiz = _owned_quiz_or_404(quiz_id)
    questions = quiz.questions

    if request.method == 'POST':
        try:
            title = (request.form.get('quiz_title') or '').strip()
            if not title:
                flash('Quiz title is required.', 'danger')
                return redirect(request.url)
            quiz.title = title

            time_limit = request.form.get('time_limit')
            quiz.time_limit = int(time_limit) if time_limit and time_limit.isdigit() else None

            # Update access code (empty string means remove access code)
            access_code = (request.form.get('access_code') or '').strip()[:50]
            quiz.access_code = access_code or None

            kept_question_ids = []

            # 1. Update existing questions
            for question in questions:
                q_id = question.id
                if f'q{q_id}_text' not in request.form:
                    # Question was removed from the form; drop it and its answers.
                    StudentAnswer.query.filter_by(question_id=q_id).delete(
                        synchronize_session=False
                    )
                    db.session.delete(question)
                    continue

                question.text = (request.form.get(f'q{q_id}_text') or '').strip() or None
                question.option_a = (request.form.get(f'q{q_id}_opt_a') or '').strip()
                question.option_b = (request.form.get(f'q{q_id}_opt_b') or '').strip()
                question.option_c = (request.form.get(f'q{q_id}_opt_c') or '').strip()
                question.option_d = (request.form.get(f'q{q_id}_opt_d') or '').strip()
                correct_val = (request.form.get(f'q{q_id}_correct') or '').lower()
                question.correct_option = correct_val or None

                image_file = request.files.get(f'q{q_id}_image')
                if image_file and image_file.filename:
                    question.image = _save_upload(image_file)

                if not all([
                    question.option_a,
                    question.option_b,
                    question.option_c,
                    question.option_d,
                    question.correct_option in ('a', 'b', 'c', 'd'),
                ]):
                    db.session.rollback()
                    flash(f"All options and a valid correct answer are required for question ID {q_id}.", 'danger')
                    return redirect(request.url)

                kept_question_ids.append(question.id)

            # 2. Add new questions
            i = 1
            while True:
                new_q_text = (request.form.get(f'new_q{i}_text') or '').strip()
                new_q_image = request.files.get(f'new_q{i}_image')
                has_image = bool(new_q_image and new_q_image.filename)
                if not new_q_text and not has_image:
                    break

                image_filename = _save_upload(new_q_image) if has_image else None

                opt_a = (request.form.get(f'new_q{i}_opt_a') or '').strip()
                opt_b = (request.form.get(f'new_q{i}_opt_b') or '').strip()
                opt_c = (request.form.get(f'new_q{i}_opt_c') or '').strip()
                opt_d = (request.form.get(f'new_q{i}_opt_d') or '').strip()
                correct = (request.form.get(f'new_q{i}_correct') or '').lower()

                if not all([opt_a, opt_b, opt_c, opt_d, correct in ('a', 'b', 'c', 'd')]):
                    db.session.rollback()
                    flash(f"All options and a valid correct answer are required for new question {i}.", 'danger')
                    return redirect(request.url)

                new_question = Question(
                    quiz_id=quiz.id,
                    text=new_q_text or None,
                    image=image_filename,
                    option_a=opt_a,
                    option_b=opt_b,
                    option_c=opt_c,
                    option_d=opt_d,
                    correct_option=correct,
                )
                db.session.add(new_question)
                i += 1

            quiz.last_updated = datetime.utcnow()
            db.session.commit()
            flash('Quiz and questions updated successfully.', 'success')

            # 3. Regrade every answer against the current correct options.
            all_answers = StudentAnswer.query.filter_by(quiz_id=quiz.id).all()
            for ans in all_answers:
                q = db.session.get(Question, ans.question_id)
                if q is None:
                    db.session.delete(ans)
                    continue
                if q.correct_option:
                    ans.is_correct = bool(
                        ans.selected_option
                        and ans.selected_option.lower() == q.correct_option.lower()
                    )

            # 4. Recompute results for every student, including all-skipped ones.
            marks_correct, marks_incorrect = _marks_scheme(quiz)
            results = Result.query.filter_by(quiz_id=quiz.id).all()
            for result in results:
                answers = StudentAnswer.query.filter_by(
                    quiz_id=quiz.id, student_id=result.student_id
                ).all()
                score = 0.0
                for ans in answers:
                    if ans.selected_option:
                        score += marks_correct if ans.is_correct else marks_incorrect
                result.score = round(score, 2)
                result.total_questions = len(quiz.questions)

            db.session.commit()
            flash("All student answers have been regraded.", "info")

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating quiz: {e}', 'danger')
            traceback.print_exc()
            return redirect(request.url)

    return render_template('edit_quiz.html', quiz=quiz, questions=quiz.questions)


@app.route('/professor/quiz/<int:quiz_id>/delete', methods=['POST'])
@professor_required
def delete_quiz(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)

    try:
        # Children first: RegradeLog and StudentAnswer reference both quiz and user.
        RegradeLog.query.filter_by(quiz_id=quiz.id).delete(synchronize_session=False)
        StudentAnswer.query.filter_by(quiz_id=quiz.id).delete(synchronize_session=False)
        QuizSession.query.filter_by(quiz_id=quiz.id).delete(synchronize_session=False)
        Result.query.filter_by(quiz_id=quiz.id).delete(synchronize_session=False)
        Question.query.filter_by(quiz_id=quiz.id).delete(synchronize_session=False)
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
        StudentAnswer.query.filter_by(question_id=question.id).delete(
            synchronize_session=False
        )
        db.session.delete(question)
        db.session.commit()
        flash("Question deleted successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error deleting question: {e}", "danger")

    return redirect(url_for('edit_quiz', quiz_id=quiz.id))


@app.route('/professor/quiz/<int:quiz_id>/regrade', methods=['POST'])
@professor_required
def regrade_quiz(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)
    results = Result.query.filter_by(quiz_id=quiz_id).all()
    professor_id = session['user_id']
    marks_correct, marks_incorrect = _marks_scheme(quiz)

    for result in results:
        student_id = result.student_id
        answers = StudentAnswer.query.filter_by(quiz_id=quiz_id, student_id=student_id).all()
        new_score = 0.0
        for ans in answers:
            if not ans.selected_option:
                continue
            new_score += marks_correct if ans.is_correct else marks_incorrect
        new_score = round(new_score, 2)

        if result.score != new_score:
            db.session.add(RegradeLog(
                quiz_id=quiz_id,
                student_id=student_id,
                old_score=result.score,
                new_score=new_score,
                regraded_by=professor_id
            ))

        result.score = new_score
        result.total_questions = len(quiz.questions)

    db.session.commit()
    flash('Regrading and logging completed.', 'success')
    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))

@app.route('/professor/quiz/<int:quiz_id>/regrade_logs')
@professor_required
def view_regrade_logs(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)
    logs = RegradeLog.query.filter_by(quiz_id=quiz_id).order_by(RegradeLog.timestamp.desc()).all()
    user_ids = {log.student_id for log in logs} | {log.regraded_by for log in logs}
    users = User.query.filter(User.id.in_(user_ids)).all() if user_ids else []
    user_map = {u.id: u.username for u in users}
    return render_template(
        'regrade_logs.html', logs=logs, quiz=quiz, user_map=user_map
    )


@app.route('/professor/quiz/<int:quiz_id>/student/<int:student_id>/report')
@professor_required
def professor_view_student_report(quiz_id, student_id):
    quiz = _owned_quiz_or_404(quiz_id)
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
            "correct": (q.correct_option or '').lower(),
            "selected": answer_map.get(q.id, None)
        })

    return render_template(
        'student_result_report.html',
        quiz=quiz,
        result=result,
        report=report,
        professor_view=True
    )


@app.route('/professor/quiz/<int:quiz_id>/release_report', methods=['POST'])
@professor_required
def release_quiz_report(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)
    quiz.report_released = True
    db.session.commit()
    flash("Reports successfully released to all students!", "success")
    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))


@app.route('/professor/quiz/<int:quiz_id>/results')
@professor_required
def view_quiz_results(quiz_id):
    quiz = _owned_quiz_or_404(quiz_id)
    marks_correct, _ = _marks_scheme(quiz)

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
        score = r.score or 0
        total = r.total_questions or 0
        max_possible = total * marks_correct
        percentage = (score * 100 / max_possible) if max_possible > 0 else 0
        percentage = max(0.0, min(100.0, percentage))

        # Answer stats (one row per question; ignore legacy duplicates)
        answers = StudentAnswer.query.filter_by(
            quiz_id=quiz_id, student_id=student_id
        ).all()
        answers_by_question = {a.question_id: a for a in answers}
        correct_count = sum(1 for a in answers_by_question.values() if a.is_correct is True)
        incorrect_count = sum(1 for a in answers_by_question.values() if a.is_correct is False)
        answered_count = len(answers_by_question)
        unanswered = max(0, total - answered_count)

        grade = (
            'A' if percentage >= 90 else
            'B' if percentage >= 75 else
            'C' if percentage >= 60 else
            'D' if percentage >= 40 else
            'F'
        )

        chart_data.append({
            "student_id": student_id,
            "username": r.username,
            "score": score,
            "correct": correct_count,
            "incorrect": incorrect_count,
            "unanswered": unanswered,
            "percentage": percentage,
            "total_questions": total,
            "submitted_at": r.submitted_at.strftime("%Y-%m-%d %H:%M") if r.submitted_at else "—",
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
        unanswered = max(0, total_students - len(answered_students))

        question_stats.append({
            'id': q.id,
            'text': q.text or '',
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
        # Ignore/clean up sessions for quizzes that were deleted.
        active_quiz = db.session.get(Quiz, active_session.quiz_id)
        if active_quiz is None:
            db.session.delete(active_session)
            db.session.commit()
        else:
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
    _owned_quiz_or_404(quiz_id)
    student = User.query.filter_by(username=student_username).first()
    if not student:
        flash("❌ Student not found.", "danger")
        return redirect(url_for('view_quiz_results', quiz_id=quiz_id))

    try:
        RegradeLog.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete(
            synchronize_session=False
        )
        Result.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete(
            synchronize_session=False
        )
        StudentAnswer.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete(
            synchronize_session=False
        )
        QuizSession.query.filter_by(quiz_id=quiz_id, student_id=student.id).delete(
            synchronize_session=False
        )

        db.session.commit()
        flash(f"✅ Quiz reset successfully for {student_username}.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"⚠️ Error resetting quiz for {student_username}: {str(e)}", "danger")

    return redirect(url_for('view_quiz_results', quiz_id=quiz_id))


@app.route('/professor/quiz/<int:quiz_id>/reset_all', methods=['POST'])
@professor_required
def reset_all_students(quiz_id):
    _owned_quiz_or_404(quiz_id)

    try:
        RegradeLog.query.filter_by(quiz_id=quiz_id).delete(synchronize_session=False)
        Result.query.filter_by(quiz_id=quiz_id).delete(synchronize_session=False)
        StudentAnswer.query.filter_by(quiz_id=quiz_id).delete(synchronize_session=False)
        QuizSession.query.filter_by(quiz_id=quiz_id).delete(synchronize_session=False)

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
        entered_code = (request.form.get('access_code') or '').strip()
        if quiz.access_code and entered_code == quiz.access_code:
            session[f'quiz_code_passed_{quiz_id}'] = True
            return redirect(url_for('take_quiz', quiz_id=quiz_id))
        flash("Incorrect access code.", "danger")

    return render_template("enter_quiz_code.html", quiz=quiz)



@app.route('/student/quiz/<int:quiz_id>/take', methods=['GET', 'POST'])
@student_required
def take_quiz(quiz_id):
    user_id = session.get("user_id")
    quiz = Quiz.query.get_or_404(quiz_id)

    # Access-code gate: the /access route is not the only way in.
    if quiz.access_code and not session.get(f'quiz_code_passed_{quiz_id}'):
        return redirect(url_for('access_quiz', quiz_id=quiz_id))

    # Block if already submitted
    result = Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if result:
        flash("You have already taken this quiz.", "warning")
        if quiz.report_released:
            return redirect(url_for("student_quiz_report", quiz_id=quiz_id))
        return redirect(url_for("student_dashboard"))

    # Deadline check
    if quiz.deadline and datetime.utcnow() > quiz.deadline:
        flash("The quiz deadline has passed.", "danger")
        return redirect(url_for("student_dashboard"))

    all_questions = list(quiz.questions)
    total_questions = len(all_questions)
    if total_questions == 0:
        flash("This quiz does not have any questions yet.", "warning")
        return redirect(url_for("student_dashboard"))

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
            question_last_seen={}
        )
        db.session.add(quiz_session)
        db.session.commit()

    # Prevent retake
    if quiz_session.submitted:
        flash("You have already submitted this quiz.", "warning")
        return redirect(url_for("student_dashboard"))

    # Remaining time logic
    started = quiz_session.start_time or datetime.utcnow()
    elapsed = (datetime.utcnow() - started).total_seconds()
    remaining_seconds = max(0, int((quiz.time_limit * 60) - elapsed)) if quiz.time_limit else None

    # Auto-submit if time over
    if remaining_seconds == 0:
        _finalize_attempt(user_id, quiz, quiz_session, _session_answers(quiz_session))
        flash("Time is up! Your quiz was auto-submitted.", "info")
        return redirect(url_for("quiz_results", quiz_id=quiz_id))

    # Get or initialize question order
    if not quiz_session.shuffled_question_ids:
        question_ids = [q.id for q in random.sample(all_questions, total_questions)]
        quiz_session.shuffled_question_ids = ",".join(map(str, question_ids))
        db.session.commit()
    else:
        question_ids = []
        for qid in quiz_session.shuffled_question_ids.split(","):
            try:
                question_ids.append(int(qid))
            except (TypeError, ValueError):
                continue

    # Get questions in the saved order
    questions = [db.session.get(Question, qid) for qid in question_ids]

    # Ensure we have all questions (in case of quiz modifications)
    existing_question_ids = {q.id for q in all_questions}
    questions = [q for q in questions if q and q.id in existing_question_ids]

    # Add any new questions that weren't in the original order
    existing_ids_in_questions = {q.id for q in questions}
    questions.extend([q for q in all_questions if q.id not in existing_ids_in_questions])

    if request.method == "POST":
        current_saved = _session_answers(quiz_session)
        submitted_answers = {}
        for q in questions:
            selected = (request.form.get(f"q_{q.id}") or "").strip().lower()
            if selected not in ('a', 'b', 'c', 'd'):
                selected = current_saved.get(str(q.id))
            if selected:
                submitted_answers[str(q.id)] = selected

        _finalize_attempt(user_id, quiz, quiz_session, submitted_answers)
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

    # Update seen timestamps to prevent a reload loop
    seen = dict(quiz_session.question_last_seen or {})
    for q in questions:
        seen[str(q.id)] = q.last_updated.isoformat() if q.last_updated else datetime.utcnow().isoformat()
    quiz_session.question_last_seen = seen

    quiz_session.quiz_last_updated = quiz.last_updated
    db.session.commit()

    return render_template(
        "take_quiz.html",
        quiz=quiz,
        questions=questions,
        remaining_seconds=remaining_seconds,
        saved_answers=_session_answers(quiz_session),
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
    filtered_answers = {}
    for qid, ans in saved.items():
        try:
            if int(qid) in current_q_ids:
                filtered_answers[qid] = ans
        except (TypeError, ValueError):
            continue
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

    _finalize_attempt(user_id, quiz, session_obj, _session_answers(session_obj))
    flash("Time is up! Your quiz was auto-submitted.", "info")
    return redirect(url_for("quiz_results", quiz_id=quiz_id))


@app.route("/quiz/<int:quiz_id>/autosave", methods=["POST"])
@student_required
def autosave(quiz_id):
    user_id = session.get("user_id")
    data = request.get_json(silent=True) or {}
    question_id = str(data.get("question_id"))
    selected_option = data.get("selected_option")

    session_obj = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
    if session_obj and not session_obj.submitted:
        saved = _session_answers(session_obj)
        if selected_option:
            saved[question_id] = str(selected_option).lower()
        else:
            saved.pop(question_id, None)
        session_obj.saved_answers = saved
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

    questions = Question.query.filter_by(quiz_id=quiz.id).all()
    answers = StudentAnswer.query.filter_by(student_id=user_id, quiz_id=quiz.id).all()
    answer_map = {a.question_id: a.selected_option for a in answers}
    option_map = {
        q.id: {'a': q.option_a, 'b': q.option_b, 'c': q.option_c, 'd': q.option_d}
        for q in questions
    }

    return render_template(
        "quiz_results.html",
        quiz=quiz,
        result=result,
        questions=questions,
        answer_map=answer_map,
        option_map=option_map,
    )


@app.route('/student/quiz/<int:quiz_id>/report')
@student_required
def student_quiz_report(quiz_id):
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
            "correct": (q.correct_option or '').lower(),
            "selected": answer_map.get(q.id, None)
        })

    return render_template('student_result_report.html', quiz=quiz, result=result, report=report)


@app.route('/submit_quiz/<int:quiz_id>', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    """Legacy submission endpoint kept for backwards compatibility."""
    user_id = session.get('user_id')
    quiz = Quiz.query.get_or_404(quiz_id)

    if session.get('user_role') != 'student':
        flash('Only students can submit quizzes.', 'danger')
        return redirect(url_for('index'))

    if Result.query.filter_by(student_id=user_id, quiz_id=quiz.id).first():
        flash('You have already taken this quiz.', 'warning')
        return redirect(url_for('student_dashboard'))

    session_obj = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz.id).first()
    if not session_obj:
        session_obj = QuizSession(
            student_id=user_id, quiz_id=quiz.id, saved_answers={}, submitted=False
        )
        db.session.add(session_obj)
        db.session.flush()

    submitted_answers = {}
    for question in quiz.questions:
        selected = (
            request.form.get(f"question_{question.id}")
            or request.form.get(f"q_{question.id}")
            or ''
        ).strip().lower()
        if selected in ('a', 'b', 'c', 'd'):
            submitted_answers[str(question.id)] = selected

    _finalize_attempt(user_id, quiz, session_obj, submitted_answers)
    flash('Quiz submitted successfully!', 'success')
    return redirect(url_for('quiz_results', quiz_id=quiz.id))




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
        data = request.get_json(silent=True) or {}
        user_id = session.get("user_id")
        try:
            quiz_id = int(data.get('quiz_id'))
            question_id = int(data.get('question_id'))
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'Invalid quiz or question id'}), 400

        selected_option = data.get('selected_option')
        if selected_option:
            selected_option = str(selected_option).strip().lower()
            if selected_option not in ('a', 'b', 'c', 'd'):
                return jsonify({'success': False, 'error': 'Invalid option'}), 400
        else:
            selected_option = None

        question = db.session.get(Question, question_id)
        if not question or question.quiz_id != quiz_id:
            return jsonify({'success': False, 'error': 'Question not found'}), 404

        # Do not accept answers after submission.
        if Result.query.filter_by(student_id=user_id, quiz_id=quiz_id).first():
            return jsonify({'success': False, 'error': 'Quiz already submitted'}), 400

        quiz_session = QuizSession.query.filter_by(student_id=user_id, quiz_id=quiz_id).first()
        if not quiz_session or quiz_session.submitted:
            return jsonify({'success': False, 'error': 'No active quiz session'}), 400

        question_key = str(question_id)

        # Save to the Flask session as a lightweight fallback.
        session_key = f'saved_answers_{quiz_id}'
        session_answers = session.get(session_key, {})
        if selected_option:
            session_answers[question_key] = selected_option
        else:
            session_answers.pop(question_key, None)
        session[session_key] = session_answers
        session.modified = True

        # Save to QuizSession (used by auto-submit).
        saved = _session_answers(quiz_session)
        if selected_option:
            saved[question_key] = selected_option
        else:
            saved.pop(question_key, None)
        quiz_session.saved_answers = saved
        quiz_session.last_saved = datetime.utcnow()

        # Mirror into StudentAnswer so analytics stay accurate during the quiz.
        answer = StudentAnswer.query.filter_by(
            student_id=user_id,
            quiz_id=quiz_id,
            question_id=question_id
        ).first()

        if answer:
            answer.selected_option = selected_option
            answer.is_correct = bool(
                selected_option and question.correct_option
                and selected_option == question.correct_option.lower()
            )
        elif selected_option:
            db.session.add(StudentAnswer(
                student_id=user_id,
                quiz_id=quiz_id,
                question_id=question_id,
                selected_option=selected_option,
                is_correct=bool(
                    question.correct_option
                    and selected_option == question.correct_option.lower()
                )
            ))

        db.session.commit()

        return jsonify({
            'success': True,
            'question_id': question_key,
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


# --- Error Handlers ---
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('403.html'), 403


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500


@app.template_filter('chr')
def chr_filter(value):
    return chr(value)


# --- Main Execution ---
if __name__ == '__main__':
    debug = os.environ.get('FLASK_DEBUG', '0') == '1'
    port = int(os.environ.get('PORT', '5100'))
    app.run(debug=debug, port=port)
