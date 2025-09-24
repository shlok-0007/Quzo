from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from sqlalchemy.orm import relationship
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.types import JSON
db = SQLAlchemy()
from sqlalchemy.ext.mutable import MutableDict

# Security questions for password recovery
SECURITY_QUESTIONS = [
    ('1', 'What was your first pet\'s name?'),
    ('2', 'What was the name of your first school?'),
    ('3', 'What is your mother\'s maiden name?'),
    ('4', 'What city were you born in?'),
    ('5', 'What is your favorite book?')
]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    security_question = db.Column(db.String(3), nullable=True)  # Stores the question ID
    security_answer_hash = db.Column(db.String(128), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
        
    def set_security_answer(self, answer):
        self.security_answer_hash = generate_password_hash(answer.lower().strip())
        
    def check_security_answer(self, answer):
        if not self.security_answer_hash:
            return False
        return check_password_hash(self.security_answer_hash, answer.lower().strip())

class Quiz(db.Model):
    __tablename__ = 'quiz'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    time_limit = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_released = db.Column(db.Boolean, default=False)
    deadline = db.Column(db.DateTime, nullable=True)  # ✅
    access_code = db.Column(db.String(20), nullable=True)  # ✅
    creator = relationship("User", backref="quizzes", foreign_keys=[professor_id])
    questions = db.relationship('Question', backref='parent_quiz', cascade='all, delete-orphan', lazy=True)
    marks_correct = db.Column(db.Float, default=1.0)
    marks_incorrect = db.Column(db.Float, default=0.0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)



class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    text = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    option_a = db.Column(db.String(100), nullable=False)
    option_b = db.Column(db.String(100), nullable=False)
    option_c = db.Column(db.String(100), nullable=False)
    option_d = db.Column(db.String(100), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_released = db.Column(db.Boolean, default=False)  
    student = db.relationship('User', backref='results', foreign_keys=[student_id])
    quiz = db.relationship('Quiz', backref='results', foreign_keys=[quiz_id])

    def __repr__(self):
        return f"<Result student_id={self.student_id} quiz_id={self.quiz_id} score={self.score}>"

class StudentAnswer(db.Model):
    __tablename__ = 'student_answers'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    selected_option = db.Column(db.String(255))
    is_correct = db.Column(db.Boolean)
    start_time = db.Column(db.DateTime, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    

class RegradeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    old_score = db.Column(db.Integer, nullable=False)
    new_score = db.Column(db.Integer, nullable=False)
    regraded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # professor
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)



class QuizSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)

    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_saved = db.Column(db.DateTime, default=datetime.utcnow)

    saved_answers = db.Column(MutableDict.as_mutable(JSON), default=dict) # ✅ Store answers as JSON
    submitted = db.Column(db.Boolean, default=False)  # ✅ Track if quiz submitted
    submitted_at = db.Column(db.DateTime)  # optional: track when submitted
    quiz_last_updated = db.Column(db.DateTime) 
    question_last_seen = db.Column(MutableDict.as_mutable(JSON), default=dict)  # {question_id: timestamp}
    shuffled_question_ids = db.Column(db.Text)  # Store comma-separated question IDs to maintain order
    randomized_question_ids = db.Column(db.PickleType)  # For backward compatibility

    __table_args__ = (
        db.UniqueConstraint('student_id', 'quiz_id', name='uq_student_quiz_session'),
    )

    def __repr__(self):
        return f"<QuizSession student_id={self.student_id}, quiz_id={self.quiz_id}>"
