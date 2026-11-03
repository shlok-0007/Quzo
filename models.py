from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import relationship
from sqlalchemy.types import JSON
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()

# Security questions for password recovery
SECURITY_QUESTIONS = [
    ('1', "What was your first pet's name?"),
    ('2', 'What was the name of your first school?'),
    ('3', "What is your mother's maiden name?"),
    ('4', 'What city were you born in?'),
    ('5', 'What is your favorite book?')
]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    # 255 leaves room for newer Werkzeug hash formats (scrypt, argon2, ...).
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    security_question = db.Column(db.String(3), nullable=True)  # Stores the question ID
    security_answer_hash = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def set_security_answer(self, answer):
        self.security_answer_hash = generate_password_hash(answer.lower().strip())

    def check_security_answer(self, answer):
        if not self.security_answer_hash or answer is None:
            return False
        return check_password_hash(self.security_answer_hash, answer.lower().strip())


class Quiz(db.Model):
    __tablename__ = 'quiz'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    professor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    time_limit = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_released = db.Column(db.Boolean, default=False)
    deadline = db.Column(db.DateTime, nullable=True)
    access_code = db.Column(db.String(50), nullable=True)
    marks_correct = db.Column(db.Float, default=1.0)
    marks_incorrect = db.Column(db.Float, default=0.0)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = relationship("User", backref="quizzes", foreign_keys=[professor_id])
    questions = db.relationship(
        'Question', backref='parent_quiz', cascade='all, delete-orphan', lazy=True
    )
    results = db.relationship(
        'Result', backref='quiz', cascade='all, delete-orphan', lazy=True
    )
    sessions = db.relationship(
        'QuizSession', backref='quiz', cascade='all, delete-orphan', lazy=True
    )


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False, index=True)
    text = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(255), nullable=True)
    option_a = db.Column(db.String(500), nullable=False)
    option_b = db.Column(db.String(500), nullable=False)
    option_c = db.Column(db.String(500), nullable=False)
    option_d = db.Column(db.String(500), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False, index=True)
    # Float so fractional marking schemes (e.g. +4 / -1.5) are stored accurately.
    score = db.Column(db.Float, nullable=False, default=0)
    total_questions = db.Column(db.Integer, nullable=False, default=0)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_released = db.Column(db.Boolean, default=False)
    student = db.relationship('User', backref='results', foreign_keys=[student_id])

    __table_args__ = (
        db.UniqueConstraint('student_id', 'quiz_id', name='uq_student_quiz_result'),
    )

    def __repr__(self):
        return f"<Result student_id={self.student_id} quiz_id={self.quiz_id} score={self.score}>"


class StudentAnswer(db.Model):
    __tablename__ = 'student_answers'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False, index=True)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False, index=True)
    selected_option = db.Column(db.String(255))
    is_correct = db.Column(db.Boolean)
    start_time = db.Column(db.DateTime, nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint(
            'student_id', 'quiz_id', 'question_id', name='uq_student_quiz_answer'
        ),
    )


class RegradeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False, index=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    old_score = db.Column(db.Float, nullable=False)
    new_score = db.Column(db.Float, nullable=False)
    regraded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class QuizSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False, index=True)

    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_saved = db.Column(db.DateTime, default=datetime.utcnow)

    saved_answers = db.Column(MutableDict.as_mutable(JSON), default=dict)  # {question_id: option}
    submitted = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime)
    quiz_last_updated = db.Column(db.DateTime)
    question_last_seen = db.Column(MutableDict.as_mutable(JSON), default=dict)
    shuffled_question_ids = db.Column(db.Text)
    randomized_question_ids = db.Column(db.PickleType)  # For backward compatibility

    __table_args__ = (
        db.UniqueConstraint('student_id', 'quiz_id', name='uq_student_quiz_session'),
    )

    def __repr__(self):
        return f"<QuizSession student_id={self.student_id}, quiz_id={self.quiz_id}>"
