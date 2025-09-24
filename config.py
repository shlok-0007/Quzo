import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-super-secret-key-that-is-long-and-random'
    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY') or 'AIzaSyDERylGAnWStdDMD14gAQ111COI7kBEYW4'
    # Use SQLite for simplicity. For production, consider PostgreSQL or MySQL.
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False