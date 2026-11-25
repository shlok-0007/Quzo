import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))


def _normalise_database_url(url):
    """Vercel/Heroku hand out ``postgres://`` URLs; SQLAlchemy needs ``postgresql://``."""
    if not url:
        return None
    url = url.strip()
    if url.startswith('postgres://'):
        url = 'postgresql://' + url[len('postgres://'):]
    # SQLAlchemy 2.1 defaults a bare ``postgresql://`` URL to psycopg 3, but
    # this project installs psycopg2-binary, so pin the driver explicitly.
    if url.startswith('postgresql://'):
        url = 'postgresql+psycopg2://' + url[len('postgresql://'):]
    return url


def _default_database_uri():
    for env_name in (
        'DATABASE_URL',
        'POSTGRES_URL',
        'POSTGRES_PRISMA_URL',
        'NEON_DATABASE_URL',
    ):
        url = _normalise_database_url(os.environ.get(env_name))
        if url:
            return url
    # Serverless filesystems are read-only apart from /tmp. Falling back to
    # /tmp keeps the app usable for demos, but data is lost on cold starts.
    if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
        return 'sqlite:////tmp/quzo.db'
    return 'sqlite:///' + os.path.join(basedir, 'app.db')


class Config:
    PRODUCTION = os.environ.get('QUZO_ENV') == 'production' or bool(
        os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME')
    )
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY and PRODUCTION:
        raise RuntimeError('SECRET_KEY is required in production.')
    if not SECRET_KEY:
        from secrets import token_urlsafe

        SECRET_KEY = token_urlsafe(48)

    GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

    SQLALCHEMY_DATABASE_URI = _default_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {'pool_pre_ping': True}

    # Uploaded question images live outside the read-only bundle on Vercel.
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER') or (
        '/tmp/quzo-uploads'
        if (os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'))
        else os.path.join(basedir, 'instance', 'uploads')
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB upload limit

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    SESSION_REFRESH_EACH_REQUEST = False
    # Vercel terminates TLS for us, so mark the cookie Secure there.
    SESSION_COOKIE_SECURE = PRODUCTION or os.environ.get(
        'SESSION_COOKIE_SECURE', ''
    ).lower() in ('1', 'true', 'yes')

    PREFERRED_URL_SCHEME = 'https' if os.environ.get('VERCEL') else 'http'
