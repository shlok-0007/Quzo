# Quzo (Quiz Application)

A web-based quiz management system built with Flask and SQLAlchemy. Professors create and manage quizzes with AI assistance, while students take quizzes and view released results.

## 🚀 Live Demo

You can access a live demo of this application at: [https://quzo.vercel.app](https://quzo.vercel.app/)

## Features

### For Professors
- Create and manage quizzes with multiple-choice questions
- Set time limits and deadlines for quizzes
- Generate quizzes using AI (Gemini API integration)
- View detailed quiz results and analytics
- Export quiz results to CSV or PDF
- Regrade quizzes and review a full regrade log
- Release results to students when ready

### For Students
- Take quizzes with a timer and auto-save
- Upload/draw answers as configured by the professor
- View results and feedback once released
- Track historical quiz attempts

## Requirements

- Python 3.10+ (3.12 is recommended; this is what Vercel uses)
- pip
- A Gemini API key (only needed for AI quiz generation)
- PostgreSQL database for production (optional but strongly recommended)

## Local Installation

1. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # macOS / Linux
   source .venv/bin/activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   ```bash
   copy .env.example .env      # Windows
   cp .env.example .env        # macOS / Linux
   ```
   Then edit `.env`:

   | Variable | Required | Description |
   | --- | --- | --- |
   | `SECRET_KEY` | Production: yes | Long random string used to sign sessions. Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. |
   | `GEMINI_API_KEY` | No | Single Google Gemini key for AI quiz generation. |
   | `GEMINI_API_KEYS` | No | Comma-separated list of Gemini keys for rotation. Takes precedence when set. |
   | `DATABASE_URL` | Production: yes | SQLAlchemy database URL. `postgres://` is normalized automatically. `POSTGRES_URL` / `POSTGRES_PRISMA_URL` / `NEON_DATABASE_URL` are also accepted. |
   | `UPLOAD_FOLDER` | No | Private upload directory. Defaults to `instance/uploads` locally and `/tmp/quzo-uploads` on Vercel. |
   | `QUZO_ENV` | Production | Set to `production` for non-Vercel deployments to require a session secret and HTTPS cookies. |
   | `QUZO_PROFESSOR_INVITE` | For new professor accounts | Private invitation code. Existing professors can sign in without it. |
   | `QUZO_PUBLIC_URL`, `QUZO_SMTP_HOST`, `QUZO_MAIL_FROM` | For recovery mail | Public app origin and SMTP-over-TLS delivery settings. Set `QUZO_SMTP_PORT`, `QUZO_SMTP_USER`, and `QUZO_SMTP_PASSWORD` as needed. |

4. **Run the app**
   ```bash
   python app1.py
   ```
   The app is served on `http://localhost:5100` by default (`PORT` overrides it).
   Tables are created automatically on first start.

## Configuration Notes

- **Database:** SQLite (`app.db`) is used automatically for local development. On serverless hosts the app falls back to `/tmp/quzo.db`, which is wiped on every cold start — always set `DATABASE_URL` for production.
- **API keys:** Keys are read from environment variables first. The optional `api_keys.json` file is a local-only fallback and is git-ignored; never commit real keys.
- **Uploads:** Question images are served through an authenticated route. Set `QUZO_S3_BUCKET` for durable storage, optionally set `QUZO_S3_ENDPOINT` for an S3-compatible endpoint, and use the AWS SDK credential chain. Keep the bucket private and grant the app read and write access under `questions/`. When no bucket is configured, the app uses `UPLOAD_FOLDER`, which is ephemeral on Vercel.
- **Recovery:** Reset links expire after 20 minutes and become unusable after a successful reset. Configure SMTP and verify it with a test account before deploying. The sign-in session format changed, so users with older sessions will need to sign in again.

## Local tests

```sh
python -m pip install -r requirements.txt pytest
python -m pytest -q
```

The tests use an isolated SQLite database and mock Gemini. Verify SMTP, Gemini, and PostgreSQL against a staging deployment before release.

## Managed database migrations

Set `QUZO_MANAGED_SCHEMA=1` in staging or production to use Alembic instead of startup table creation. Apply migrations from the repository root before starting the web process.

```sh
python -m flask --app wsgi db upgrade
python -m flask --app wsgi db check
```

For a database created by an older release using `create_all`, take a backup and verify a restore on a separate database. Compare the existing tables, columns, and constraints with revision `f14084471806` before adopting that baseline. If they match, run `python -m flask --app wsgi db stamp f14084471806` once, then upgrade and check. Apply the procedure to the restored copy before repeating it on the live database.

## Backup and restore checks

Run `python backup.py path/to/new-backup` with `QUZO_BACKUP_DATABASE_URL` supplied through the backup process environment. Use an existing private, durable destination directory. SQLite archives are checked for integrity. PostgreSQL requires compatible `pg_dump` and `pg_restore` utilities and creates a checked custom-format archive. Schedule this command in the deployment's backup service and retain the question-image bucket separately.

Rehearse restoration against a new database with isolated credentials. Open a SQLite archive from a copy. For PostgreSQL, configure an isolated libpq service or rehearsal host and credentials in the environment, then run `pg_restore --dbname=quzo_restore --exit-on-error --no-owner path/to/archive` against the empty rehearsal database. Verify migrations and the quiz smoke flow against the restored copy before relying on the backup.

## Deploying to Vercel

Vercel deploys this app using its zero-config **Flask** support:

- `wsgi.py` — exports the Flask `app`; Vercel detects this entrypoint automatically
- `requirements.txt` — installed by the Python builder
- `.vercelignore` — keeps the virtualenv, local database, and secrets out of the upload

> **Important:** the Vercel project's **Framework Preset must be set to `flask`**. If it is left on "Other", Vercel treats the repo as a static site and every route returns 404. Set it under **Project → Settings → General → Framework Preset**, or with:
> ```bash
> vercel project update quzo --framework flask --yes
> ```

### 1. Get a Postgres database

Create a free database with [Neon](https://neon.tech/) or Vercel Postgres and copy the **pooled** connection string. Serverless functions open many short-lived connections, so a pooler (e.g. Neon's `-pooler` host) is important.

### 2. Deploy

```bash
npm i -g vercel
vercel login
vercel            # preview deployment
vercel --prod     # production deployment
```

Deploy from the repository root. To enable automatic deployments on every push, connect the repository with `vercel git connect` or import the project in the Vercel dashboard.

### 3. Set environment variables

In **Vercel → Project → Settings → Environment Variables**, add:

- `SECRET_KEY` (required)
- `DATABASE_URL` (required for persistent data)
- `GEMINI_API_KEY` or `GEMINI_API_KEYS` (optional, for AI quiz generation)

Redeploy after adding them so the functions pick them up.

### Command-line deployment with a token

```bash
vercel --prod --token "$env:VERCEL_TOKEN"
vercel env add SECRET_KEY production
vercel env add DATABASE_URL production
```

## Security Notes

- Never commit `.env` or real API keys. This repository previously contained Gemini keys in `api_keys.json`; those keys should be **revoked and rotated** in Google AI Studio.
- Set a strong, unique `SECRET_KEY` in production. The built-in fallback is for local development only.
- The app does not yet include global CSRF protection on forms. Add Flask-WTF/CSRF tokens before exposing sensitive write endpoints publicly.
- Use HTTPS in production. Cookies are marked `Secure` automatically when `VERCEL` is set.

## Project Structure

```
.
├── app1.py               # Main application (routes, helpers, CLI entrypoint)
├── config.py             # Environment-aware configuration
├── models.py             # SQLAlchemy models
├── api_utils.py          # Gemini key rotation and API helpers
├── wsgi.py               # Flask entrypoint used by Vercel (exports `app`)
├── requirements.txt      # Python dependencies
├── .vercelignore         # Files excluded from Vercel uploads
├── static/               # CSS, JS, images, uploads
└── templates/            # Jinja2 templates
```

## AI Integration

1. Get a Gemini API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Export it as `GEMINI_API_KEY` (or list several in `GEMINI_API_KEYS`).
3. The AI generator becomes available when creating a new quiz.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Uses [SQLAlchemy](https://www.sqlalchemy.org/) for database operations
- AI features powered by [Google Gemini](https://ai.google.dev/)
- Frontend built with Bootstrap 5
