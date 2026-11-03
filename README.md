# Quzo (Quiz Application)

A web-based quiz management system built with Flask and SQLAlchemy. Professors create and manage quizzes with AI assistance, while students take quizzes and view released results.

## 🚀 Live Demo

You can access a live demo of this application at: [shloksitare.pythonanywhere.com](http://shloksitare.pythonanywhere.com)

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
   | `UPLOAD_FOLDER` | No | Directory for uploaded question images. Defaults to `static/uploads` locally and `/tmp/quzo-uploads` on Vercel. |

4. **Run the app**
   ```bash
   python app1.py
   ```
   The app is served on `http://localhost:5100` by default (`PORT` overrides it).
   Tables are created automatically on first start.

## Configuration Notes

- **Database:** SQLite (`app.db`) is used automatically for local development. On serverless hosts the app falls back to `/tmp/quzo.db`, which is wiped on every cold start — always set `DATABASE_URL` for production.
- **API keys:** Keys are read from environment variables first. The optional `api_keys.json` file is a local-only fallback and is git-ignored; never commit real keys.
- **Uploads:** Question images are written to `UPLOAD_FOLDER` and served through the `/uploads/<filename>` route. On Vercel this is ephemeral, so use external object storage for long-lived images.

## Deploying to Vercel

The repository already contains everything Vercel needs:

- `api/index.py` — serverless entrypoint that exports the Flask `app`
- `vercel.json` — builds `api/index.py` with `@vercel/python` and routes all traffic to it
- `requirements.txt` — installed by the Python builder

### 1. Get a Postgres database

Create a free database with [Neon](https://neon.tech/) or Vercel Postgres and copy the **pooled** connection string. Serverless functions open many short-lived connections, so a pooler (e.g. Neon's `-pooler` host) is important.

### 2. Deploy

```bash
npm i -g vercel
vercel login
vercel            # preview deployment
vercel --prod     # production deployment
```

Deploy from the directory that contains `vercel.json` (the project root).

Alternatively, push the repository to GitHub and import it in the Vercel dashboard. Leave the framework preset as **Other** and do not override the build/output settings.

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
├── wsgi.py               # Generic WSGI / local runner
├── api/index.py          # Vercel serverless entrypoint
├── vercel.json           # Vercel build and routing config
├── requirements.txt      # Python dependencies
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
