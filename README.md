# Quiz Application

A comprehensive web-based quiz management system built with Flask and SQLAlchemy. This application allows professors to create and manage quizzes, while students can take these quizzes and view their results.

## 🚀 Live Demo

You can access a live demo of this application at: [shloksitare.pythonanywhere.com](http://shloksitare.pythonanywhere.com)

## Features

### For Professors
- Create and manage quizzes with multiple-choice questions
- Set time limits and deadlines for quizzes
- Generate quizzes using AI (Gemini API integration)
- View detailed quiz results and analytics
- Export quiz results to CSV
- Regrade quizzes and manage student submissions
- Release results to students

### For Students
- Take quizzes with a user-friendly interface
- View quiz results and feedback
- Track time remaining during quizzes
- Auto-save progress during quiz taking
- View historical quiz attempts

## Prerequisites

- Python 3.7+
- pip (Python package manager)
- Git
- A Gemini API key (for AI quiz generation)

## Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/shlok-0007/Quzo.git
   cd Quzo
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   Create a `.env` file in the project root with the following content:
   ```
   SECRET_KEY=your-secret-key-here
   DATABASE_URI=sqlite:///app.db
   GEMINI_API_KEY=your-gemini-api-key
   ```

5. **Initialize the database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

## Configuration

1. **API Keys**
   - Create a `api_keys.json` file in the project root with your Gemini API key:
     ```json
     {
         "keys": ["your-gemini-api-key-here"],
         "key_status": {
             "your-gemini-api-key-here": {
                 "is_active": true,
                 "usage_count": 0
             }
         }
     }
     ```

2. **Database**
   - The application uses SQLite by default, which will be created automatically
   - For production, consider using PostgreSQL or MySQL by updating the `SQLALCHEMY_DATABASE_URI` in `config.py`

## Running the Application

1. **Start the development server**
   ```bash
   python app1.py
   ```
   or
   ```bash
   flask run
   ```

2. **Access the application**
   - Open your web browser and go to `http://localhost:5000`
   - Register as a professor or student

## Project Structure

```
.
├── app1.py               # Main application file
├── config.py            # Configuration settings
├── models.py            # Database models
├── api_utils.py         # Utility functions for API integration
├── requirements.txt     # Python dependencies
├── migrations/          # Database migrations
├── static/              # Static files (CSS, JS, images)
└── templates/           # HTML templates
```

## API Integration

This application integrates with the Google Gemini API for AI-powered quiz generation. To use this feature:

1. Get a Gemini API key from [Google AI Studio](https://makersuite.google.com/)
2. Add the key to your `api_keys.json` file
3. The AI will be available when creating new quizzes

## Security Considerations

- Always keep your `SECRET_KEY` and API keys private
- Use environment variables for sensitive information
- Regularly update your dependencies
- Use HTTPS in production

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Flask](https://flask.palletsprojects.com/)
- Uses [SQLAlchemy](https://www.sqlalchemy.org/) for database operations
- AI features powered by [Google Gemini](https://ai.google.dev/)
- Frontend built with Bootstrap 5
