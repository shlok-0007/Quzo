import json
import os
import re
from datetime import datetime

import google.generativeai as genai

DEFAULT_MODEL = os.environ.get('GEMINI_MODEL', 'gemini-1.5-flash')


class APIKeyManager:
    """Small helper that rotates Gemini API keys.

    Keys are looked up in this order:
      1. ``GEMINI_API_KEYS`` (comma separated) or ``GEMINI_API_KEY`` env vars.
      2. ``api_keys.json`` (local development convenience only).

    On read-only filesystems (Vercel/Lambda) usage counters are kept in
    memory instead of trying to write the JSON file.
    """

    def __init__(self, keys_file='api_keys.json'):
        self.keys_file = keys_file
        self.data = {"keys": [], "key_status": {}}
        self._writable = True
        self.load_keys()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def load_keys(self):
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    self.data = {
                        "keys": data.get("keys", []),
                        "key_status": data.get("key_status", {}),
                    }
            except (OSError, ValueError):
                self.data = {"keys": [], "key_status": {}}

        env_keys = os.environ.get('GEMINI_API_KEYS') or os.environ.get('GEMINI_API_KEY') or ''
        for key in env_keys.split(','):
            key = key.strip()
            if key and key not in self.data['keys']:
                self.data['keys'].append(key)
                self.data['key_status'].setdefault(
                    key, {'is_active': True, 'usage_count': 0}
                )

    def save_keys(self):
        if not self._writable:
            return
        try:
            with open(self.keys_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2)
        except OSError:
            # Read-only deployment: persist in memory for this process only.
            self._writable = False

    # ------------------------------------------------------------------
    # Key selection / health
    # ------------------------------------------------------------------
    def get_active_key(self):
        keys = self.data.get('keys', [])
        key_status = self.data.get('key_status', {})

        active_keys = [k for k in keys if key_status.get(k, {}).get('is_active', True)]
        if not active_keys:
            # All keys were marked inactive (e.g. quota reset happened).
            for key in keys:
                key_status.setdefault(key, {})['is_active'] = True
            active_keys = list(keys)
            self.save_keys()

        if not active_keys:
            return None

        active_keys.sort(key=lambda k: key_status.get(k, {}).get('usage_count', 0))
        return active_keys[0]

    def mark_key_used(self, api_key):
        status = self.data.setdefault('key_status', {}).setdefault(api_key, {})
        status['last_used'] = datetime.now().isoformat()
        status['usage_count'] = status.get('usage_count', 0) + 1
        self.save_keys()

    def mark_key_inactive(self, api_key, reason="quota_exceeded"):
        status = self.data.setdefault('key_status', {}).setdefault(api_key, {})
        status['is_active'] = False
        status['deactivated_at'] = datetime.now().isoformat()
        status['deactivation_reason'] = reason
        self.save_keys()

    def reactivate_all_keys(self):
        for key in self.data.get('keys', []):
            self.data.setdefault('key_status', {}).setdefault(key, {})['is_active'] = True
        self.save_keys()


def _extract_json(response_text):
    """Pull a JSON array/object out of an LLM response."""
    text = (response_text or '').strip()

    # Prefer fenced code blocks when present.
    match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
    if match:
        text = match.group(1).strip()

    text = re.sub(r'^```.*?$', '', text, flags=re.MULTILINE).strip()

    if (text.startswith('[') and text.endswith(']')) or (
        text.startswith('{') and text.endswith('}')
    ):
        return json.loads(text)

    # Otherwise grab the largest array-looking chunk.
    array_match = re.search(r'\[.*\]', text, re.DOTALL)
    if array_match:
        return json.loads(array_match.group(0))
    return json.loads(text)


def generate_quiz_questions(topic, num_questions=10, difficulty='medium', max_retries=3):
    """Generate quiz questions using Gemini with API key rotation.

    Returns a list of ``{"question_text", "options", "correct_answer"}`` dicts.
    Raises an exception when generation fails after all retries.
    """
    key_manager = APIKeyManager()

    difficulty_descriptions = {
        'easy': 'Beginner level questions with straightforward concepts and answers',
        'medium': 'Intermediate level questions that require some knowledge and understanding',
        'hard': 'Advanced level questions that test in-depth knowledge and application',
        'mixed': 'A mix of easy, medium, and hard questions (distributed evenly)',
    }
    difficulty_instruction = difficulty_descriptions.get(
        difficulty, difficulty_descriptions['medium']
    )

    prompt = f"""Create a JSON array of {num_questions} multiple-choice quiz questions on the topic of '{topic}'.
    Difficulty Level: {difficulty_instruction}

    Each question object must have this exact format:
    {{
        "question_text": "The question text here",
        "options": ["Option A", "Option B", "Option C", "Option D"],
        "correct_answer": "The correct option text from above",
        "difficulty": "easy/medium/hard"
    }}

    IMPORTANT RULES:
    - Return ONLY a JSON array, no additional text or code blocks
    - Each question must have exactly 4 options
    - The correct_answer must exactly match one of the options
    - Include a difficulty level (easy/medium/hard) for each question
    - For mixed difficulty, distribute questions across all levels
    - Avoid using code snippets with backticks in question text
    - Use clear and concise language appropriate for the difficulty level
    - Ensure questions are educational and test understanding
    - Make incorrect options plausible but clearly wrong
    - Vary the position of the correct answer

    For {difficulty} difficulty, follow these guidelines:
    - Easy: Focus on basic recall and understanding
    - Medium: Include application and analysis questions
    - Hard: Include synthesis and evaluation questions
    - Mixed: Distribute questions across all difficulty levels
    """

    last_error = None
    for attempt in range(max_retries):
        api_key = None
        try:
            api_key = key_manager.get_active_key()
            if not api_key:
                raise RuntimeError(
                    'No Gemini API key configured. Set GEMINI_API_KEY (or '
                    'GEMINI_API_KEYS) in the environment.'
                )

            genai.configure(api_key=api_key)
            model = genai.GenerativeModel(DEFAULT_MODEL)
            response = model.generate_content(prompt)
            key_manager.mark_key_used(api_key)

            questions_list = _extract_json(getattr(response, 'text', ''))

            if isinstance(questions_list, dict) and 'questions' in questions_list:
                questions_list = questions_list['questions']
            if not isinstance(questions_list, list):
                raise ValueError("Expected a list of questions")

            validated_questions = []
            for question in questions_list:
                if not isinstance(question, dict):
                    continue
                if not all(k in question for k in ('question_text', 'options', 'correct_answer')):
                    continue

                options = question['options']
                if isinstance(options, dict):
                    options = list(options.values())
                if not isinstance(options, list) or len(options) != 4:
                    continue
                options = [str(o).strip() for o in options]

                question_text = str(question['question_text']).replace('```', '').strip()
                if not question_text:
                    continue

                correct_answer = str(question['correct_answer']).strip()
                if correct_answer not in options:
                    match = next(
                        (
                            o
                            for o in options
                            if o.lower() == correct_answer.lower()
                        ),
                        None,
                    )
                    if not match:
                        continue
                    correct_answer = match

                validated_questions.append(
                    {
                        'question_text': question_text,
                        'options': options,
                        'correct_answer': correct_answer,
                    }
                )

            minimum = min(3, max(1, int(num_questions) // 2))
            if len(validated_questions) >= minimum:
                return validated_questions[: int(num_questions)]

            raise ValueError(
                f"Only {len(validated_questions)} valid questions generated, "
                f"expected at least {minimum}"
            )

        except json.JSONDecodeError as exc:
            last_error = exc
            print(f"JSON parsing error on attempt {attempt + 1}: {exc}")
        except Exception as exc:  # noqa: BLE001 - surface a useful final message
            last_error = exc
            error_msg = str(exc).lower()
            print(f"Error on attempt {attempt + 1}: {exc}")

            if api_key and any(
                keyword in error_msg
                for keyword in ('quota', 'limit', '429', 'rate limit', 'api key')
            ):
                key_manager.mark_key_inactive(api_key, 'quota_exceeded')
                print(f"Marked API key as inactive: {api_key[:10]}...")

    raise RuntimeError(
        f"Failed to generate quiz questions after {max_retries} attempts: {last_error}"
    )
