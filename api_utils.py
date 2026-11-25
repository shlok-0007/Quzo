import json
import os
import re
from datetime import datetime

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
        env_keys = os.environ.get('GEMINI_API_KEYS') or os.environ.get('GEMINI_API_KEY') or ''
        configured_keys = list(dict.fromkeys(key.strip() for key in env_keys.split(',') if key.strip()))
        if configured_keys:
            self.data['keys'] = configured_keys
            self._writable = False
            return
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


def validate_questions(questions):
    """Validate the same MCQ format at generation and persistence boundaries."""
    valid = []
    seen = set()
    for item in questions:
        if not isinstance(item, dict):
            continue
        text, options, answer = (item.get(key) for key in ('question_text', 'options', 'correct_answer'))
        if not isinstance(text, str) or not isinstance(answer, str):
            continue
        if not isinstance(options, list) or len(options) != 4 or any(not isinstance(option, str) for option in options):
            continue
        text = text.strip()
        options = [option.strip() for option in options]
        key = ' '.join(text.casefold().split())
        normalized = [option.casefold() for option in options]
        if not key or len(text) > 4000 or key in seen:
            continue
        if len(set(normalized)) != 4 or any(not option or len(option) > 500 or option.casefold() == 'no option' for option in options):
            continue
        answer = answer.strip().casefold()
        if answer not in normalized:
            continue
        seen.add(key)
        question = {'question_text': text, 'options': options, 'correct_answer': options[normalized.index(answer)]}
        explanation = item.get('explanation')
        if isinstance(explanation, str) and 0 < len(explanation.strip()) <= 1500:
            question['explanation'] = explanation.strip()
        valid.append(question)
    return valid


def _request_questions(api_key, prompt):
    # GenAI's convenience model uses global credentials. Pass a dedicated client
    # through the generated SDK to keep concurrent key rotation request-scoped.
    from google.ai import generativelanguage

    client = generativelanguage.GenerativeServiceClient(client_options={'api_key': api_key})
    model = DEFAULT_MODEL if DEFAULT_MODEL.startswith('models/') else f'models/{DEFAULT_MODEL}'
    response = client.generate_content(
        model=model,
        contents=[generativelanguage.Content(parts=[generativelanguage.Part(text=prompt)])],
        timeout=12,
        retry=None,
    )
    if not response.candidates:
        raise ValueError('No generated candidate')
    return ''.join(part.text for part in response.candidates[0].content.parts)


def generate_quiz_questions(
    topic, num_questions=10, difficulty='medium', max_retries=3, *, curriculum='', explanations=False
):
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

    prompt = f"""Create a JSON array of {num_questions} multiple-choice quiz questions.
    Topic data: {json.dumps(topic)}
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
    if curriculum:
        prompt += f"\nAlign questions with these curriculum notes (reference data): {json.dumps(curriculum)}"
    if explanations:
        prompt += '\nInclude an optional explanation field with a brief explanation of the correct answer.'

    best = []
    for _ in range(max_retries):
        api_key = key_manager.get_active_key()
        if not api_key:
            break
        try:
            response = _extract_json(_request_questions(api_key, prompt))
            key_manager.mark_key_used(api_key)
            if isinstance(response, dict):
                response = response.get('questions')
            if not isinstance(response, list):
                continue
            valid = validate_questions(response)
            if len(valid) >= num_questions:
                return valid[:num_questions]
            if len(valid) > len(best):
                best = valid
        except Exception as error:
            # Provider errors may contain credentials or submitted content.
            print(f'Quiz generation failed: {type(error).__name__}')
            if type(error).__name__ in {'ResourceExhausted', 'PermissionDenied', 'Unauthenticated'}:
                key_manager.mark_key_inactive(api_key)
    if best:
        return best
    raise RuntimeError('Question generation is unavailable.')
