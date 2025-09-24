import json
import os
from datetime import datetime
import google.generativeai as genai
import random

class APIKeyManager:
    def __init__(self, keys_file='api_keys.json'):
        self.keys_file = keys_file
        self.data = {"keys": [], "key_status": {}}
        self.load_keys()

        from flask import current_app
        if not self.data.get('keys') and current_app and hasattr(current_app, 'config'):
            config_key = current_app.config.get('GEMINI_API_KEY')
            if config_key:
                self.data['keys'] = [config_key]
                self.data['key_status'][config_key] = {
                    'is_active': True,
                    'usage_count': 0,
                    'added_from_config': True
                }
                self.save_keys()
    
    def load_keys(self):
        """Load API keys from the JSON file"""
        if os.path.exists(self.keys_file):
            with open(self.keys_file, 'r') as f:
                self.data = json.load(f)
        else:
            # Create default structure if file doesn't exist
            self.data = {"keys": [], "key_status": {}}
    
    def save_keys(self):
        """Save API keys to the JSON file"""
        with open(self.keys_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def get_active_key(self):
        """Get an active API key with lowest usage count"""
        keys = self.data.get('keys', [])
        key_status = self.data.get('key_status', {})
        
        # Find active keys or activate all if none are active
        active_keys = []
        for key in keys:
            status = key_status.get(key, {})
            if status.get('is_active', True):  # Default to True if not specified
                active_keys.append(key)
        
        if not active_keys:
            # If no active keys, activate all keys
            for key in keys:
                if key not in key_status:
                    key_status[key] = {}
                key_status[key]['is_active'] = True
            active_keys = keys.copy()
            self.save_keys()
        
        if not active_keys:
            return None
        
        # Sort by usage count (ascending) and return the least used key
        active_keys.sort(key=lambda k: key_status.get(k, {}).get('usage_count', 0))
        return active_keys[0]
    
    def mark_key_used(self, api_key):
        """Mark an API key as used and update usage statistics"""
        if api_key not in self.data.get('key_status', {}):
            self.data['key_status'][api_key] = {}
        
        self.data['key_status'][api_key]['last_used'] = datetime.now().isoformat()
        self.data['key_status'][api_key]['usage_count'] = self.data['key_status'][api_key].get('usage_count', 0) + 1
        self.save_keys()
    
    def mark_key_inactive(self, api_key, reason="quota_exceeded"):
        """Mark an API key as inactive due to quota issues"""
        if api_key not in self.data.get('key_status', {}):
            self.data['key_status'][api_key] = {}
        
        self.data['key_status'][api_key]['is_active'] = False
        self.data['key_status'][api_key]['deactivated_at'] = datetime.now().isoformat()
        self.data['key_status'][api_key]['deactivation_reason'] = reason
        self.save_keys()
    
    def reactivate_all_keys(self):
        """Reactivate all keys (useful for daily quota reset)"""
        for key in self.data.get('keys', []):
            if key not in self.data.get('key_status', {}):
                self.data['key_status'][key] = {}
            self.data['key_status'][key]['is_active'] = True
        self.save_keys()

def generate_quiz_questions(topic, num_questions=10, difficulty='medium', max_retries=3):
    """Generate quiz questions using AI with API key rotation
    
    Args:
        topic (str): The topic for the quiz questions
        num_questions (int): Number of questions to generate (5-50)
        difficulty (str): Difficulty level - 'easy', 'medium', 'hard', or 'mixed'
        max_retries (int): Maximum number of retry attempts
        
    Returns:
        list: List of question dictionaries or None if generation fails
    """
    key_manager = APIKeyManager()
    
    # Define difficulty descriptions
    difficulty_descriptions = {
        'easy': 'Beginner level questions with straightforward concepts and answers',
        'medium': 'Intermediate level questions that require some knowledge and understanding',
        'hard': 'Advanced level questions that test in-depth knowledge and application',
        'mixed': 'A mix of easy, medium, and hard questions (distributed evenly)'
    }
    
    difficulty_instruction = difficulty_descriptions.get(difficulty, difficulty_descriptions['medium'])
    
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
    
    for attempt in range(max_retries):
        try:
            api_key = key_manager.get_active_key()
            if not api_key:
                raise Exception("No active API keys available")
            
            # Configure the API with the current key
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            response = model.generate_content(prompt)
            key_manager.mark_key_used(api_key)
            
            # Clean the response to extract JSON
            response_text = response.text.strip()
            
            # Remove any markdown code blocks
            import re
            
            # First, try to extract from code blocks
            json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(1).strip()
            else:
                json_text = response_text
            
            # Remove any remaining markdown formatting
            json_text = re.sub(r'^```.*?$', '', json_text, flags=re.MULTILINE)
            json_text = json_text.strip()
            
            # If it starts and ends with array brackets, it's likely the JSON we want
            if json_text.startswith('[') and json_text.endswith(']'):
                pass  # Good format
            elif json_text.startswith('{') and json_text.endswith('}'):
                # Might be wrapped in an object
                pass
            else:
                # Try to find JSON array in the text
                array_match = re.search(r'\[.*\]', json_text, re.DOTALL)
                if array_match:
                    json_text = array_match.group(0)
            
            print(f"Attempt {attempt + 1} - Cleaned JSON text (first 200 chars):")
            print(json_text[:200] + "..." if len(json_text) > 200 else json_text)
            
            # Parse the JSON
            questions_list = json.loads(json_text)
            
            # Validate the structure
            if isinstance(questions_list, dict) and 'questions' in questions_list:
                questions_list = questions_list['questions']
            
            if not isinstance(questions_list, list):
                raise ValueError("Expected a list of questions")
            
            # Validate each question
            validated_questions = []
            for i, question in enumerate(questions_list):
                if not isinstance(question, dict):
                    continue
                
                if 'question_text' not in question or 'options' not in question or 'correct_answer' not in question:
                    continue
                
                options = question['options']
                if isinstance(options, dict):
                    options = list(options.values())
                
                if len(options) != 4:
                    continue
                
                # Clean up question text (remove problematic characters)
                question_text = question['question_text'].replace('```', '').replace('\n```', '').strip()
                
                # Ensure correct_answer matches one of the options
                correct_answer = question['correct_answer']
                if correct_answer not in options:
                    # Try to find the closest match
                    for option in options:
                        if option.lower().strip() == correct_answer.lower().strip():
                            correct_answer = option
                            break
                    else:
                        # If no match found, skip this question
                        continue
                
                validated_questions.append({
                    'question_text': question_text,
                    'options': options,
                    'correct_answer': correct_answer
                })
            
            if len(validated_questions) >= min(3, int(num_questions) // 2):  # At least half or 3 questions
                return validated_questions
            else:
                raise ValueError(f"Only {len(validated_questions)} valid questions generated, expected {num_questions}")
                
        except json.JSONDecodeError as e:
            print(f"JSON parsing error on attempt {attempt + 1}: {e}")
            print(f"Response text: {response_text[:500]}...")
            
        except Exception as e:
            error_msg = str(e).lower()
            print(f"Error on attempt {attempt + 1}: {e}")
            
            # Check for quota-related errors
            if any(keyword in error_msg for keyword in ['quota', 'limit', '429', 'rate limit']):
                if api_key:
                    key_manager.mark_key_inactive(api_key, "quota_exceeded")
                    print(f"Marked API key as inactive due to quota: {api_key[:10]}...")
                
            if attempt == max_retries - 1:
                raise e
    
    raise Exception(f"Failed to generate questions after {max_retries} attempts")
