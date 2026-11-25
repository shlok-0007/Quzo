import json
import os
import re

import pytest

from api_utils import validate_questions


@pytest.fixture(scope='module')
def quzo(tmp_path_factory):
    with pytest.MonkeyPatch.context() as patch:
        folder = tmp_path_factory.mktemp('quzo')
        database = os.environ.get('QUZO_TEST_DATABASE_URL') or f'sqlite:///{(folder / "test.db").as_posix()}'
        patch.setenv('DATABASE_URL', database)
        patch.setenv('UPLOAD_FOLDER', str(folder / 'uploads'))
        patch.setenv('SECRET_KEY', 'quzo-test-session-key')
        patch.setenv('QUZO_PROFESSOR_INVITE', 'test-invitation')
        patch.delenv('VERCEL', raising=False)
        patch.delenv('AWS_LAMBDA_FUNCTION_NAME', raising=False)
        import app1

        app1.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False)
        yield app1


def token(client):
    response = client.get('/login')
    return re.search(rb'<meta name="csrf-token" content="([^"]+)">', response.data)[1].decode()


def sign_in(client, username, password='Example1!'):
    return client.post('/login', data={
        '_csrf_token': token(client), 'username': username, 'password': password,
    })


def with_token(client, data=None):
    with client.session_transaction() as state:
        return dict(data or {}, _csrf_token=state['_csrf_token'])


def test_csrf_blocks_missing_and_wrong_tokens(quzo):
    client = quzo.app.test_client()
    assert client.post('/login').status_code == 400
    token(client)
    assert client.post('/login', data={'_csrf_token': 'wrong'}).status_code == 400
    assert client.get('/logout').status_code == 405


def test_protected_quiz_attempt_and_results(quzo):
    from models import Question, Quiz, QuizSession, Result, User, db

    with quzo.app.app_context():
        for username, role in [('teacher', 'professor'), ('other-teacher', 'professor'), ('student', 'student')]:
            user = User(username=username, email=f'{username}@example.test', role=role)
            user.set_password('Example1!')
            db.session.add(user)
        db.session.flush()
        quiz = Quiz(title='Math', professor_id=User.query.filter_by(username='teacher').one().id,
                    access_code='test', marks_correct=4, marks_incorrect=-1)
        db.session.add(quiz)
        db.session.flush()
        question = Question(quiz_id=quiz.id, text='2 + 2', option_a='1', option_b='4',
                            option_c='2', option_d='3', correct_option='b')
        db.session.add(question)
        db.session.commit()
        quiz_id, question_id = quiz.id, question.id

    student = quzo.app.test_client()
    sign_in(student, 'student')
    access = f'/student/quiz/{quiz_id}/access'
    take = f'/student/quiz/{quiz_id}/take'
    assert student.get(access).status_code == 200
    assert student.post(f'/submit_quiz/{quiz_id}', data=with_token(student)).location.endswith('/access')
    with quzo.app.app_context():
        assert QuizSession.query.count() == 0
    assert student.post(access, data=with_token(student, {'access_code': 'wrong'})).status_code == 200
    assert student.post(access, data=with_token(student, {'access_code': 'test'})).location.endswith('/take')
    assert student.get(take).status_code == 200
    assert student.post(f'/quiz/{quiz_id}/auto_submit', data=with_token(student)).status_code == 409
    csrf = with_token(student)['_csrf_token']
    saved = student.post('/save_answer', json={
        'quiz_id': quiz_id, 'question_id': question_id, 'selected_option': 'b',
    }, headers={'X-CSRFToken': csrf})
    assert saved.status_code == 200
    assert student.post(take, data=with_token(student)).status_code == 302
    assert student.post(take, data=with_token(student)).status_code == 302
    with quzo.app.app_context():
        assert Result.query.one().score == 4
    report = f'/student/quiz/{quiz_id}/report'
    assert student.get(report).location.endswith('/dashboard')
    teacher = quzo.app.test_client()
    sign_in(teacher, 'teacher')
    assert teacher.get('/professor/dashboard').status_code == 200
    release = f'/professor/quiz/{quiz_id}/release_report'
    assert teacher.post(release, data=with_token(teacher)).status_code == 302
    assert student.get(report).status_code == 200
    assert teacher.get(f'/professor/quiz/{quiz_id}/export').content_type.startswith('text/csv')
    other = quzo.app.test_client()
    sign_in(other, 'other-teacher')
    assert other.get(f'/professor/quiz/{quiz_id}/export').status_code == 403


def test_password_reset_is_single_use_and_revokes_session(quzo):
    from models import User, db

    with quzo.app.app_context():
        user = User(username='recovery-student', email='recovery@example.test', role='student')
        user.set_password('Example1!')
        db.session.add(user)
        db.session.commit()
        recovery_token = quzo._recovery_serializer().dumps([user.id, quzo._credential_version(user)])
    original = quzo.app.test_client()
    assert sign_in(original, 'recovery-student').location.endswith('/dashboard')
    recovery = quzo.app.test_client()
    path = f'/reset-password/{recovery_token}'
    assert recovery.get(path).status_code == 200
    assert recovery.post(path, data=with_token(recovery, {
        'password': 'Updated1!', 'confirm_password': 'Updated1!',
    })).location.endswith('/login')
    assert recovery.get(path).status_code == 400
    assert original.get('/student/dashboard').location.endswith('/login')
    assert sign_in(recovery, 'recovery-student', 'Updated1!').location.endswith('/dashboard')


def test_ai_validation_filters_duplicates_and_invalid_answers(monkeypatch, tmp_path):
    import api_utils

    valid = {'question_text': 'Capital of Japan?', 'options': ['Tokyo', 'Osaka', 'Kyoto', 'Nagoya'],
             'correct_answer': 'tokyo'}
    duplicate_options = dict(valid, options=['Tokyo', 'tokyo', 'Kyoto', 'Nagoya'])
    wrong = dict(valid, correct_answer='Paris')
    assert validate_questions([duplicate_options, wrong, valid, valid]) == [
        dict(valid, correct_answer='Tokyo')
    ]
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('GEMINI_API_KEY', 'test-key')
    monkeypatch.setattr(api_utils, '_request_questions', lambda *_: json.dumps([wrong, valid]))
    assert api_utils.generate_quiz_questions('Geography', 2)[0]['correct_answer'] == 'Tokyo'
    assert not (tmp_path / 'api_keys.json').exists()
