# Quzo feature inventory and implementation roadmap

Quzo helps professors author, deliver, and grade multiple-choice assessments. Students sign in to take quizzes and see reports after the professor releases them. Gemini assists with question authoring. Scoring runs in Flask using the answer key and configured marks.

**Reviewed version.** The local checkout is at `6819ab5`. The application, models, configuration, Gemini client, quiz-taking template, and dependency manifest match their file hashes on GitHub’s `main`. Features below are verified by source inspection. Live Gemini, browser, and deployment behavior still need runtime verification. [GitHub repository](https://github.com/shlok-0007/Quzo)

## Implemented features

| Area | What the code supports | Source |
|---|---|---|
| Professor and student accounts | Registration, login, logout, role-based dashboards, and password recovery using a security question. Registration validates key fields and checks for duplicate accounts. | [Account routes](app1.py#L287), [user model](models.py#L21) |
| Manual quiz authoring | Create, edit, and delete quizzes and questions. Configure multiple-choice options, question images, time limits, deadlines, access codes, and marks for correct and incorrect answers. | [Create quiz](app1.py#L890), [edit quiz](app1.py#L1094) |
| AI-assisted authoring | Professors request topic-based multiple-choice questions from Gemini, choose a difficulty, review the generated questions, and select which ones to save as a quiz. | [AI route](app1.py#L491), [authoring template](templates/ai_quiz_generator.html) |
| Student quiz access | The student dashboard lists quizzes and past attempts. A quiz can require a professor-managed code before entry. | [Access code flow](app1.py#L714), [student dashboard](app1.py#L1453) |
| Timed attempts | The server records quiz sessions and shuffles the question order. The browser displays a countdown, saves answers, warns before leaving with an active attempt, and submits when time runs out. The server applies quiz deadlines and session timing checks. | [Attempt flow](app1.py#L1555), [session model](models.py#L132), [quiz template](templates/take_quiz.html) |
| Quiz edits during attempts | The student UI polls for updates and marks questions as seen. The server reconciles the saved question list as the quiz changes. | [Update endpoints](app1.py#L1031), [session reconciliation](app1.py#L1832) |
| Scoring and reports | Multiple-choice grading uses the configured marks. Professors can inspect analytics and individual reports, export results as CSV or individual PDFs, and control when detailed reports are released to students. | [Scoring](app1.py#L134), [PDF export](app1.py#L633), [CSV export](app1.py#L742), [reports](app1.py#L1328), [analytics](app1.py#L2129) |
| Regrade and retry | Professors can regrade a quiz, inspect the regrade log, and reset individual or all student attempts for a quiz. | [Regrade](app1.py#L1281), [attempt resets](app1.py#L1483) |
| Deployment and storage | Flask/Jinja templates and browser JavaScript serve the UI. SQLAlchemy models store accounts, questions, attempts, answers, results, and regrade logs. SQLite is the local fallback and PostgreSQL URLs are supported for persistent deployment. | [Models](models.py), [settings](config.py), [setup guide](README.md) |

In the reviewed student flow, a question can display an image uploaded by the professor. The student submits a multiple-choice option. Student drawing, free-text grading, and answer attachments would each need their own input, persistence, and grading workflow. [Question model](models.py#L72) · [Student quiz form](templates/take_quiz.html)

## How the Gemini integration works

1. A professor opens the generator and supplies a topic, a requested count from 1 to 50, and easy, medium, hard, or mixed difficulty.
2. The server asks Gemini for a structured list of question text, four options, correct answer, and difficulty. The model is configurable using `GEMINI_MODEL`.
3. The generator extracts JSON and filters invalid questions. It checks the number of choices and matches the correct answer to an actual option. A request can return fewer valid questions than requested.
4. When the professor saves the selected questions, the route matches the answer to its option letter and saves the quiz and valid questions in a transaction.
5. The key manager uses `GEMINI_API_KEYS` or `GEMINI_API_KEY`, with a git-ignored local key-file fallback. The generator has bounded retries and key rotation. Manual quiz authoring works independently of Gemini. [Gemini client and validation](api_utils.py) · [Key administration](manage_keys.py)

The existing prompt asks for structured output, but its response still needs review for factual accuracy, difficulty, and ambiguous choices. Quiz creation accepts the selected question payloads from the form, so apply the same strict validation on generation and save paths when hardening this feature. Preserve the professor’s selection and review step. [Generation and save paths](app1.py#L491)

## Security and assessment controls in the code

| Control | Current coverage |
|---|---|
| Credential storage | Werkzeug hashes passwords and normalized security answers. |
| Session handling | Flask-signed cookies with HttpOnly and SameSite=Lax. The Secure flag is configurable and enabled on Vercel. Login and logout clear session state at the relevant transitions. |
| Role and resource checks | Route decorators distinguish logged-in users, professors, and students. Professor quiz operations use an ownership helper. Access codes are separate from account authentication. |
| Upload handling | Question image uploads use sanitized filenames and a 16 MB request limit. The app stores media in a configured directory and serves it through an upload route. |
| Exam controls | Timers, independently shuffled question order, autosave, and controlled report release are present. Webcam monitoring, OpenCV motion recognition, and browser lockdown are absent from this checkout. |
| Error views | Custom 403, 404, and 500 templates are included. |

[Authorization and upload helpers](app1.py#L100) · [Credential model](models.py#L21) · [Cookie and upload configuration](config.py#L37)

## Implementation backlog

| Priority | Feature | Implementation and acceptance criteria |
|---|---|---|
| P0 | CSRF protection | Wire application-wide verification to mutating forms and JSON requests. The quiz template has a conditional token reference, while the backend has no global verifier in this checkout. Move state-changing GET actions to protected POST handlers. Add tests for valid, missing, and invalid tokens. |
| P0 | Session and secret configuration | Fail closed outside development when the session secret is absent. Require secure cookies on HTTPS and define session expiration and invalidation after password changes. Test session behavior at login, reset, and logout. |
| P0 | Account recovery and abuse prevention | Replace security-question recovery with expiring, single-use reset links and generic responses. Apply rate limits to authentication, reset, quiz-code entry, and AI generation. Define who may register as a professor and enforce the policy server-side. |
| P0 | Authorization regression tests | Test ownership for edits, exports, regrades, resets, and reports. Verify students can submit and read only their own eligible attempts. Keep timing, question membership, and allowed attempt state authoritative on the server. |
| P1 | Upload and export hardening | Restrict upload types and validate actual image content. Use persistent storage and enforce intended access. Protect spreadsheet exports from formula interpretation and test filenames, oversized requests, and private media reads. |
| P1 | AI output quality and cost | Validate a strict schema on both generation and save. Reject duplicates, placeholder choices, and ambiguous answers. Make the generated count and any validation losses visible to the professor. Add timeouts, per-user usage limits, mocked provider tests, and redacted error reporting. |
| P1 | Assessment reliability | Test reconnects, duplicate submits, expired attempts, concurrent quiz edits, and regrading. Ensure finalization persists one result and records which question version the score used. |
| P2 | Additional AI features | Pilot curriculum-aligned question drafts and optional answer explanations. Let professors review and approve both. Release explanations with results according to the existing report policy. Measure instructor editing time and answer accuracy before wider use. |
| P2 | Exam integrity signals | If instructors need more than timing and access controls, define a consent-based, accessible policy. Treat browser focus or webcam signals as review cues with a human decision and documented retention. Verify any claimed monitoring capability end to end. |
| P2 | Deployment maintenance | Add a repeatable schema migration workflow, CI tests, and backup/restore checks. Use a deployed database and durable object storage for records and media that must survive a restart. |

## Delivery sequence and verification

### Current implementation branch

Global CSRF protection covers forms and JSON writes. Logout, quiz start, and explicit timeout finalization use POST. Account recovery uses timed single-use email links, existing sessions are bound to the current password version, and new professor accounts require a configured invitation. A database-backed quota limits sensitive requests. Gemini generation and quiz save now share validation, and generation uses bounded calls with generic errors. Question image delivery checks the teacher’s ownership or the student’s attempt. New media is decoded and re-encoded before storage. Quiz scoring still uses the configured answer key.

The branch adds a local test baseline. Live SMTP and Gemini, PostgreSQL concurrency, and image processing need staging verification. Object storage, versioned migrations, CI and backup automation, scoring against immutable question versions, new AI explanations and curriculum workflows, and proctoring are still open.

1. **Establish a test baseline.** Use a temporary database and separate test secrets. Add a professor and a student fixture and cover manual quiz creation, enrollment by code, submission, release, and access to the published report. Run the same smoke flow on PostgreSQL before a deployment.
2. **Secure account and quiz operations.** Add protected POST handling and CSRF coverage, then test every professor write and export with a second professor’s account. Converge on one server-side check for an eligible attempt, valid question membership, remaining time, and finalization. Verify duplicate submission leaves a single result.
3. **Harden the current Gemini flow.** Share a schema between response parsing and quiz save, and return a useful message when the provider is unavailable. Test valid output, invalid JSON, duplicate choices, a missing answer, an undersized response, and a provider timeout using a mock. Run a dedicated live check with an approved test key before release.
4. **Evaluate new assessment capabilities.** Prioritize answer explanations and instructor feedback after the existing release gate is tested. Add new question types or proctoring only after defining how they affect accessibility, review, scoring, and data retention.

| Smoke check | Expected behavior |
|---|---|
| Professor creates a manual quiz with positive and negative marks | The student sees the configured quiz and the server grades the selected options using that scheme. |
| Student refreshes mid-attempt and later reaches the limit | Saved answers and the question order survive a refresh. Timeout finalizes the attempt without granting extra time. |
| Professor regrades, releases, and exports | Regrade updates the stored result and records an audit entry. Released reports and exports match the stored results. |
| A different professor requests somebody else’s quiz data | The request is rejected. The response contains no student answers or report data. |
| Gemini returns invalid output or times out | The author sees a recoverable failure and can still create a quiz manually. Invalid questions are excluded from persistence. |

The reviewed implementation uses Flask, Jinja, SQLAlchemy, SQLite or PostgreSQL, and the Gemini SDK. [Dependencies](requirements.txt) · [Application entry point](wsgi.py)
