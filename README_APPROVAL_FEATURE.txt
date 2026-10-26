LEARNING MANAGEMENT SYSTEM - CANDIDATE APPROVAL UPDATE

New features:
- Candidate registration creates a PENDING account.
- Pending/rejected candidates cannot log in.
- Admin dashboard shows pending approval count.
- Admin > Manage Candidates & Progress shows Candidate ID, name, email, registration date, login count, last login, and course progress.
- Admin can approve or reject candidates.
- Admin can reset a candidate password (passwords are stored hashed and cannot be displayed in plaintext).
- Admin can permanently delete a candidate and their login history/progress (foreign keys use cascade in the supplied schema).
- Existing databases are upgraded automatically by app.py by adding candidates.status if missing.

IMPORTANT:
1. Back up your existing database and uploaded MP4 videos before replacing any project files.
2. Do not overwrite your config.py without keeping your MySQL credentials and secret key.
3. Existing candidates will be marked PENDING after the new status column is added. Log in as admin and approve the accounts that should continue to have access.
4. If you prefer manual migration, use UPGRADE_EXISTING_DATABASE.sql. Do not run its ALTER TABLE command if the status column already exists.
5. Admin cannot see old candidate passwords. This is intentional; use Reset password to set a new one.
6. This update was syntax-checked, but it has not been end-to-end tested against your local MySQL instance/browser.

Run on Windows PowerShell from this project folder:
  .\venv\Scripts\Activate.ps1
  python -m pip install -r requirements.txt
  python app.py

Open http://127.0.0.1:5000/
