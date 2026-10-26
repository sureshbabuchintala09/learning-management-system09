
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort
)
import mysql.connector
from mysql.connector import Error
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid
from urllib.parse import urlparse, parse_qs
from flask import send_file
from flask_wtf.csrf import CSRFProtect

from config import (
    DB_CONFIG,
    SECRET_KEY,
    UPLOAD_FOLDER,
    MAX_CONTENT_LENGTH,
    SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE,
)


app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SESSION_COOKIE_HTTPONLY"] = SESSION_COOKIE_HTTPONLY
app.config["SESSION_COOKIE_SAMESITE"] = SESSION_COOKIE_SAMESITE
app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE

# Protect every POST/PUT/PATCH/DELETE request against CSRF.
csrf = CSRFProtect(app)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def get_db_connection():
    """Create and return a MySQL database connection."""
    return mysql.connector.connect(**DB_CONFIG)


def ensure_candidate_approval_column(cursor):
    """Backward-compatible migration for databases created before approval workflow."""
    cursor.execute("""
        SELECT COUNT(*) AS column_exists
        FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'candidates'
          AND COLUMN_NAME = 'status'
    """)
    row = cursor.fetchone()
    exists = row.get("column_exists", 0) if isinstance(row, dict) else row[0]
    if not exists:
        cursor.execute("ALTER TABLE candidates ADD COLUMN status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending' AFTER password_hash")



def login_required(role=None):
    """Protect routes that require an authenticated user."""
    def decorator(view_function):
        @wraps(view_function)
        def wrapped_view(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                abort(403)

            return view_function(*args, **kwargs)

        return wrapped_view
    return decorator


@app.route("/")
def home():
    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if session.get("role") == "candidate":
        return redirect(url_for("candidate_dashboard"))

    return redirect(url_for("login"))



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT id, username, password_hash "
                "FROM admins WHERE username = %s",
                (username,)
            )
            admin = cursor.fetchone()

            cursor.close()
            conn.close()

            if admin and check_password_hash(
                admin["password_hash"], password
            ):
                session.clear()
                session["user_id"] = admin["id"]
                session["username"] = admin["username"]
                session["role"] = "admin"

                flash("Admin login successful!", "success")
                return redirect(url_for("admin_dashboard"))

            flash("Invalid username or password.", "danger")

        except Error as e:
            app.logger.error("Admin login database error: %s", e)
            flash("Database connection error. Check MySQL settings.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        candidate_code = request.form.get("candidate_code", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not all([candidate_code, full_name, email, password]):
            flash("Please fill in all fields.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("register.html")

        password_hash = generate_password_hash(password)

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            ensure_candidate_approval_column(cursor)

            cursor.execute(
                """
                INSERT INTO candidates
                    (candidate_code, full_name, email, password_hash, status)
                VALUES (%s, %s, %s, %s, 'pending')
                """,
                (candidate_code, full_name, email, password_hash)
            )

            conn.commit()
            cursor.close()
            conn.close()

            flash("Registration submitted. Please wait for admin approval before logging in.", "success")
            return redirect(url_for("candidate_login"))

        except Error as e:
            app.logger.error("Candidate registration error: %s", e)
            flash(
                "Registration failed. Candidate code or email may already exist.",
                "danger"
            )

    return render_template("register.html")


@app.route("/candidate/login", methods=["GET", "POST"])
def candidate_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            ensure_candidate_approval_column(cursor)

            cursor.execute(
                """
                SELECT id, candidate_code, full_name, email, password_hash, status
                FROM candidates
                WHERE email = %s
                """,
                (email,)
            )
            candidate = cursor.fetchone()

            if candidate and check_password_hash(
                candidate["password_hash"], password
            ):
                ensure_candidate_approval_column(cursor)
                # Refresh status after applying a possible migration.
                cursor.execute("SELECT status FROM candidates WHERE id = %s", (candidate["id"],))
                status_row = cursor.fetchone()
                status = status_row["status"] if status_row else "pending"
                if status != "approved":
                    cursor.close()
                    conn.close()
                    if status == "rejected":
                        flash("Your registration was not approved. Please contact the administrator.", "danger")
                    else:
                        flash("Your registration is pending admin approval. Please try again after approval.", "warning")
                    return render_template("candidate_login.html")
                session.clear()
                session["user_id"] = candidate["id"]
                session["username"] = candidate["full_name"]
                session["role"] = "candidate"

                cursor.execute(
                    "INSERT INTO login_history (candidate_id) VALUES (%s)",
                    (candidate["id"],)
                )
                conn.commit()

                cursor.close()
                conn.close()

                flash("Login successful!", "success")
                return redirect(url_for("candidate_dashboard"))

            cursor.close()
            conn.close()
            flash("Invalid email or password.", "danger")

        except Error as e:
            app.logger.error("Candidate login database error: %s", e)
            flash("Database connection error. Check MySQL settings.", "danger")

    return render_template("candidate_login.html")

@app.route("/admin/dashboard")
@login_required("admin")
def admin_dashboard():
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT c.id, c.course_name, c.description, c.created_at,
                   COUNT(v.id) AS video_count
            FROM courses c
            LEFT JOIN videos v ON v.course_id = c.id
            GROUP BY c.id, c.course_name, c.description, c.created_at
            ORDER BY c.id DESC
        """)
        courses = cursor.fetchall()

        ensure_candidate_approval_column(cursor)
        cursor.execute("SELECT COUNT(*) AS total FROM candidates")
        candidate_count = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) AS total FROM candidates WHERE status = 'pending'")
        pending_candidate_count = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS total FROM videos")
        video_count = cursor.fetchone()["total"]

        return render_template(
            "admin_dashboard.html",
            courses=courses,
            candidate_count=candidate_count,
            pending_candidate_count=pending_candidate_count,
            video_count=video_count
        )

    except Error as e:
        app.logger.error("Admin dashboard error: %s", e)
        flash("Could not load dashboard. Check the database.", "danger")
        return render_template(
            "admin_dashboard.html",
            courses=[],
            candidate_count=0,
            pending_candidate_count=0,
            video_count=0
        )

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/admin/candidates")
@login_required("admin")
def admin_candidates():
    """Show candidate login activity and per-course progress to admins."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        ensure_candidate_approval_column(cursor)

        cursor.execute("""
            SELECT c.id, c.candidate_code, c.full_name, c.email, c.created_at, c.status,
                   COALESCE(l.login_count, 0) AS login_count,
                   l.last_login
            FROM candidates c
            LEFT JOIN (
                SELECT candidate_id, COUNT(*) AS login_count,
                       MAX(login_at) AS last_login
                FROM login_history
                GROUP BY candidate_id
            ) l ON l.candidate_id = c.id
            ORDER BY l.last_login DESC, c.full_name ASC
        """)
        candidates = cursor.fetchall()

        cursor.execute("""
            SELECT c.id AS candidate_id, co.id AS course_id,
                   co.course_name,
                   COUNT(v.id) AS total_videos,
                   SUM(CASE WHEN vp.completed = 1 THEN 1 ELSE 0 END) AS completed_videos
            FROM candidates c
            CROSS JOIN courses co
            LEFT JOIN videos v ON v.course_id = co.id
            LEFT JOIN video_progress vp
                   ON vp.video_id = v.id AND vp.candidate_id = c.id
            GROUP BY c.id, co.id, co.course_name
            ORDER BY co.course_name ASC
        """)
        progress_rows = cursor.fetchall()

        progress_by_candidate = {}
        for row in progress_rows:
            total = int(row["total_videos"] or 0)
            completed = int(row["completed_videos"] or 0)
            row["percentage"] = round(completed * 100 / total) if total else 0
            progress_by_candidate.setdefault(row["candidate_id"], []).append(row)

        for candidate in candidates:
            candidate["course_progress"] = progress_by_candidate.get(candidate["id"], [])

        return render_template("admin_candidates.html", candidates=candidates)
    except Error as e:
        app.logger.error("Admin candidate report error: %s", e)
        flash("Could not load candidate progress. Check the database.", "danger")
        return redirect(url_for("admin_dashboard"))
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/admin/candidates/<int:candidate_id>/status", methods=["POST"])
@login_required("admin")
def admin_update_candidate_status(candidate_id):
    status = request.form.get("status", "").strip()
    if status not in {"approved", "rejected", "pending"}:
        flash("Invalid candidate status.", "danger")
        return redirect(url_for("admin_candidates"))
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        ensure_candidate_approval_column(cursor)
        cursor.execute("UPDATE candidates SET status = %s WHERE id = %s", (status, candidate_id))
        if cursor.rowcount:
            conn.commit()
            flash(f"Candidate status updated to {status}.", "success")
        else:
            conn.rollback()
            flash("Candidate not found.", "danger")
    except Error as e:
        if conn and conn.is_connected(): conn.rollback()
        app.logger.error("Candidate status update error: %s", e)
        flash("Could not update candidate status.", "danger")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/delete", methods=["POST"])
@login_required("admin")
def admin_delete_candidate(candidate_id):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM candidates WHERE id = %s", (candidate_id,))
        if cursor.rowcount:
            conn.commit()
            flash("Candidate and related progress/login history deleted.", "success")
        else:
            conn.rollback()
            flash("Candidate not found.", "danger")
    except Error as e:
        if conn and conn.is_connected(): conn.rollback()
        app.logger.error("Candidate deletion error: %s", e)
        flash("Could not delete candidate. Check foreign-key settings.", "danger")
    finally:
        if cursor: cursor.close()
        if conn and conn.is_connected(): conn.close()
    return redirect(url_for("admin_candidates"))


@app.route("/admin/candidates/<int:candidate_id>/reset-password", methods=["POST"])
@login_required("admin")
def admin_reset_candidate_password(candidate_id):
    """Allow an authenticated admin to set a new candidate password."""
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "danger")
        return redirect(url_for("admin_candidates"))

    if new_password != confirm_password:
        flash("The passwords do not match. Please try again.", "danger")
        return redirect(url_for("admin_candidates"))

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE candidates SET password_hash = %s WHERE id = %s",
            (generate_password_hash(new_password), candidate_id)
        )
        if cursor.rowcount == 0:
            conn.rollback()
            flash("Candidate was not found; password was not changed.", "danger")
        else:
            conn.commit()
            flash("Candidate password reset successfully. Share the new password securely with the candidate.", "success")
    except Error as e:
        if conn and conn.is_connected():
            conn.rollback()
        app.logger.error("Candidate password reset error: %s", e)
        flash("Could not reset candidate password. Check the database.", "danger")
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("admin_candidates"))


@app.route("/admin/courses/add", methods=["POST"])
@login_required("admin")
def add_course():
    course_name = request.form.get("course_name", "").strip()
    description = request.form.get("description", "").strip()

    if not course_name:
        flash("Course name is required.", "danger")
        return redirect(url_for("admin_dashboard"))

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO courses (course_name, description) VALUES (%s, %s)",
            (course_name, description)
        )
        conn.commit()
        flash("Course added successfully!", "success")

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Add course error: %s", e)
        flash("Could not add course.", "danger")

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/courses/edit/<int:course_id>", methods=["GET", "POST"])
@login_required("admin")
def edit_course(course_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        if request.method == "POST":
            course_name = request.form.get("course_name", "").strip()
            description = request.form.get("description", "").strip()

            if not course_name:
                flash("Course name is required.", "danger")
            else:
                cursor.execute(
                    """
                    UPDATE courses
                    SET course_name = %s, description = %s
                    WHERE id = %s
                    """,
                    (course_name, description, course_id)
                )
                conn.commit()
                flash("Course updated successfully!", "success")
                return redirect(url_for("admin_dashboard"))

        cursor.execute("SELECT * FROM courses WHERE id = %s", (course_id,))
        course = cursor.fetchone()

        if not course:
            abort(404)

        return render_template("edit_course.html", course=course)

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Edit course error: %s", e)
        flash("Could not edit course.", "danger")
        return redirect(url_for("admin_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/admin/courses/delete/<int:course_id>", methods=["POST"])
@login_required("admin")
def delete_course(course_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM courses WHERE id = %s", (course_id,))
        conn.commit()

        if cursor.rowcount:
            flash("Course deleted successfully.", "success")
        else:
            flash("Course not found.", "danger")

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Delete course error: %s", e)
        flash(
            "Could not delete course. Check related video/progress records.",
            "danger"
        )

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

    return redirect(url_for("admin_dashboard"))

ALLOWED_VIDEO_EXTENSIONS = {"mp4"}
YOUTUBE_HOSTS = {"youtube.com", "www.youtube.com", "youtu.be", "www.youtube-nocookie.com"}


def is_valid_youtube_url(url):
    """Accept HTTPS YouTube watch, short, or embed URLs only."""
    try:
        parsed = urlparse((url or "").strip())
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or host not in YOUTUBE_HOSTS:
            return False
        if parsed.username or parsed.password:
            return False
        if host == "youtu.be":
            return bool(parsed.path.strip("/"))
        if parsed.path == "/watch":
            return bool(parse_qs(parsed.query).get("v", [""])[0])
        if parsed.path.startswith("/embed/") or parsed.path.startswith("/shorts/"):
            return bool(parsed.path.split("/")[-1])
        return False
    except (TypeError, ValueError):
        return False


def looks_like_mp4(file_storage):
    """Basic MP4 signature check; this is not a full malware/media scan."""
    try:
        file_storage.stream.seek(0)
        header = file_storage.stream.read(12)
        file_storage.stream.seek(0)
        return len(header) >= 12 and header[4:8] == b"ftyp"
    except (AttributeError, OSError):
        return False


@app.route("/admin/courses/<int:course_id>/videos", methods=["GET", "POST"])
@login_required("admin")
def manage_videos(course_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM courses WHERE id = %s", (course_id,))
        course = cursor.fetchone()

        if not course:
            abort(404)

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            video_type = request.form.get("video_type", "").strip()
            sequence_raw = request.form.get("sequence_no", "").strip()
            video_url = request.form.get("video_url", "").strip()
            video_file = request.files.get("video_file")

            if not title or video_type not in {"youtube", "mp4"}:
                flash("Enter a title and valid video type.", "danger")
                return redirect(url_for("manage_videos", course_id=course_id))

            try:
                sequence_no = int(sequence_raw)
                if sequence_no < 1:
                    raise ValueError
            except ValueError:
                flash("Sequence number must be a positive integer.", "danger")
                return redirect(url_for("manage_videos", course_id=course_id))

            if video_type == "youtube":
                if not is_valid_youtube_url(video_url):
                    flash("Enter a valid HTTPS YouTube URL.", "danger")
                    return redirect(url_for("manage_videos", course_id=course_id))
                saved_url = video_url

            else:
                if not video_file or not video_file.filename:
                    flash("Choose an MP4 file to upload.", "danger")
                    return redirect(url_for("manage_videos", course_id=course_id))

                filename = secure_filename(video_file.filename)
                if not filename or not filename.lower().endswith(".mp4"):
                    flash("Only MP4 files are allowed.", "danger")
                    return redirect(url_for("manage_videos", course_id=course_id))

                if not looks_like_mp4(video_file):
                    flash("The uploaded file does not appear to be a valid MP4 video.", "danger")
                    return redirect(url_for("manage_videos", course_id=course_id))

                # Use a unique filename to avoid overwriting existing uploads.
                filename = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                video_file.save(filepath)
                saved_url = filename

            cursor.execute(
                """
                INSERT INTO videos
                    (course_id, title, video_url, sequence_no, video_type)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (course_id, title, saved_url, sequence_no, video_type)
            )
            conn.commit()
            flash("Video added successfully!", "success")
            return redirect(url_for("manage_videos", course_id=course_id))

        cursor.execute(
            """
            SELECT * FROM videos
            WHERE course_id = %s
            ORDER BY sequence_no ASC
            """,
            (course_id,)
        )
        videos = cursor.fetchall()

        return render_template(
            "manage_videos.html",
            course=course,
            videos=videos
        )

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Manage videos error: %s", e)
        flash("Video operation failed. Check the database and sequence number.", "danger")
        return redirect(url_for("admin_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/admin/videos/edit/<int:video_id>", methods=["GET", "POST"])
@login_required("admin")
def edit_video(video_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM videos WHERE id = %s", (video_id,))
        video = cursor.fetchone()

        if not video:
            abort(404)

        if request.method == "POST":
            title = request.form.get("title", "").strip()

            try:
                sequence_no = int(request.form.get("sequence_no", ""))
                if not title or sequence_no < 1:
                    raise ValueError
            except ValueError:
                flash("Enter a title and positive sequence number.", "danger")
                return render_template("edit_video.html", video=video)

            try:
                cursor.execute(
                    """
                    UPDATE videos
                    SET title = %s, sequence_no = %s
                    WHERE id = %s
                    """,
                    (title, sequence_no, video_id)
                )
                conn.commit()
                flash("Video updated successfully!", "success")
                return redirect(url_for("manage_videos", course_id=video["course_id"]))

            except Error:
                conn.rollback()
                flash("Update failed. Sequence number may already be in use.", "danger")

        return render_template("edit_video.html", video=video)

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Edit video error: %s", e)
        flash("Could not edit video.", "danger")
        return redirect(url_for("admin_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/admin/videos/delete/<int:video_id>", methods=["POST"])
@login_required("admin")
def delete_video(video_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM videos WHERE id = %s", (video_id,))
        video = cursor.fetchone()

        if not video:
            flash("Video not found.", "danger")
            return redirect(url_for("admin_dashboard"))

        cursor.execute("DELETE FROM videos WHERE id = %s", (video_id,))
        conn.commit()

        # Remove uploaded MP4 file when applicable.
        if video["video_type"] == "mp4":
            filename = os.path.basename(video["video_url"])
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            if os.path.isfile(filepath):
                os.remove(filepath)

        flash("Video deleted successfully!", "success")
        return redirect(url_for("manage_videos", course_id=video["course_id"]))

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Delete video error: %s", e)
        flash("Could not delete video. Check related progress records.", "danger")
        return redirect(url_for("admin_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

@app.route("/candidate/dashboard")
@login_required("candidate")
def candidate_dashboard():
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT
                c.id,
                c.course_name,
                c.description,
                COUNT(v.id) AS total_videos,
                COUNT(
                    CASE WHEN vp.completed = 1 THEN 1 END
                ) AS completed_videos
            FROM courses c
            LEFT JOIN videos v ON v.course_id = c.id
            LEFT JOIN video_progress vp
                ON vp.video_id = v.id
                AND vp.candidate_id = %s
            GROUP BY c.id, c.course_name, c.description
            ORDER BY c.id DESC
        """, (session["user_id"],))

        courses = cursor.fetchall()

        for course in courses:
            total = course["total_videos"]
            completed = course["completed_videos"]
            course["percentage"] = round(completed * 100 / total) if total else 0

        return render_template(
            "candidate_dashboard.html",
            courses=courses
        )

    except Error as e:
        app.logger.error("Candidate dashboard error: %s", e)
        flash("Could not load courses. Check the database.", "danger")
        return redirect(url_for("logout"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/candidate/course/<int:course_id>")
@login_required("candidate")
def candidate_course(course_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT * FROM courses WHERE id = %s",
            (course_id,)
        )
        course = cursor.fetchone()

        if not course:
            abort(404)

        cursor.execute("""
            SELECT
                v.*,
                COALESCE(vp.completed, 0) AS completed
            FROM videos v
            LEFT JOIN video_progress vp
                ON vp.video_id = v.id
                AND vp.candidate_id = %s
            WHERE v.course_id = %s
            ORDER BY v.sequence_no ASC
        """, (session["user_id"], course_id))

        videos = cursor.fetchall()

        completed_count = sum(
            1 for video in videos if video["completed"]
        )
        total_count = len(videos)
        percentage = round(completed_count * 100 / total_count) if total_count else 0

        # Unlock the first incomplete video only.
        next_uncompleted_found = False

        for video in videos:
            if video["completed"]:
                video["locked"] = False
            elif not next_uncompleted_found:
                video["locked"] = False
                next_uncompleted_found = True
            else:
                video["locked"] = True

        return render_template(
            "candidate_course.html",
            course=course,
            videos=videos,
            percentage=percentage,
            completed_count=completed_count,
            total_count=total_count
        )

    except Error as e:
        app.logger.error("Candidate course error: %s", e)
        flash("Could not load course videos.", "danger")
        return redirect(url_for("candidate_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


def get_candidate_video_access(cursor, video_id, candidate_id):
    cursor.execute(
        "SELECT id, course_id, sequence_no, video_type, video_url "
        "FROM videos WHERE id = %s",
        (video_id,)
    )
    video = cursor.fetchone()

    if not video:
        return None, False

    cursor.execute(
        """
        SELECT id, sequence_no
        FROM videos
        WHERE course_id = %s AND sequence_no < %s
        ORDER BY sequence_no ASC
        """,
        (video["course_id"], video["sequence_no"])
    )
    previous_videos = cursor.fetchall()

    if not previous_videos:
        return video, True

    cursor.execute(
        """
        SELECT video_id
        FROM video_progress
        WHERE candidate_id = %s AND completed = 1
        """,
        (candidate_id,)
    )
    completed_ids = {row["video_id"] for row in cursor.fetchall()}

    cursor.execute(
        """
        SELECT id
        FROM videos
        WHERE course_id = %s AND sequence_no < %s
        """,
        (video["course_id"], video["sequence_no"])
    )
    required_ids = {row["id"] for row in cursor.fetchall()}

    return video, required_ids.issubset(completed_ids)


@app.route("/candidate/video/<int:video_id>/stream")
@login_required("candidate")
def stream_candidate_video(video_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        video, allowed = get_candidate_video_access(
            cursor, video_id, session["user_id"]
        )

        if not video:
            abort(404)

        if not allowed:
            abort(403)

        if video["video_type"] == "youtube":
            return redirect(video["video_url"])

        filename = os.path.basename(video["video_url"])
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        if not os.path.isfile(filepath):
            abort(404)

        return send_file(filepath, mimetype="video/mp4", conditional=True)

    except Error as e:
        app.logger.error("Video stream error: %s", e)
        abort(500)

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


@app.route("/candidate/video/<int:video_id>/complete", methods=["POST"])
@login_required("candidate")
def complete_candidate_video(video_id):
    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        video, allowed = get_candidate_video_access(
            cursor, video_id, session["user_id"]
        )

        if not video:
            abort(404)

        if not allowed:
            abort(403)

        cursor.execute(
            """
            INSERT INTO video_progress
                (candidate_id, video_id, completed, completed_at)
            VALUES (%s, %s, 1, NOW())
            ON DUPLICATE KEY UPDATE
                completed = 1,
                completed_at = NOW()
            """,
            (session["user_id"], video_id)
        )

        conn.commit()
        flash("Video marked as completed!", "success")

        return redirect(
            url_for("candidate_course", course_id=video["course_id"])
        )

    except Error as e:
        if conn:
            conn.rollback()
        app.logger.error("Video completion error: %s", e)
        flash("Could not save video progress.", "danger")
        return redirect(url_for("candidate_dashboard"))

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


if __name__ == "__main__":
    app.run(debug=True)
