from copy import Error
from flask import (
    Flask,
    session,
    redirect,
    request,
    render_template,
    url_for,
    flash,
    jsonify,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_cors import CORS
from dotenv import load_dotenv
from sendotp import srotp, verify
from config import Email, password, get_connection
import mysql.connector
import os
import re
from io import BytesIO
from flask import send_file
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps

load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.secret_key = os.environ.get("secret_key", "default_secret_key")
serializer = URLSafeTimedSerializer(app.secret_key)


def create_token(email):
    return serializer.dumps({"email": email})


def verify_token(token, max_age=60 * 60 * 24 * 7):
    data = serializer.loads(token, max_age=max_age)
    return data["email"]


def require_token(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401
        token = auth.replace("Bearer ", "").strip()
        try:
            email = verify_token(token)
        except SignatureExpired:
            return jsonify({"error": "Token expired"}), 401
        except BadSignature:
            return jsonify({"error": "Invalid token"}), 401

        request.user_email = email  # attach to request
        return fn(*args, **kwargs)

    return wrapper


# --- Global Config ---
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# --- Helper Functions ---
def get_user_id(email):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        return user["user_id"] if user else None
    finally:
        cursor.close()
        conn.close()


# OTP Routes
app.add_url_rule("/send-otp", "srotp", srotp, methods=["POST"])
app.add_url_rule("/srotp", "srotp", srotp, methods=["POST"])
app.add_url_rule("/verify", "verify", verify, methods=["POST"])

# Main routes


@app.route("/")
def home():
    if "email" not in session:
        return redirect("/login")
    role = session.get("role")

    # Both Admin and AssistantAdmin go to the main admin dashboard now
    if role == "Admin" or role == "AssistantAdmin":
        return redirect("/admin")

    if role == "SuperAdmin":
        return redirect("/SA")
    if role == "IT":
        return redirect("/IT")
    if role == "Dean":
        return redirect("/dean")
    return redirect("/udashboard")


@app.route("/udashboard")
def udashboard():
    if "email" not in session:
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch Request Types AND Template Info so we can show the download button
        cursor.execute(
            "SELECT request_type_id, type_name, template_filename FROM request_types ORDER BY type_name ASC"
        )
        request_types = cursor.fetchall()

        return render_template("user.html", request_types=request_types)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/user_notifications")
def get_user_notifications():
    if "email" not in session:
        return jsonify([]), 401

    user_id = get_user_id(session["email"])
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # get all activity for notification
        query = """
            SELECT r.request_id, r.filename, rt.type_name, s.status_name, 
            r.rejection_message, r.created_at, p.position_name as current_stage
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """
        cursor.execute(query, (user_id,))
        requests = cursor.fetchall()

        notifications = []
        for req in requests:
            # Create a notification object
            notif = {
                "id": req["request_id"],
                "title": f"Update on {req['type_name']}",
                "time": req["created_at"].strftime("%b %d, %H:%M"),
                "icon": "info",
            }

            # message and style based on status

            status_lower = req["status_name"].lower()

            if status_lower == "approved":
                notif["message"] = (
                    f"Your request for {req['filename']} has been fully approved."
                )
                notif["type"] = "success"
                notif["icon"] = "check-circle"
            elif status_lower == "rejected":
                notif["message"] = (
                    f"Your request was rejected. Reason: {req['rejection_message']}"
                )
                notif["type"] = "error"
                notif["icon"] = "x-circle"
            else:
                notif["message"] = (
                    f"Currently being reviewed by: {req['current_stage']}"
                )
                notif["type"] = "pending"
                notif["icon"] = "clock"

            notifications.append(notif)

        return jsonify(notifications)
    except Exception as e:
        print(f"Notification Error: {e}")
        return jsonify([]), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/assistant")
def assistant_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("assistant.html")


@app.route("/SA")
def super_admin_dashboard():
    if "email" not in session:
        return redirect("/login")
    return render_template("super_admin.html")


@app.route("/dean")
def dean_dashboard():
    if "email" not in session:
        return redirect(url_for("login"))
    return render_template("dean.html")


# Admin Dashboard


@app.route("/admin")
def admin_dashboard():
    if "email" not in session:
        return redirect("/login")

    role = session.get("role")
    # Security: Only Admins and Assistants allowed
    if role not in ["Admin", "AssistantAdmin"]:
        return redirect("/")

    user_id = session["user_id"]
    position_id = session.get("position_id")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # --- 1. INCOMING APPROVALS (Filtered by Role) ---
        # Admin sees ALL. Assistant sees ONLY requests assigned to their position.
        where_clause = ""
        params = []

        if role == "AssistantAdmin":
            where_clause = " AND r.stage_position_id = %s"
            params.append(position_id)

        # Fetch Counts
        cursor.execute(
            f"SELECT COUNT(*) as count FROM requests r WHERE r.status_id = 1{where_clause}",
            tuple(params),
        )
        pending_count = cursor.fetchone()["count"]

        cursor.execute(
            f"SELECT COUNT(*) as count FROM requests r WHERE r.status_id = 2{where_clause}",
            tuple(params),
        )
        approved_count = cursor.fetchone()["count"]

        cursor.execute(
            f"SELECT COUNT(*) as count FROM requests r WHERE r.status_id = 3{where_clause}",
            tuple(params),
        )
        rejected_count = cursor.fetchone()["count"]

        cursor.execute(
            f"SELECT COUNT(*) as count FROM requests r WHERE r.status_id = 2 AND DATE(r.updated_at) = CURDATE(){where_clause}",
            tuple(params),
        )
        approvals_today = cursor.fetchone()["count"]

        # Fetch Incoming Requests Table
        query_incoming = f"""
            SELECT r.request_id, u.email, d.dept_name, rt.type_name, 
            r.filename, s.status_name, r.created_at
            FROM requests r
            JOIN users u ON r.user_id = u.user_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            WHERE 1=1 {where_clause}
            ORDER BY r.created_at DESC LIMIT 20
        """
        cursor.execute(query_incoming, tuple(params))
        incoming_requests = cursor.fetchall()

        # --- 2. MY REQUESTS (Personal requests made by this Admin/Assistant) ---
        query_my_requests = """
            SELECT r.request_id, rt.type_name, r.filename, s.status_name, 
                   r.created_at, r.rejection_message
            FROM requests r
            LEFT JOIN request_types rt ON r.request_type_id = rt.request_type_id
            LEFT JOIN request_status s ON r.status_id = s.status_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """
        cursor.execute(query_my_requests, (user_id,))
        my_requests = cursor.fetchall()

        # --- 3. SYSTEM SETUP DATA (For managing types and templates) ---
        # Get Positions for dropdown
        cursor.execute(
            "SELECT position_id, position_name FROM positions ORDER BY position_name ASC"
        )
        positions = cursor.fetchall()

        # Get Existing Request Types (Including Template Info + Reviewers/Approvers)
        cursor.execute("""
            SELECT 
                rt.request_type_id,
                rt.type_name,
                rt.template_filename,
                GROUP_CONCAT(DISTINCT pr.position_name ORDER BY rtr.id SEPARATOR ', ') AS reviewer_names,
                GROUP_CONCAT(DISTINCT pa.position_name ORDER BY rta.id SEPARATOR ', ') AS approver_names,
                GROUP_CONCAT(DISTINCT pr.position_id ORDER BY rtr.id SEPARATOR ',') AS reviewer_ids,
                GROUP_CONCAT(DISTINCT pa.position_id ORDER BY rta.id SEPARATOR ',') AS approver_ids
            FROM request_types rt
            LEFT JOIN request_type_reviewers rtr ON rt.request_type_id = rtr.request_type_id
            LEFT JOIN positions pr ON rtr.position_id = pr.position_id
            LEFT JOIN request_type_approvers rta ON rt.request_type_id = rta.request_type_id
            LEFT JOIN positions pa ON rta.position_id = pa.position_id
            GROUP BY rt.request_type_id, rt.type_name, rt.template_filename
            ORDER BY rt.type_name ASC
        """)
        existing_types = cursor.fetchall()

        # Get Simple List for "Create Request" Dropdown
        cursor.execute(
            "SELECT request_type_id, type_name FROM request_types ORDER BY type_name ASC"
        )
        available_types = cursor.fetchall()

        return render_template(
            "admin.html",
            pending_count=pending_count,
            approved_count=approved_count,
            rejected_count=rejected_count,
            approvals_today=approvals_today,
            recent_requests=incoming_requests,
            my_requests=my_requests,
            request_types=available_types,
            positions=positions,
            existing_types=existing_types,
        )
    finally:
        cursor.close()
        conn.close()


# --- Routes for System Setup (Adding Request Types) ---
@app.route("/add_request_type", methods=["POST"])
def add_request_type():
    if session.get("role") not in ["Admin", "AssistantAdmin"]:
        return redirect("/")

    type_name = request.form.get("type_name")
    reviewer_pos_ids = request.form.getlist("reviewer_position_ids[]")
    approver_pos_ids = request.form.getlist("approver_position_ids[]")

    # Handle Template File Upload
    file = request.files.get("template_file")
    template_filename = None
    template_blob = None

    if file and file.filename != "":
        template_filename = secure_filename(file.filename)
        template_blob = file.read()  # Read binary

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Insert Request Type + Template Data
        query = """
            INSERT INTO request_types (type_name, template_filename, template_file) 
            VALUES (%s, %s, %s)
        """
        cursor.execute(query, (type_name, template_filename, template_blob))
        type_id = cursor.lastrowid

        # Link Reviewer Positions (optional)
        for pos_id in reviewer_pos_ids:
            if pos_id:
                cursor.execute(
                    "INSERT INTO request_type_reviewers (request_type_id, position_id) VALUES (%s, %s)",
                    (type_id, pos_id),
                )

        # Link Approver Positions (required)
        for pos_id in approver_pos_ids:
            if pos_id:
                cursor.execute(
                    "INSERT INTO request_type_approvers (request_type_id, position_id) VALUES (%s, %s)",
                    (type_id, pos_id),
                )

        conn.commit()
        flash("Request Type added successfully.", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    return redirect("/admin")


@app.route("/create_request", methods=["POST"])
def create_request():
    if "user_id" not in session:
        return redirect("/login")

    user_id = session["user_id"]
    request_type_id = request.form.get("request_type_id")
    file = request.files.get("file")

    filename = None
    file_blob = None

    if file and file.filename != "":
        filename = secure_filename(file.filename)
        file_blob = file.read()

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # Find first REVIEWER (if any), else first APPROVER
        cursor.execute(
            "SELECT position_id FROM request_type_reviewers WHERE request_type_id = %s ORDER BY id ASC LIMIT 1",
            (request_type_id,),
        )
        reviewer = cursor.fetchone()

        if reviewer:
            stage_position_id = reviewer[0]
        else:
            cursor.execute(
                "SELECT position_id FROM request_type_approvers WHERE request_type_id = %s ORDER BY id ASC LIMIT 1",
                (request_type_id,),
            )
            approver = cursor.fetchone()
            stage_position_id = approver[0] if approver else None

        # Insert Request
        query = """
            INSERT INTO requests (user_id, request_type_id, filename, attachment, status_id, stage_position_id)
            VALUES (%s, %s, %s, %s, 1, %s)
        """
        cursor.execute(
            query, (user_id, request_type_id, filename, file_blob, stage_position_id)
        )
        conn.commit()
        flash("Request submitted successfully!", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        cursor.close()
        conn.close()

    # Redirect back based on role
    if session.get("role") in ["Admin", "AssistantAdmin"]:
        return redirect("/admin")
    return redirect("/udashboard")


# Download User Uploaded Attachment (Admin/Assistant/User can view)
@app.route("/download_attachment/<int:request_id>")
def download_attachment(request_id):
    if "email" not in session:
        return redirect("/login")

    role = session.get("role")
    user_id = session.get("user_id")
    position_id = session.get("position_id")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT request_id, user_id, stage_position_id, filename, attachment "
            "FROM requests WHERE request_id = %s",
            (request_id,),
        )
        row = cursor.fetchone()

        if not row or not row.get("attachment"):
            flash("No attachment found for this request.", "warning")
            return redirect(request.referrer or "/admin")

        # Authorization:
        # Admin -> can view all
        # AssistantAdmin -> can view requests assigned to them + their own
        # User -> can view only their own
        allowed = False
        if role == "Admin":
            allowed = True
        elif role == "AssistantAdmin":
            allowed = (row.get("stage_position_id") == position_id) or (
                row.get("user_id") == user_id
            )
        else:
            allowed = row.get("user_id") == user_id

        if not allowed:
            return "Access Denied", 403

        # View in browser by default; add ?download=1 to force download
        force_download = request.args.get("download") == "1"

        import mimetypes

        mime_type, _ = mimetypes.guess_type(row.get("filename") or "")

        return send_file(
            BytesIO(row["attachment"]),
            download_name=row.get("filename") or f"request_{request_id}_attachment",
            mimetype=mime_type or "application/octet-stream",
            as_attachment=force_download,
        )
    finally:
        cursor.close()
        conn.close()


# 3. Download Template Route
@app.route("/download_template/<int:type_id>")
def download_template(type_id):
    if "user_id" not in session:
        return redirect("/login")

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT template_filename, template_file FROM request_types WHERE request_type_id = %s",
            (type_id,),
        )
        data = cursor.fetchone()

        if data and data["template_file"]:
            return send_file(
                BytesIO(data["template_file"]),
                download_name=data["template_filename"],
                as_attachment=True,
            )
        else:
            flash("No template found.", "warning")
            return redirect(request.referrer)
    finally:
        cursor.close()
        conn.close()


@app.route("/delete_request_type/<int:id>")
def delete_request_type(id):
    if session.get("role") not in ["Admin", "AssistantAdmin"]:
        return redirect("/")
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (id,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (id,)
        )
        cursor.execute("DELETE FROM request_types WHERE request_type_id = %s", (id,))
        conn.commit()
        flash("Request Type deleted.", "success")
    except Exception as e:
        conn.rollback()
        flash("Cannot delete: Type is in use.", "danger")
    finally:
        cursor.close()
        conn.close()
    return redirect("/admin")


@app.route("/edit_request_type", methods=["POST"])
def edit_request_type():
    if "email" not in session:
        return redirect("/login")

    type_id = request.form.get("type_id")
    new_name = request.form.get("type_name")
    reviewer_pos_ids = request.form.getlist("reviewer_position_ids[]")
    approver_pos_ids = request.form.getlist("approver_position_ids[]")

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Update the Name
        cursor.execute(
            "UPDATE request_types SET type_name = %s WHERE request_type_id = %s",
            (new_name, type_id),
        )

        # Replace reviewer/approver mappings
        cursor.execute(
            "DELETE FROM request_type_reviewers WHERE request_type_id = %s", (type_id,)
        )
        cursor.execute(
            "DELETE FROM request_type_approvers WHERE request_type_id = %s", (type_id,)
        )

        for pos_id in reviewer_pos_ids:
            if pos_id:
                cursor.execute(
                    "INSERT INTO request_type_reviewers (request_type_id, position_id) VALUES (%s, %s)",
                    (type_id, pos_id),
                )

        for pos_id in approver_pos_ids:
            if pos_id:
                cursor.execute(
                    "INSERT INTO request_type_approvers (request_type_id, position_id) VALUES (%s, %s)",
                    (type_id, pos_id),
                )

        conn.commit()
        flash("Request type updated successfully", "success")
    except Exception as e:
        conn.rollback()
        flash(f"Error: {e}", "danger")
    finally:
        conn.close()
    return redirect(url_for("admin_dashboard"))


#  IT DASHBOARD ROUTES


@app.route("/IT")
def it_dashboard():

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT COUNT(*) as count FROM users")
        result = cursor.fetchone()
        total_users = result["count"] if result else 0
        new_users_count = 5

        query_users = """
            SELECT u.user_id, u.email, d.dept_name, r.role_name, p.position_name
            FROM users u
            JOIN departments d ON u.dept_id = d.dept_id
            JOIN roles r ON u.role_id = r.role_id
            JOIN positions p ON u.position_id = p.position_id
            ORDER BY u.user_id DESC LIMIT 20
        """
        cursor.execute(query_users)
        users = cursor.fetchall()

        cursor.execute("SELECT * FROM departments")
        departments = cursor.fetchall()
        cursor.execute("SELECT * FROM roles")
        roles = cursor.fetchall()
        cursor.execute("SELECT * FROM positions")
        positions = cursor.fetchall()

        cursor.execute("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 15")
        notifications = cursor.fetchall()

        return render_template(
            "IT.html",
            users=users,
            total_users=total_users,
            new_users_count=new_users_count,
            departments=departments,
            roles=roles,
            positions=positions,
            notifications=notifications,
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/it/stats")
def get_it_stats():
    """Returns system stats for the IT dashboard cards"""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Total Users
    cursor.execute("SELECT COUNT(*) as count FROM users")
    total_users = cursor.fetchone()["count"]

    # Total Departments
    cursor.execute("SELECT COUNT(*) as count FROM departments")
    total_depts = cursor.fetchone()["count"]

    # Active Sessions
    active_sessions = 12

    cursor.close()
    conn.close()

    return jsonify(
        {
            "total_users": total_users,
            "total_depts": total_depts,
            "active_sessions": active_sessions,
        }
    )


@app.route("/api/it/users", methods=["GET"])
def get_all_users_for_admin():
    # Fetches all users for the Account Management tab
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    query = """
        SELECT 
            u.user_id, 
            u.email, 
            r.role_name, 
            d.dept_name, 
            p.position_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.role_id
        LEFT JOIN departments d ON u.dept_id = d.dept_id
        LEFT JOIN positions p ON u.position_id = p.position_id
        ORDER BY u.user_id DESC
    """
    cursor.execute(query)
    users = cursor.fetchall()

    cursor.close()
    conn.close()
    return jsonify(users)


# --- Add these routes to main.py ---


@app.route("/create_role", methods=["POST"])
def create_role():
    # Security check
    if "email" not in session:
        return redirect("/login")

    role_name = request.form.get("role_name")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 1. Insert into Roles table
        cursor.execute("INSERT INTO roles (role_name) VALUES (%s)", (role_name,))

        # 2. Log the Activity
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            ("Role Created", f"New system role '{role_name}' added."),
        )

        conn.commit()
        flash(f"Role '{role_name}' created successfully!", "success")

    except mysql.connector.Error as err:
        conn.rollback()
        # Check for Duplicate Entry error (Error Code 1062)
        if err.errno == 1062:
            flash(f"Role '{role_name}' already exists.", "danger")
        else:
            flash(f"Database Error: {err}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/create_position", methods=["POST"])
def create_position():
    # Security check
    if "email" not in session:
        return redirect("/login")

    position_name = request.form.get("position_name")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # 1. Insert into Positions table
        cursor.execute(
            "INSERT INTO positions (position_name) VALUES (%s)", (position_name,)
        )

        # 2. Log the Activity
        cursor.execute(
            "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
            ("Position Created", f"New position '{position_name}' added."),
        )

        conn.commit()
        flash(f"Position '{position_name}' created successfully!", "success")

    except mysql.connector.Error as err:
        conn.rollback()
        # Check for Duplicate Entry error
        if err.errno == 1062:
            flash(f"Position '{position_name}' already exists.", "danger")
        else:
            flash(f"Database Error: {err}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/api/request/<int:request_id>/status", methods=["POST"])
def update_request_status(request_id):
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    new_status = data.get("status")
    rejection_msg = data.get("message", None)

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        # Get Status ID
        cursor.execute(
            "SELECT status_id FROM request_status WHERE status_name = %s",
            (new_status.upper(),),
        )
        status_row = cursor.fetchone()

        if not status_row:
            return jsonify({"error": "Invalid status"}), 400

        status_id = status_row["status_id"]

        # If REJECTED -> mark rejected immediately
        if (new_status or "").lower() == "rejected":
            cursor.execute(
                """
                UPDATE requests
                SET status_id = %s, rejection_message = %s
                WHERE request_id = %s
            """,
                (status_id, rejection_msg, request_id),
            )
            conn.commit()
            return jsonify({"message": "Request rejected successfully"})

        # If APPROVED -> advance to next reviewer/approver if exists
        if (new_status or "").lower() == "approved":
            cursor.execute(
                "SELECT request_type_id, stage_position_id FROM requests WHERE request_id = %s",
                (request_id,),
            )
            req = cursor.fetchone()
            if not req:
                return jsonify({"error": "Request not found"}), 404

            req_type_id = req["request_type_id"]
            current_stage = req["stage_position_id"]

            # reviewers first, then approvers
            cursor.execute(
                "SELECT position_id FROM request_type_reviewers WHERE request_type_id = %s ORDER BY id ASC",
                (req_type_id,),
            )
            reviewers = [r["position_id"] for r in cursor.fetchall()]

            cursor.execute(
                "SELECT position_id FROM request_type_approvers WHERE request_type_id = %s ORDER BY id ASC",
                (req_type_id,),
            )
            approvers = [a["position_id"] for a in cursor.fetchall()]

            workflow = reviewers + approvers

            if not workflow:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                    WHERE request_id = %s
                """,
                    (status_id, request_id),
                )
                conn.commit()
                return jsonify(
                    {"message": "Request approved (no workflow configured)."}
                )

            if not current_stage:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = 1, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (workflow[0], request_id),
                )
                conn.commit()
                return jsonify({"message": "Request routed to first stage."})

            try:
                idx = workflow.index(current_stage)
            except ValueError:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = 1, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (workflow[0], request_id),
                )
                conn.commit()
                return jsonify({"message": "Request stage reset to first stage."})

            if idx < len(workflow) - 1:
                next_stage = workflow[idx + 1]
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = 1, rejection_message = NULL, stage_position_id = %s
                    WHERE request_id = %s
                """,
                    (next_stage, request_id),
                )
                conn.commit()
                return jsonify({"message": "Approved. Moved to next stage."})
            else:
                cursor.execute(
                    """
                    UPDATE requests
                    SET status_id = %s, rejection_message = NULL, stage_position_id = NULL
                    WHERE request_id = %s
                """,
                    (status_id, request_id),
                )
                conn.commit()
                return jsonify({"message": "Request fully approved."})

        # Fallback: set status as requested
        cursor.execute(
            """
            UPDATE requests 
            SET status_id = %s, rejection_message = %s 
            WHERE request_id = %s
        """,
            (status_id, rejection_msg, request_id),
        )

        conn.commit()
        return jsonify({"message": f"Request {new_status} successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/it/user/update", methods=["POST"])
def update_user_role():
    """Allows IT to change a user's role or department"""
    data = request.json
    user_id = data.get("user_id")
    new_role_id = data.get("role_id")

    conn = get_connection()
    cursor = conn.cursor()

    try:
        sql = "UPDATE users SET role_id = %s WHERE user_id = %s"
        cursor.execute(sql, (new_role_id, user_id))
        conn.commit()
        return jsonify({"success": True, "message": "User updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/create_user", methods=["POST"])
def create_user():

    if "email" not in session:
        return redirect("/login")

    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    dept_id = request.form["dept_id"]
    role_id = request.form["role_id"]
    position_id = request.form["position_id"]

    # Hash the password
    hashed_password = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16
    )

    conn = get_connection()
    cursor = conn.cursor()

    try:
        #  Insert the New User
        query_user = """
            INSERT INTO users (email, password, dept_id, role_id, position_id)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(
            query_user, (email, hashed_password, dept_id, role_id, position_id)
        )

        #  Insert the Activity Log (The Notification)
        query_log = """
            INSERT INTO activity_logs (title, description) 
            VALUES (%s, %s)
        """
        log_title = "New Account Created"
        # formatted string to include the specific email created
        log_desc = f"Admin created a new account for {email}"

        cursor.execute(query_log, (log_title, log_desc))

        # Commit both changes at once
        conn.commit()
        flash("User created successfully!", "success")

    except mysql.connector.Error as e:
        conn.rollback()  # Undo changes if error occurs
        flash(f"Error creating user: {e}", "danger")

    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("it_dashboard"))


@app.route("/create_dept", methods=["POST"])
def create_dept():
    # Security check
    if "email" not in session:
        return redirect("/login")

    if request.method == "POST":
        dept_name = request.form["dept_name"]
        # optional: if you have a dept_head field in your form
        # dept_head = request.form.get('dept_head', '')

        conn = get_connection()
        cursor = conn.cursor()

        try:
            #  Create the Department
            cursor.execute(
                "INSERT INTO departments (dept_name) VALUES (%s)", (dept_name,)
            )

            # Create the Log
            log_title = "Department Created"
            log_desc = f"New department '{dept_name}' added to the system."

            cursor.execute(
                "INSERT INTO activity_logs (title, description) VALUES (%s, %s)",
                (log_title, log_desc),
            )

            conn.commit()
            flash("Department added successfully!", "success")

        except mysql.connector.Error as e:
            conn.rollback()
            flash(f"Error adding department: {e}", "danger")

        finally:
            cursor.close()
            conn.close()

        return redirect(url_for("it_dashboard"))


# API Endpoints


@app.route("/api/user-profile", methods=["GET"])
def api_user_profile():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch detailed profile info
        query = """
            SELECT u.email, d.dept_name, p.position_name, r.role_name
            FROM users u
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = %s
        """
        cursor.execute(query, (session["email"],))
        data = cursor.fetchone()
        if data:
            return jsonify(data)
        return jsonify({"error": "User not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cursor.close()
        conn.close()


@app.route("/api/request-types", methods=["GET"])
def api_request_types():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT request_type_id, type_name FROM request_types")
        data = cursor.fetchall()
        return jsonify(data)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/requests", methods=["GET", "POST"])
def api_requests():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = get_user_id(session["email"])
    if not user_id:
        return jsonify({"error": "User ID not found"}), 404

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    # Fetch All Requests
    if request.method == "GET":
        try:
            query = """
                SELECT 
                    r.request_id,
                    rt.type_name,
                    r.filename,
                    rs.status_name,
                    p.position_name,
                    r.rejection_message,
                    r.created_at
                FROM requests r
                JOIN request_types rt ON r.request_type_id = rt.request_type_id
                JOIN request_status rs ON r.status_id = rs.status_id
                LEFT JOIN positions p ON r.stage_position_id = p.position_id
                WHERE r.user_id = %s
                ORDER BY r.created_at DESC
            """
            cursor.execute(query, (user_id,))
            requests_data = cursor.fetchall()
            return jsonify(requests_data)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()

    # Create New Request
    if request.method == "POST":
        try:
            # Handle JSON
            req_type_id = request.form.get("request_type_id")

            # Handle File
            if "attachment" in request.files:
                file = request.files["attachment"]
                filename = secure_filename(file.filename)
                file_data = file.read()
            else:
                # Fallback if no file uploaded
                filename = request.form.get("filename")
                file_data = None

            if not req_type_id:
                return jsonify({"error": "Request Type ID is required"}), 400

            # Find Approver
            cursor.execute(
                """
                SELECT position_id FROM request_type_approvers 
                WHERE request_type_id = %s ORDER BY id ASC LIMIT 1
            """,
                (req_type_id,),
            )
            approver = cursor.fetchone()

            if not approver:
                return (
                    jsonify({"error": "No approver configured for this request type"}),
                    400,
                )

            stage_position_id = approver["position_id"]

            # Get 'PENDING' Status ID
            cursor.execute(
                "SELECT status_id FROM request_status WHERE status_name='PENDING'"
            )
            status_row = cursor.fetchone()
            if not status_row:
                return jsonify({"error": "Pending status not configured in DB"}), 500

            status_id = status_row["status_id"]

            cursor.execute(
                """
                INSERT INTO requests (request_type_id, user_id, filename, attachment, status_id, stage_position_id, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
            """,
                (
                    req_type_id,
                    user_id,
                    filename,
                    file_data,
                    status_id,
                    stage_position_id,
                ),
            )

            conn.commit()
            return jsonify({"message": "Request created successfully"}), 201

        except Exception as e:
            print(f"Error creating request: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            cursor.close()
            conn.close()


# Account Management Routes


@app.route("/change_password", methods=["POST"])
def change_password():
    if "email" not in session:
        return redirect("/login")

    current_pass = request.form.get("current_password")
    new_pass = request.form.get("new_password")
    email = session["email"]

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute("SELECT password FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user["password"], current_pass):
            new_hash = generate_password_hash(
                new_pass, method="pbkdf2:sha256", salt_length=16
            )
            cursor.execute(
                "UPDATE users SET password=%s WHERE email=%s", (new_hash, email)
            )
            conn.commit()
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("udashboard"))


@app.route("/delete_account", methods=["POST"])
def delete_account():
    if "email" not in session:
        return redirect("/login")
    email = session["email"]

    conn = get_connection()
    cursor = conn.cursor()
    try:
        # Delete related data first to avoid Foreign Key errors
        cursor.execute("DELETE FROM otp_codes WHERE email=%s", (email,))

        # Get user_id for request deletion
        cursor.execute("SELECT user_id FROM users WHERE email=%s", (email,))
        uid_row = cursor.fetchone()
        if uid_row:
            # Handle tuple vs dict return depending on config
            uid = uid_row["user_id"] if isinstance(uid_row, dict) else uid_row[0]
            cursor.execute("DELETE FROM requests WHERE user_id=%s", (uid,))
            cursor.execute("DELETE FROM users WHERE email=%s", (email,))
            conn.commit()
            session.clear()
            return redirect("/")
    except Exception as e:
        print("Delete error:", e)
        return redirect("/udashboard")
    finally:
        cursor.close()
        conn.close()


# Auth Routes (Signup/Login)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT dept_name FROM departments ORDER BY dept_name")
    departments = cursor.fetchall()
    cursor.close()
    conn.close()

    if request.method == "POST":
        if not session.get("otp_verified"):
            return render_template(
                "signup.html",
                message="Please verify OTP first",
                departments=departments,
            )

        e = request.form["email"].strip().lower()
        p = request.form["pass"]
        cp = request.form["cpass"]
        dept_name = request.form.get("dept", "").strip()

        allow_domain = "phinmaed.com"

        if not dept_name:
            return render_template(
                "signup.html",
                message="Please Select your Department",
                departments=departments,
            )
        if not re.match(r"[a-z0-9.%+]+@[a-z0-9.-]+\.[a-z]{2,}$", e):
            return render_template(
                "signup.html", message="Invalid email address", departments=departments
            )
        if e.split("@")[1] != allow_domain:
            return render_template(
                "signup.html",
                message="Use your phinmaed account",
                departments=departments,
            )
        if (
            len(p) < 6
            or not any(c.isdigit() for c in p)
            or not any(c.isupper() for c in p)
        ):
            return render_template(
                "signup.html",
                message="Password: 6+ chars, 1 digit, 1 uppercase",
                departments=departments,
            )
        if p != cp:
            return render_template(
                "signup.html", message="Passwords do not match", departments=departments
            )

        try:
            conn = get_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute("SELECT user_id FROM users WHERE email=%s", (e,))
            if cursor.fetchone():
                return render_template(
                    "signup.html",
                    message="Email already used please login",
                    departments=departments,
                )

            cursor.execute(
                "SELECT dept_id FROM departments WHERE dept_name=%s", (dept_name,)
            )
            dept = cursor.fetchone()
            if not dept:
                return render_template(
                    "signup.html", message="Invalid department", departments=departments
                )
            dept_id = dept["dept_id"]

            # Default Role/Position
            cursor.execute("SELECT role_id FROM roles WHERE role_name='User'")
            role_row = cursor.fetchone()
            role_id = role_row["role_id"] if role_row else 1

            cursor.execute(
                "SELECT position_id FROM positions WHERE position_name='None'"
            )
            pos_row = cursor.fetchone()
            position_id = pos_row["position_id"] if pos_row else 1

            hp = generate_password_hash(p, method="pbkdf2:sha256", salt_length=16)

            cursor.execute(
                "INSERT INTO users (email, password, dept_id, role_id, position_id) VALUES (%s,%s,%s,%s,%s)",
                (e, hp, dept_id, role_id, position_id),
            )
            conn.commit()

            session["email"] = e
            session["dept"] = dept_name
            session["role"] = "User"
            session["position"] = "None"
            session.pop("otp_verified", None)

            return redirect("/udashboard")

        except Exception as ex:
            print("Signup error:", ex)
            return render_template(
                "signup.html", message="Something went wrong", departments=departments
            )
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

    return render_template("signup.html", departments=departments)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        password = request.form["pass"]

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        try:
            # Added p.position_id to the SELECT query
            cursor.execute(
                """
                SELECT u.user_id, u.email, u.password, r.role_name, 
                p.position_name, p.position_id, d.dept_name
                FROM users u
                JOIN roles r ON u.role_id = r.role_id
                JOIN positions p ON u.position_id = p.position_id
                LEFT JOIN departments d ON u.dept_id = d.dept_id
                WHERE u.email = %s
            """,
                (e,),
            )
            user = cursor.fetchone()

            if user and check_password_hash(user["password"], password):
                session["email"] = user["email"]
                session["user_id"] = user["user_id"]
                session["role"] = user["role_name"]
                session["position"] = user["position_name"]
                session["position_id"] = user["position_id"]
                session["dept"] = user["dept_name"]
                return redirect("/")
            else:
                return render_template("login.html", message="Invalid credentials")
        finally:
            cursor.close()
            conn.close()
    return render_template("login.html")


@app.route("/api/mobile/login", methods=["POST"])
def mobile_login():
    data = request.get_json(silent=True) or {}
    e = (data.get("email") or "").strip().lower()
    pw = data.get("password") or ""

    if not e or not pw:
        return jsonify({"error": "Email and password required"}), 400

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.user_id, u.email, u.password, r.role_name,
                   p.position_name, d.dept_name
            FROM users u
            JOIN roles r ON u.role_id = r.role_id
            JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            WHERE u.email = %s
        """,
            (e,),
        )
        user = cursor.fetchone()

        if not user or not check_password_hash(user["password"], pw):
            return jsonify({"error": "Invalid credentials"}), 401

        # USER ONLY guard
        if user["role_name"] != "User":
            return jsonify({"error": "User role only"}), 403

        token = create_token(user["email"])

        return jsonify(
            {
                "token": token,
                "user": {
                    "email": user["email"],
                    "dept_name": user["dept_name"],
                    "position_name": user["position_name"],
                    "role_name": user["role_name"],
                },
            }
        )
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/user-profile", methods=["GET"])
@require_token
def mobile_user_profile():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT u.email, d.dept_name, p.position_name, r.role_name
            FROM users u
            LEFT JOIN departments d ON u.dept_id = d.dept_id
            LEFT JOIN positions p ON u.position_id = p.position_id
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = %s
        """,
            (request.user_email,),
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({"error": "User not found"}), 404
        if row["role_name"] != "User":
            return jsonify({"error": "User role only"}), 403
        return jsonify(row)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/requests", methods=["GET"])
@require_token
def mobile_requests():
    user_id = get_user_id(request.user_email)
    if not user_id:
        return jsonify({"error": "User ID not found"}), 404

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT 
                r.request_id,
                rt.type_name,
                r.filename,
                rs.status_name,
                p.position_name,
                r.rejection_message,
                r.created_at
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status rs ON r.status_id = rs.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """,
            (user_id,),
        )
        return jsonify(cursor.fetchall())
    finally:
        cursor.close()
        conn.close()


@app.route("/api/mobile/notifications", methods=["GET"])
@require_token
def mobile_notifications():
    user_id = get_user_id(request.user_email)
    if not user_id:
        return jsonify([])

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            """
            SELECT r.request_id, r.filename, rt.type_name, s.status_name, 
            r.rejection_message, r.created_at, p.position_name as current_stage
            FROM requests r
            JOIN request_types rt ON r.request_type_id = rt.request_type_id
            JOIN request_status s ON r.status_id = s.status_id
            LEFT JOIN positions p ON r.stage_position_id = p.position_id
            WHERE r.user_id = %s
            ORDER BY r.created_at DESC
        """,
            (user_id,),
        )

        rows = cursor.fetchall()
        notifications = []
        for req in rows:
            status_lower = (req["status_name"] or "").lower()
            notif = {
                "id": req["request_id"],
                "title": f"Update on {req['type_name']}",
                "time": req["created_at"].strftime("%b %d, %H:%M"),
                "type": "pending",
                "message": f"Currently being reviewed by: {req['current_stage']}",
            }
            if status_lower == "approved":
                notif["type"] = "success"
                notif["message"] = (
                    f"Your request for {req['filename']} has been fully approved."
                )
            elif status_lower == "rejected":
                notif["type"] = "error"
                notif["message"] = f"Rejected: {req['rejection_message']}"
            notifications.append(notif)

        return jsonify(notifications)
    finally:
        cursor.close()
        conn.close()


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    # app.run(debug=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
