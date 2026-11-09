import os
import uuid
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from database import db
from models import User, Document, DocumentPermission, AuditLog

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key-trustvault-2026")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///trustvault.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5MB limit

PRIVATE_FOLDER = Path(app.instance_path) / "private_uploads"
PRIVATE_FOLDER.mkdir(parents=True, exist_ok=True)
app.config["UPLOAD_FOLDER"] = str(PRIVATE_FOLDER)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

with app.app_context():
    db.create_all()

def log_action(action, document_id=None, details=""):
    log = AuditLog(
        actor_id=current_user.id if current_user.is_authenticated else None,
        document_id=document_id,
        action=action,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def can_read_document(document):
    if document.owner_id == current_user.id or current_user.role == "admin":
        return True

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    return permission is not None and permission.permission in ["read", "edit"]

# ---------------- ROUTES ----------------

@app.route("/")
def home():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        role = request.form["role"]

        # AUTO-ASSIGN ADMIN ROLE IF USERNAME IS 'admin'
        if username.lower() == "admin":
            role = "admin"
        elif role not in ["owner", "viewer"]:
            flash("Invalid role selection.")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return redirect(url_for("register"))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already exists.")
            return redirect(url_for("register"))

        user = User(username=username, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            log_action("USER_LOGIN", details=f"User logged in: {user.email}")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    search_query = request.args.get("q", "").strip()

    if current_user.role == "owner":
        query = Document.query.filter_by(owner_id=current_user.id)
    elif current_user.role == "admin":
        query = Document.query
    else:
        permissions = DocumentPermission.query.filter_by(user_id=current_user.id).all()
        doc_ids = [p.document_id for p in permissions]
        query = Document.query.filter(Document.id.in_(doc_ids))

    if search_query:
        query = query.filter(Document.title.ilike(f"%{search_query}%") | Document.category.ilike(f"%{search_query}%"))

    documents = query.order_by(Document.created_at.desc()).all()
    return render_template("dashboard.html", user=current_user, documents=documents, search_query=search_query)

@app.route("/upload", methods=["POST"])
@login_required
def upload_document():
    if current_user.role != "owner":
        log_action("DENIED_UPLOAD_ATTEMPT", details="Non-owner attempted file upload")
        abort(403)

    uploaded_file = request.files.get("document")
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()

    if not uploaded_file or uploaded_file.filename == "" or not title or not category:
        flash("All fields are required.")
        return redirect(url_for("dashboard"))

    if not uploaded_file.filename.lower().endswith(".pdf"):
        flash("Only PDF files are permitted.")
        return redirect(url_for("dashboard"))

    # Magic byte header verification (%PDF-)
    file_header = uploaded_file.stream.read(5)
    uploaded_file.stream.seek(0)
    if file_header != b"%PDF-":
        flash("Security Alert: File is not a valid PDF binary.")
        log_action("MALICIOUS_UPLOAD_BLOCKED", details=f"Invalid magic bytes for title: {title}")
        return redirect(url_for("dashboard"))

    stored_name = f"{uuid.uuid4()}.pdf"
    save_path = PRIVATE_FOLDER / stored_name
    uploaded_file.save(save_path)

    document = Document(
        title=title,
        original_filename=uploaded_file.filename,
        stored_filename=stored_name,
        category=category,
        owner_id=current_user.id
    )
    db.session.add(document)
    db.session.commit()

    log_action("UPLOAD", document.id, f"Uploaded document: {title}")
    flash("Document securely vaulted!")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = db.session.get(Document, document_id)
    if not document:
        abort(404)

    if not can_read_document(document):
        log_action("DENIED_DOWNLOAD", document.id, "Unauthorized download attempt blocked")
        abort(403)

    file_path = PRIVATE_FOLDER / document.stored_filename
    if not file_path.is_file():
        abort(404)

    log_action("DOWNLOAD", document.id, f"Downloaded document: {document.title}")
    return send_file(file_path, as_attachment=True, download_name=document.original_filename)

@app.route("/documents/<int:document_id>/share", methods=["POST"])
@login_required
def share_document(document_id):
    document = db.session.get(Document, document_id)
    if not document or document.owner_id != current_user.id:
        abort(403)

    email = request.form.get("email", "").strip().lower()
    permission = request.form.get("permission")

    if permission not in ["read", "edit"]:
        abort(400)

    target_user = User.query.filter_by(email=email).first()
    if not target_user or target_user.id == current_user.id:
        flash("Invalid target user email.")
        return redirect(url_for("dashboard"))

    existing = DocumentPermission.query.filter_by(document_id=document.id, user_id=target_user.id).first()
    if existing:
        existing.permission = permission
    else:
        existing = DocumentPermission(document_id=document.id, user_id=target_user.id, permission=permission, granted_by=current_user.id)
        db.session.add(existing)

    db.session.commit()
    log_action("PERMISSION_GRANTED", document.id, f"Granted {permission} to {target_user.email}")
    flash("Permissions updated.")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:document_id>/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke_access(document_id, user_id):
    document = db.session.get(Document, document_id)
    if not document or document.owner_id != current_user.id:
        abort(403)

    permission = DocumentPermission.query.filter_by(document_id=document.id, user_id=user_id).first()
    if permission:
        db.session.delete(permission)
        db.session.commit()
        log_action("PERMISSION_REVOKED", document.id, f"Revoked access for user #{user_id}")

    flash("Access revoked immediately.")
    return redirect(url_for("dashboard"))

# ---------------- DELETE DOCUMENT ROUTE ----------------

@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    document = db.session.get(Document, document_id)

    if not document:
        abort(404)

    # Server Authorization Check: Only file owner or system Admin can delete
    if document.owner_id != current_user.id and current_user.role != "admin":
        log_action("DENIED_DELETE_ATTEMPT", document.id, "Unauthorized deletion attempt blocked")
        abort(403)

    title = document.title
    file_path = PRIVATE_FOLDER / document.stored_filename

    # Delete physical file from instance/private_uploads/
    if file_path.is_file():
        file_path.unlink()

    # Delete associated permission records
    DocumentPermission.query.filter_by(document_id=document.id).delete()

    # Delete database record
    db.session.delete(document)

    log_action("DELETE_DOCUMENT", details=f"Permanently deleted document: {title}")
    db.session.commit()

    flash(f"Document '{title}' deleted permanently.")
    return redirect(url_for("dashboard"))

@app.route("/admin")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        log_action("DENIED_ADMIN_ACCESS", details="Unauthorized admin route access attempt")
        abort(403)

    users = User.query.order_by(User.id.asc()).all()
    documents = Document.query.order_by(Document.created_at.desc()).all()
    permissions = DocumentPermission.query.all()
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(100).all()

    return render_template("admin_dashboard.html", users=users, documents=documents, permissions=permissions, logs=audit_logs)

@app.route("/audit")
@login_required
def audit_logs():
    if current_user.role != "admin":
        abort(403)

    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).all()
    return render_template("audit.html", logs=logs)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("login"))

@app.cli.command("create-admin")
def create_admin():
    import getpass
    username = input("Admin Username: ").strip()
    email = input("Admin Email: ").strip().lower()
    password = getpass.getpass("Admin Password: ")

    if not username or not email or len(password) < 8:
        print("Invalid entries. Password must be 8+ chars.")
        return

    admin = User(username=username, email=email, role="admin")
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"Success! Admin account created for {username}.")
# CORRECT POSITION: Above if __name__ == '__main__':

@app.route('/make-admin')
def make_admin():
    u = User.query.filter_by(username='admin').first()
    if u:
        u.role = 'admin'
        db.session.commit()
        return "Admin role granted successfully!"
    return "User 'admin' not found."

if __name__ == '__main__':
    app.run(debug=True)