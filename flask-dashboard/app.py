import os
import json
import datetime
import urllib.parse
import requests
from requests.exceptions import RequestException
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_mail import Mail, Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask import redirect, session, request, url_for, flash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-key')

# ---------------------- Mail Configuration ----------------------
app.config.update(
    MAIL_SERVER=os.getenv('SMTP_HOST'),
    MAIL_PORT=int(os.getenv('SMTP_PORT') or 587),
    MAIL_USERNAME=os.getenv('SMTP_USER'),
    MAIL_PASSWORD=os.getenv('SMTP_PASSWORD'),
    MAIL_USE_TLS=True
)
mail = Mail(app)

# ---------------------- Rate Limiter ----------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
try:
    limiter = Limiter(app, key_func=get_remote_address, storage_uri=REDIS_URL)
except Exception:
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# ---------------------- Database Setup ----------------------
MYSQL_USER = os.getenv('MYSQL_USER')
MYSQL_PASS = os.getenv('MYSQL_PASSWORD')
MYSQL_HOST = os.getenv('MYSQL_HOST', 'localhost')
MYSQL_DB = os.getenv('MYSQL_DATABASE', 'threat_monitor')

user_enc = urllib.parse.quote_plus(MYSQL_USER or "")
pass_enc = urllib.parse.quote_plus(MYSQL_PASS or "")
host_enc = MYSQL_HOST
DATABASE_URL = f"mysql+mysqlconnector://{user_enc}:{pass_enc}@{host_enc}/{MYSQL_DB}"

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ----------------------------------------------------------------------
#                     Patched Splunk Event Sender
# ----------------------------------------------------------------------
def send_splunk_event(event, severity="info", sourcetype="threat_monitor"):
    import json, datetime, os
    from requests.exceptions import RequestException

    def _default(o):
        if isinstance(o, (datetime.datetime, datetime.date)):
            return o.isoformat()
        return str(o)

    # normalize event: if dict of primitives keep it, else convert to string
    if isinstance(event, dict):
        # make sure all values are serializable primitives; if not, convert the dict to string
        try:
            json.dumps(event, default=_default)  # try serialization
            event_field = event
        except Exception:
            event_field = json.dumps(event, default=_default)
    else:
        # non-dict (string/int) - keep as-is wrapped inside a dict for clarity
        event_field = {"message": str(event)}

    # To be compatible with Splunk HEC variations, send event as a string if it's nested:
    # If event_field is a dict with simple keys, leave it. If values are not primitives, stringify the event.
    try:
        # if json dump yields an object (dict), keep as dict else stringify
        serialized_test = json.dumps(event_field, default=_default)
        # Decide whether to send event as object or string: safest is to send string when nested keys exist
        # We'll send as an object only if it's a flat dict of primitives (this is conservative)
        is_flat = all(not isinstance(v, (dict, list)) for v in (event_field if isinstance(event_field, dict) else {}).values())
        if not is_flat:
            event_payload = serialized_test  # JSON string
        else:
            event_payload = event_field      # keep as dict
    except Exception:
        event_payload = str(event_field)

    payload = {
        "time": int(datetime.datetime.utcnow().timestamp()),
        "event": event_payload,
        "severity": severity,
        "sourcetype": sourcetype,
        "index": os.getenv("SPLUNK_INDEX", "main"),
        "host": os.getenv("HOSTNAME", "flask-app")
    }

    # log payload
    try:
        app.logger.info("<<SPLUNK SEND>> payload=%s", json.dumps(payload, default=_default))
    except Exception:
        app.logger.info("<<SPLUNK SEND>> payload(unserializable)")

    headers = {
        "Authorization": f"Splunk {os.getenv('SPLUNK_HEC_TOKEN','')}",
        "Content-Type": "application/json"
    }

    verify_env = os.getenv("SPLUNK_VERIFY_SSL", "false").lower()
    if verify_env in ("1", "true", "yes"):
        ca_path = os.getenv("SPLUNK_CA_PATH", None)
        verify = ca_path if ca_path and os.path.exists(ca_path) else True
    else:
        verify = False

    try:
        r = requests.post(os.getenv('SPLUNK_HEC_URL'), headers=headers, json=payload, timeout=6, verify=verify)
        app.logger.info("<<SPLUNK RESP>> status=%s text=%s", r.status_code, r.text)
        r.raise_for_status()
        return True
    except RequestException as exc:
        try:
            app.logger.error("<<SPLUNK ERROR>> status=%s text=%s exc=%s", getattr(r, "status_code", None), getattr(r, "text", None), exc)
        except Exception:
            app.logger.error("<<SPLUNK ERROR>> exc=%s", exc)
        return False
# ----------------------------------------------------------------------

# ---------------------- Email Alert Function ----------------------
def send_email_alert(subject, body):
    try:
        msg = Message(subject, sender=app.config.get("MAIL_USERNAME"), recipients=[os.getenv('ALERT_EMAIL_TO')])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        app.logger.error("Failed to send email alert: %s", e)

# ---------------------- Flask-Login Setup ----------------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------------- User Model ----------------------
class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

Base.metadata.create_all(bind=engine)

@login_manager.user_loader
def load_user(user_id):
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == int(user_id)).first()
    finally:
        db.close()

# ---------------------- Routes ----------------------
@app.route("/")
def index():
    return redirect('/api/login')

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("Username and password required", "danger")
            return render_template("register.html")
        db = SessionLocal()
        try:
            if db.query(User).filter(User.username == username).first():
                flash("Username already exists", "danger")
                return render_template("register.html")
            password_hash = generate_password_hash(password)
            new_user = User(username=username, password_hash=password_hash)
            db.add(new_user)
            db.commit()
            flash("Account created. Please login.", "success")
            send_splunk_event({"type": "register", "username": username}, severity="info")
            return redirect('/api/login')
        finally:
            db.close()
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        db = SessionLocal()
        try:
            user = db.query(User).filter(User.username == username).first()
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                send_splunk_event({"type": "login_success", "username": username, "ip": request.remote_addr}, severity="info")
                return redirect('/api/dashboard')
            else:
                send_splunk_event({"type": "login_failed", "username": username, "ip": request.remote_addr}, severity="warning")
                flash("Invalid credentials", "danger")
                return render_template("login.html")
        finally:
            db.close()
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

@app.route('/api/logout', methods=['GET', 'POST'])
@login_required
def logout():
    username = session.pop('username', None)
    # send Splunk event (if you want)
    try:
        send_splunk_event({"type": "logout", "user": username, "ip": request.remote_addr}, severity="info")
    except Exception:
        app.logger.exception("send_splunk_event failed during logout")

    flash("You have been logged out.", "info")
    # redirect to proxied login route
    return redirect('/api' + url_for('login'))

@app.route('/search', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
@login_required
def search():
    # For GET (query string) use request.args, for POST use request.form
    if request.method == 'GET':
        q = request.args.get('q', '').strip()
    else:
        q = request.form.get('q', '').strip()

    if q:
        # simple SQLi pattern detection example
        if " or " in q.lower() or "1'='1" in q.lower():
            send_splunk_event({"type": "sqli_suspected", "query": q, "user": session.get('username'), "ip": request.remote_addr}, severity="high")
            return render_template('dashboard.html', message="Suspicious query detected")

    # normal search behavior (results variable assumed defined)
    results = []
    return render_template('dashboard.html', results=results, query=q)

# ---------------------- Main Entry ----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=(os.getenv('FLASK_ENV') == 'development'))

