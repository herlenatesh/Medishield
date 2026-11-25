import io
import os
import json
import sqlite3
import hashlib
import secrets
import html
import hmac
import textwrap
from datetime import datetime, timedelta

import pandas as pd
import qrcode
import streamlit as st

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


# ============================================================
# MEDISHIELD — FAKE MEDICINE DETECTION
# Educational security prototype using synthetic records
# ============================================================

APP_TITLE = "MediShield"
DB_NAME = "medishield.db"
PRIVATE_KEY_FILE = "medishield_private.pem"
PUBLIC_KEY_FILE = "medishield_public.pem"

SCAN_LIMIT = 3
PASSWORD_ITERATIONS = 200_000

ROLES = ["Admin", "Pharmacist", "Security Tester"]

RECORD_FIELDS = [
    "medicine_id",
    "name",
    "batch",
    "manufacturer",
    "manufactured",
    "expiry",
]

st.set_page_config(
    page_title="MediShield | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ============================================================
# PREMIUM UI AND CSS
# ============================================================

st.markdown(
    textwrap.dedent("""
    <style>
    .stApp {
        background: #0b1120;
        color: #edf2f7;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(
            180deg,
            #07111f 0%,
            #0b1929 55%,
            #102437 100%
        );
        border-right: 1px solid rgba(85, 230, 173, 0.25);
    }

    [data-testid="stSidebar"] > div:first-child {
        padding-top: 1.2rem;
    }

    h1, h2, h3 {
        color: #55e6ad !important;
    }

    .brand {
        color: #55e6ad;
        font-size: 29px;
        font-weight: 800;
    }

    .subtitle {
        color: #9ca9bc;
        font-size: 12px;
        margin-bottom: 25px;
    }

    .hero {
        background: linear-gradient(135deg, #12243a, #123b39);
        border: 1px solid #24594d;
        padding: 28px;
        border-radius: 18px;
        margin-bottom: 24px;
    }

    .hero-title {
        color: #55e6ad;
        font-size: 32px;
        font-weight: 800;
    }

    .hero-text {
        color: #d0dae7;
        font-size: 15px;
        margin-top: 10px;
    }

    .metric-card,
    .medicine-card {
        background: #121e31;
        border: 1px solid #263750;
        border-radius: 15px;
        padding: 20px;
        margin-bottom: 12px;
    }

    .metric-label {
        color: #9baac0;
        font-size: 13px;
        margin-bottom: 10px;
    }

    .metric-value {
        color: #55e6ad;
        font-size: 30px;
        font-weight: 800;
    }

    .medicine-name {
        font-size: 23px;
        color: #ffffff;
        font-weight: 750;
    }

    .medicine-id {
        color: #55e6ad;
        font-size: 13px;
        margin: 6px 0 18px;
    }

    .detail-label {
        color: #92a3ba;
        font-size: 12px;
        margin-bottom: 4px;
    }

    .detail-value {
        color: #f1f5f9;
        font-size: 15px;
        font-weight: 600;
        margin-bottom: 13px;
        overflow-wrap: anywhere;
    }

    .small-note {
        color: #9ba8ba;
        font-size: 12px;
    }

    .status-good {
        background: #12392f;
        border: 1px solid #1d7258;
        color: #57efab;
        border-radius: 11px;
        padding: 16px;
        margin: 12px 0;
    }

    .status-bad {
        background: #3c202b;
        border: 1px solid #8c3949;
        color: #ff9aa8;
        border-radius: 11px;
        padding: 16px;
        margin: 12px 0;
    }

    .status-info {
        background: #152d49;
        border: 1px solid #294f78;
        color: #85c7ff;
        border-radius: 11px;
        padding: 16px;
        margin: 12px 0;
    }

    div.stButton > button {
        border-radius: 10px;
        min-height: 43px;
        font-weight: 650;
        transition: all 0.2s ease;
    }

    div.stButton > button:hover {
        border-color: #55e6ad;
        color: #55e6ad;
        transform: translateY(-1px);
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] > div {
        gap: 8px;
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] label {
        display: flex;
        align-items: center;
        padding: 10px 12px;
        border: 1px solid transparent;
        border-radius: 12px;
        background: rgba(255, 255, 255, 0.025);
        color: #b9c8d8;
        transition: all 0.22s ease;
        cursor: pointer;
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
        background: rgba(85, 230, 173, 0.10);
        border-color: rgba(85, 230, 173, 0.35);
        color: #ffffff;
        transform: translateX(3px);
    }

    [data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
        background: linear-gradient(
            100deg,
            rgba(85, 230, 173, 0.20),
            rgba(16, 185, 129, 0.07)
        );
        border: 1px solid rgba(85, 230, 173, 0.55);
        color: #ffffff;
        box-shadow: 0 4px 18px rgba(85, 230, 173, 0.08);
    }

    [data-testid="stSidebar"] hr {
        border-color: rgba(148, 163, 184, 0.16);
    }

    [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
        color: #8da3b8;
    }

    [data-testid="stSidebar"] ::-webkit-scrollbar {
        width: 5px;
    }

    [data-testid="stSidebar"] ::-webkit-scrollbar-thumb {
        background: #2b8a5b;
        border-radius: 10px;
    }

    #MainMenu,
    footer {
        visibility: hidden;
    }
    </style>
    """),
    unsafe_allow_html=True,
)


# ============================================================
# DATABASE
# ============================================================

def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS medicines (
                medicine_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                batch TEXT NOT NULL,
                manufacturer TEXT NOT NULL,
                manufactured TEXT NOT NULL,
                expiry TEXT NOT NULL,
                record_hash TEXT,
                signature BLOB,
                created_at TEXT
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                detail TEXT NOT NULL,
                username TEXT DEFAULT 'system'
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_events (
                scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                medicine_id TEXT NOT NULL,
                scan_time TEXT NOT NULL,
                username TEXT DEFAULT 'system'
            )
            """
        )

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL
                    CHECK(role IN ('Admin', 'Pharmacist', 'Security Tester')),
                created_at TEXT NOT NULL
            )
            """
        )

        # Migrate older databases without deleting existing data.
        migrations = {
            "medicines": {
                "record_hash": "TEXT",
                "signature": "BLOB",
                "created_at": "TEXT",
            },
            "security_events": {
                "username": "TEXT DEFAULT 'system'",
            },
            "scan_events": {
                "username": "TEXT DEFAULT 'system'",
            },
        }

        for table, additions in migrations.items():
            existing_columns = {
                row["name"]
                for row in conn.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }

            for column, column_type in additions.items():
                if column not in existing_columns:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        f"{column} {column_type}"
                    )


init_database()


# ============================================================
# RSA KEYS AND DIGITAL SIGNATURES
# ============================================================

def load_or_create_keys():
    if (
        os.path.exists(PRIVATE_KEY_FILE)
        and os.path.exists(PUBLIC_KEY_FILE)
    ):
        with open(PRIVATE_KEY_FILE, "rb") as file:
            private_key = serialization.load_pem_private_key(
                file.read(),
                password=None,
            )

        with open(PUBLIC_KEY_FILE, "rb") as file:
            public_key = serialization.load_pem_public_key(
                file.read()
            )

        return private_key, public_key

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    with open(PRIVATE_KEY_FILE, "wb") as file:
        file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(PUBLIC_KEY_FILE, "wb") as file:
        file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key, public_key


PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()


def canonical_record(record):
    return json.dumps(
        {
            field: str(record[field])
            for field in RECORD_FIELDS
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def record_hash(record):
    return hashlib.sha256(canonical_record(record)).hexdigest()


def create_signature(record):
    return PRIVATE_KEY.sign(
        canonical_record(record),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def verify_signature(record, signature):
    if not signature:
        return False

    try:
        PUBLIC_KEY.verify(
            signature,
            canonical_record(record),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
    ):
        return False


def record_to_dict(row):
    return {
        field: row[field]
        for field in RECORD_FIELDS
    }


def get_medicines():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM medicines ORDER BY medicine_id"
        ).fetchall()

    return [dict(row) for row in rows]


def get_medicine(medicine_id):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM medicines WHERE medicine_id = ?",
            (medicine_id,),
        ).fetchone()

    return dict(row) if row else None


def current_username():
    user = st.session_state.get("authenticated_user")
    return user["username"] if user else "system"


def log_event(
    action,
    target,
    result,
    detail,
    username=None,
):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO security_events (
                event_time,
                action,
                target,
                result,
                detail,
                username
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                str(action),
                str(target),
                str(result),
                str(detail),
                username or current_username(),
            ),
        )


def register_medicine(record):
    signature = create_signature(record)
    digest = record_hash(record)

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO medicines (
                medicine_id,
                name,
                batch,
                manufacturer,
                manufactured,
                expiry,
                record_hash,
                signature,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["medicine_id"],
                record["name"],
                record["batch"],
                record["manufacturer"],
                record["manufactured"],
                record["expiry"],
                digest,
                signature,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )


def update_medicine_without_resigning(record):
    """Demo-only tampering: update fields but preserve the original hash/signature."""
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE medicines
            SET name = ?, batch = ?, manufacturer = ?, manufactured = ?, expiry = ?
            WHERE medicine_id = ?
            """,
            (
                record["name"],
                record["batch"],
                record["manufacturer"],
                record["manufactured"],
                record["expiry"],
                record["medicine_id"],
            ),
        )


def verify_registered_medicine(medicine_id):
    stored = get_medicine(medicine_id)

    if not stored:
        return False, "Medicine ID is not registered.", None

    record = record_to_dict(stored)

    if not stored.get("record_hash") or not stored.get("signature"):
        return False, "Security metadata is missing.", record

    if not verify_signature(record, stored["signature"]):
        return False, "DIGITAL SIGNATURE INVALID — Record data has changed since signing.", record

    if record_hash(record) != stored["record_hash"]:
        return False, "Record integrity check failed.", record

    return True, "Digital signature valid. Record integrity confirmed.", record


# ============================================================
# USER AUTHENTICATION
# ============================================================

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16).hex()

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt),
        PASSWORD_ITERATIONS,
    ).hex()

    return digest, salt


def create_user(username, password, role):
    username = username.strip()

    if len(username) < 3:
        return False, "Username must contain at least 3 characters."

    if len(password) < 10:
        return False, "Password must contain at least 10 characters."

    if role not in ROLES:
        return False, "Invalid role."

    digest, salt = hash_password(password)

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username,
                    password_hash,
                    salt,
                    role,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    digest,
                    salt,
                    role,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ),
            )

        log_event(
            "Create user",
            username,
            "ACCEPTED",
            f"Created account with role {role}.",
        )

        return True, "User created successfully."

    except sqlite3.IntegrityError:
        return False, "That username already exists."


def authenticate_user(username, password):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username.strip(),),
        ).fetchone()

    if not row:
        return None

    digest, _ = hash_password(password, row["salt"])

    if hmac.compare_digest(digest, row["password_hash"]):
        return {
            "username": row["username"],
            "role": row["role"],
        }

    return None


def user_count():
    with get_connection() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]


def get_users_df():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT user_id, username, role, created_at
            FROM users
            ORDER BY user_id
            """
        ).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def login_screen():
    st.markdown(
        textwrap.dedent("""
        <div class="hero">
            <div class="hero-title">🛡️ MediShield Login</div>
            <div class="hero-text">
                Secure access to the Fake Medicine Detection
                educational security prototype.
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    if user_count() == 0:
        st.subheader("Create the First Administrator")

        st.info(
            "No accounts exist yet. Create the initial Admin account."
        )

        with st.form("initial_admin_form"):
            username = st.text_input("Admin username")

            password = st.text_input(
                "Password (minimum 10 characters)",
                type="password",
            )

            confirm = st.text_input(
                "Confirm password",
                type="password",
            )

            submitted = st.form_submit_button(
                "Create Admin",
                type="primary",
            )

        if submitted:
            if password != confirm:
                st.error("Passwords do not match.")
            else:
                success, message = create_user(
                    username,
                    password,
                    "Admin",
                )

                if success:
                    st.success(
                        "Administrator created. Please sign in."
                    )
                    st.rerun()
                else:
                    st.error(message)

    else:
        with st.form("login_form"):
            username = st.text_input("Username")

            password = st.text_input(
                "Password",
                type="password",
            )

            submitted = st.form_submit_button(
                "Sign In",
                type="primary",
                use_container_width=True,
            )

        if submitted:
            user = authenticate_user(username, password)

            if user:
                st.session_state["authenticated_user"] = user

                log_event(
                    "Login",
                    user["username"],
                    "ACCEPTED",
                    "Successful login.",
                    user["username"],
                )

                st.rerun()

            else:
                log_event(
                    "Login",
                    username or "(empty username)",
                    "REJECTED",
                    "Failed login attempt.",
                    username or "unknown",
                )

                st.error("Invalid username or password.")


def require_roles(*allowed_roles):
    user = st.session_state.get("authenticated_user")

    if not user or user["role"] not in allowed_roles:
        st.error(
            "Access denied: your account role cannot access this page."
        )
        st.stop()


# ============================================================
# DEMONSTRATION DATA AND UTILITIES
# ============================================================

def seed_demo_data():
    if get_medicines():
        return

    demo_records = [
        (
            "MED1001",
            "Paracetamol",
            "BATCH-A101",
            "Demo Pharma A",
            "2025-01",
            "2027-01",
        ),
        (
            "MED1002",
            "Amoxicillin",
            "BATCH-B202",
            "Demo Pharma B",
            "2025-03",
            "2027-03",
        ),
        (
            "MED1003",
            "Cetirizine",
            "BATCH-C303",
            "Demo Pharma C",
            "2025-05",
            "2027-05",
        ),
        (
            "MED1004",
            "Ibuprofen",
            "BATCH-D404",
            "Demo Pharma D",
            "2025-07",
            "2027-07",
        ),
        (
            "MED1005",
            "Vitamin C",
            "BATCH-E505",
            "Demo Pharma E",
            "2025-09",
            "2027-09",
        ),
    ]

    for values in demo_records:
        record = dict(zip(RECORD_FIELDS, values))

        try:
            register_medicine(record)
        except sqlite3.IntegrityError:
            pass


seed_demo_data()


def valid_month(value):
    try:
        datetime.strptime(value, "%Y-%m")
        return True
    except (ValueError, TypeError):
        return False


def expiry_status(value):
    try:
        expiry = datetime.strptime(value, "%Y-%m").replace(day=1)
        current = datetime.now().replace(day=1)
        days_remaining = (expiry - current).days

        if expiry < current:
            return "EXPIRED"

        if days_remaining <= 90:
            return "EXPIRING SOON"

        return "VALID"

    except (ValueError, TypeError):
        return "INVALID DATE"


def get_events():
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT
                event_id,
                event_time,
                action,
                target,
                result,
                detail,
                username
            FROM security_events
            ORDER BY event_id DESC
            """
        ).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_scan_count_24h(medicine_id):
    cutoff = (
        datetime.now() - timedelta(hours=24)
    ).strftime("%Y-%m-%d %H:%M:%S")

    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM scan_events
            WHERE medicine_id = ? AND scan_time >= ?
            """,
            (medicine_id, cutoff),
        ).fetchone()

    return row["total"]


def record_scan(medicine_id):
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_events (
                medicine_id,
                scan_time,
                username
            )
            VALUES (?, ?, ?)
            """,
            (
                medicine_id,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                current_username(),
            ),
        )

    count = get_scan_count_24h(medicine_id)

    if count > SCAN_LIMIT:
        log_event(
            "Repeated scan monitoring",
            medicine_id,
            "SUSPICIOUS",
            f"{count} scans recorded within 24 hours.",
        )
        return count, True

    log_event(
        "Medicine verification scan",
        medicine_id,
        "ACCEPTED",
        f"Scan {count} within 24 hours.",
    )

    return count, False


def make_qr(medicine_id):
    image = qrcode.make(medicine_id)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def show_metric(label, value, caption=""):
    label = html.escape(str(label))
    value = html.escape(str(value))
    caption = html.escape(str(caption))

    st.markdown(
        (
            '<div class="metric-card">'
            f'<div class="metric-label">{label}</div>'
            f'<div class="metric-value">{value}</div>'
            f'<div class="small-note">{caption}</div>'
            '</div>'
        ),
        unsafe_allow_html=True,
    )


def show_medicine_card(record):
    # Build the HTML without leading indentation so Streamlit does not
    # interpret indented lines as a Markdown code block.
    card_html = (
        '<div class="medicine-card">'
        f'<div class="medicine-name">💊 {html.escape(str(record["name"]))}</div>'
        f'<div class="medicine-id">Medicine ID: {html.escape(str(record["medicine_id"]))}</div>'
        '<div class="detail-label">BATCH NUMBER</div>'
        f'<div class="detail-value">{html.escape(str(record["batch"]))}</div>'
        '<div class="detail-label">MANUFACTURER</div>'
        f'<div class="detail-value">{html.escape(str(record["manufacturer"]))}</div>'
        '<div class="detail-label">MANUFACTURED</div>'
        f'<div class="detail-value">{html.escape(str(record["manufactured"]))}</div>'
        '<div class="detail-label">EXPIRY DATE</div>'
        f'<div class="detail-value">{html.escape(str(record["expiry"]))}</div>'
        '</div>'
    )
    st.markdown(card_html, unsafe_allow_html=True)


# ============================================================
# AUTHENTICATION GATE
# ============================================================

if not st.session_state.get("authenticated_user"):
    login_screen()
    st.stop()

user = st.session_state["authenticated_user"]


# ============================================================
# ROLE-BASED NAVIGATION
# ============================================================

page_access = {
    "Admin": [
        "🏠 Security Overview",
        "💊 Medicine Registry",
        "📷 Verify Medicine",
        "⏳ Expiry Alerts",
        "🚨 Fraud Risk Review",
        "🛡️ Medicine Integrity Testing",
        "🧪 Automated Security Tests",
        "🔎 Threat Detection & Monitoring",
        "📋 Security Events",
        "📄 PDF Report",
        "👥 User Management",
    ],
    "Pharmacist": [
        "🏠 Security Overview",
        "💊 Medicine Registry",
        "📷 Verify Medicine",
        "⏳ Expiry Alerts",
        "🚨 Fraud Risk Review",
    ],
    "Security Tester": [
        "🏠 Security Overview",
        "🛡️ Medicine Integrity Testing",
        "🧪 Automated Security Tests",
        "🔎 Threat Detection & Monitoring",
        "📋 Security Events",
    ],
}


# ============================================================
# SIDEBAR BRANDING — NATIVE STREAMLIT COMPONENTS
# Uses native widgets instead of HTML so markup cannot appear as text.
# ============================================================

with st.sidebar:
    st.markdown("---")
    st.title("🛡️ MediShield")
    st.caption("MEDICINE SECURITY PLATFORM")
    st.success("● SYSTEM ACTIVE")
    st.markdown("---")
    st.success(f"Signed in: {user['username']}")
    st.caption(f"Role: {user['role']}")

    page = st.radio(
        "NAVIGATION",
        page_access.get(
            user["role"],
            page_access["Pharmacist"],
        ),
        label_visibility="collapsed",
    )

    if st.button("↪ Logout", use_container_width=True):
        log_event(
            "Logout",
            user["username"],
            "ACCEPTED",
            "User logged out.",
        )
        st.session_state.pop("authenticated_user", None)
        st.rerun()


# ============================================================
# SECURITY OVERVIEW
# ============================================================

if page.endswith("Security Overview"):
    st.markdown(
        textwrap.dedent("""
        <div class="hero">
            <div class="hero-title">
                🛡️ MediShield Security Center
            </div>
            <div class="hero-text">
                Medicine authentication, digital signatures,
                QR identification, expiry monitoring and security analytics.
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    medicines = get_medicines()
    events = get_events()

    total_events = len(events)

    accepted = (
        int((events["result"] == "ACCEPTED").sum())
        if not events.empty else 0
    )

    flagged = (
        int(
            events["result"].isin(
                ["REJECTED", "SUSPICIOUS"]
            ).sum()
        )
        if not events.empty else 0
    )

    columns = st.columns(4)

    metrics = [
        ("Medicine Records", len(medicines), "Registered records"),
        ("Security Events", total_events, "Recorded activities"),
        ("Accepted Events", accepted, "Successful operations"),
        ("Flagged Events", flagged, "Rejected or suspicious"),
    ]

    for column, metric in zip(columns, metrics):
        with column:
            show_metric(*metric)

    st.subheader("Security Capabilities")

    left, right = st.columns(2)

    with left:
        st.markdown(
            textwrap.dedent("""
            <div class="medicine-card">
                <h3>🔐 Digital Signature</h3>
                <p>
                    RSA signatures verify signed record integrity.
                </p>
            </div>

            <div class="medicine-card">
                <h3>🛡️ Medicine Integrity Testing</h3>
                <p>
                    Controlled tests demonstrate record tampering
                    and invalid signatures.
                </p>
            </div>
            """),
            unsafe_allow_html=True,
        )

    with right:
        st.markdown(
            textwrap.dedent("""
            <div class="medicine-card">
                <h3>📱 QR Identification</h3>
                <p>
                    QR codes identify records registered in MediShield.
                </p>
            </div>

            <div class="medicine-card">
                <h3>📊 Security Monitoring</h3>
                <p>
                    Verification outcomes and security events are logged.
                </p>
            </div>
            """),
            unsafe_allow_html=True,
        )

    st.subheader("Recent Security Events")

    if events.empty:
        st.info("No events recorded yet.")
    else:
        st.dataframe(
            events.head(8),
            use_container_width=True,
            hide_index=True,
        )

    st.caption(
        "Educational prototype using synthetic records. "
        "A valid signature does not prove physical medicine authenticity."
    )


# ============================================================
# MEDICINE REGISTRY
# ============================================================

elif page.endswith("Medicine Registry"):
    require_roles("Admin", "Pharmacist")

    st.title("💊 Medicine Registry")

    with st.expander("➕ Register a New Medicine"):
        with st.form("register_medicine_form"):
            name = st.text_input("Medicine Name")
            batch = st.text_input("Batch Number")
            manufacturer = st.text_input("Manufacturer")

            manufactured = st.text_input(
                "Manufacturing Month (YYYY-MM)",
                value=datetime.now().strftime("%Y-%m"),
            )

            expiry_default = (
                datetime.now().replace(day=1)
                + timedelta(days=730)
            ).strftime("%Y-%m")

            expiry = st.text_input(
                "Expiry Month (YYYY-MM)",
                value=expiry_default,
            )

            submitted = st.form_submit_button(
                "Register and Sign Record",
                type="primary",
            )

        if submitted:
            name = name.strip()
            batch = batch.strip()
            manufacturer = manufacturer.strip()

            if not all([name, batch, manufacturer]):
                st.error("Fill in all medicine details.")

            elif not valid_month(manufactured) or not valid_month(expiry):
                st.error("Dates must use YYYY-MM format.")

            elif expiry < manufactured:
                st.error(
                    "Expiry cannot be earlier than manufacturing date."
                )

            else:
                medicine_id = "MED" + secrets.token_hex(3).upper()

                record = {
                    "medicine_id": medicine_id,
                    "name": name,
                    "batch": batch,
                    "manufacturer": manufacturer,
                    "manufactured": manufactured,
                    "expiry": expiry,
                }

                try:
                    register_medicine(record)

                    log_event(
                        "Register medicine",
                        medicine_id,
                        "ACCEPTED",
                        "Synthetic record registered and digitally signed.",
                    )

                    st.success(f"Registered successfully: {medicine_id}")
                    st.rerun()

                except sqlite3.IntegrityError:
                    st.error(
                        "Registration failed. Please try again."
                    )

    medicines = get_medicines()

    # Demo-only tampering editor: preserve the original digital signature.
    if medicines:
        with st.expander("🧪 Tampering Demonstration — Change Existing Record"):
            st.warning(
                "Use only for synthetic/demo records. This intentionally changes "
                "stored fields without replacing the original signature, so verification "
                "should reject the changed record."
            )
            demo_id = st.selectbox(
                "Choose an existing medicine record",
                [medicine["medicine_id"] for medicine in medicines],
                key="tamper_medicine_select",
            )
            existing = get_medicine(demo_id)
            st.caption("The medicine ID stays the same; the original hash and signature are preserved.")

            with st.form("tamper_existing_medicine_form"):
                edit_name = st.text_input(
                    "Medicine Name", value=existing["name"], key="tamper_name"
                )
                edit_batch = st.text_input(
                    "Batch Number", value=existing["batch"], key="tamper_batch"
                )
                edit_manufacturer = st.text_input(
                    "Manufacturer", value=existing["manufacturer"], key="tamper_manufacturer"
                )
                edit_manufactured = st.text_input(
                    "Manufacturing Month (YYYY-MM)", value=existing["manufactured"], key="tamper_manufactured"
                )
                edit_expiry = st.text_input(
                    "Expiry Month (YYYY-MM)", value=existing["expiry"], key="tamper_expiry"
                )
                save_tamper = st.form_submit_button(
                    "Modify Data Without Re-signing", type="primary"
                )

            if save_tamper:
                edit_name = edit_name.strip()
                edit_batch = edit_batch.strip()
                edit_manufacturer = edit_manufacturer.strip()
                if not all([edit_name, edit_batch, edit_manufacturer]):
                    st.error("Fill in all medicine details.")
                elif not valid_month(edit_manufactured) or not valid_month(edit_expiry):
                    st.error("Dates must use YYYY-MM format.")
                elif edit_expiry < edit_manufactured:
                    st.error("Expiry cannot be earlier than manufacturing date.")
                else:
                    changed_record = {
                        "medicine_id": demo_id,
                        "name": edit_name,
                        "batch": edit_batch,
                        "manufacturer": edit_manufacturer,
                        "manufactured": edit_manufactured,
                        "expiry": edit_expiry,
                    }
                    update_medicine_without_resigning(changed_record)
                    log_event(
                        "Tampering demonstration",
                        demo_id,
                        "TEST MODIFICATION",
                        "Demo medicine fields changed while original hash/signature were preserved.",
                    )
                    st.success("Demo data changed. Now open Verify Medicine and verify this same ID; the original signature should be rejected.")
                    st.rerun()

    if medicines:
        dataframe = pd.DataFrame(
            [
                {
                    "Medicine ID": medicine["medicine_id"],
                    "Name": medicine["name"],
                    "Batch": medicine["batch"],
                    "Manufacturer": medicine["manufacturer"],
                    "Manufactured": medicine["manufactured"],
                    "Expiry": medicine["expiry"],
                    "Expiry Status": expiry_status(medicine["expiry"]),
                }
                for medicine in medicines
            ]
        )

        st.subheader("Registered Medicine Records")

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

        selected_id = st.selectbox(
            "Select a medicine to generate its QR code",
            [medicine["medicine_id"] for medicine in medicines],
        )

        if st.button("Generate QR Code"):
            record = get_medicine(selected_id)
            qr_bytes = make_qr(selected_id)

            left, right = st.columns([1, 2])

            with left:
                st.image(qr_bytes, width=230)

            with right:
                st.subheader(record["name"])
                st.write(f"Medicine ID: **{selected_id}**")
                st.write(f"Batch: **{record['batch']}**")
                st.caption(
                    "The QR code contains the medicine ID only."
                )

                st.download_button(
                    "Download QR Code",
                    qr_bytes,
                    file_name=f"{selected_id}_QR.png",
                    mime="image/png",
                )

    else:
        st.info("No medicine records have been registered yet.")


# ============================================================
# VERIFY MEDICINE — MANUAL ID AND QR IMAGE SCANNING
# ============================================================

elif page.endswith("Verify Medicine"):
    require_roles("Admin", "Pharmacist")

    st.title("🔐 Verify Medicine")

    st.subheader("📷 Scan a Medicine QR Code")

    st.caption(
        "Upload a clear image of a MediShield QR code. "
        "You can also verify a medicine by entering its ID below."
    )

    qr_file = st.file_uploader(
        "Upload QR image",
        type=["png", "jpg", "jpeg"],
        key="verify_qr_upload",
    )

    if qr_file is not None:
        try:
            import cv2
            import numpy as np

            image_bytes = qr_file.getvalue()
            image_array = np.frombuffer(
                image_bytes,
                dtype=np.uint8,
            )

            decoded_image = cv2.imdecode(
                image_array,
                cv2.IMREAD_COLOR,
            )

            if decoded_image is None:
                st.error("The uploaded image could not be read.")

            else:
                detector = cv2.QRCodeDetector()
                decoded_text, points, _ = detector.detectAndDecode(
                    decoded_image
                )

                if decoded_text:
                    scanned_id = decoded_text.strip().upper()

                    st.success(f"QR code detected: {scanned_id}")

                    if st.button(
                        "Verify Scanned QR",
                        type="primary",
                    ):
                        valid, message, record = (
                            verify_registered_medicine(scanned_id)
                        )

                        if valid:
                            st.success(
                                "SIGNATURE VALID — " + message
                            )

                            show_medicine_card(record)

                            count, suspicious = record_scan(scanned_id)

                            log_event(
                                "QR medicine verification",
                                scanned_id,
                                "ACCEPTED",
                                message,
                            )

                            if suspicious:
                                st.warning(
                                    f"Repeated scan alert: {count} scans "
                                    "in 24 hours. Review this activity."
                                )

                            if expiry_status(record["expiry"]) == "EXPIRED":
                                st.error(
                                    "Expiry alert: this record is expired."
                                )

                            elif (
                                expiry_status(record["expiry"])
                                == "EXPIRING SOON"
                            ):
                                st.warning(
                                    "This record is approaching its expiry month."
                                )

                        else:
                            st.error(
                                "VERIFICATION FAILED — " + message
                            )

                            log_event(
                                "QR medicine verification",
                                scanned_id,
                                "REJECTED",
                                message,
                            )

                else:
                    st.warning(
                        "No QR code was detected. Upload a clear image."
                    )

        except ImportError:
            st.error(
                "QR image scanning requires OpenCV and NumPy. "
                "Install them with: "
                "pip install opencv-python-headless numpy"
            )

        except Exception as exc:
            st.error(f"Could not scan the QR image: {exc}")

    st.markdown("---")

    medicines = get_medicines()
    medicine_ids = [
        medicine["medicine_id"]
        for medicine in medicines
    ]

    medicine_id = st.text_input(
        "Medicine ID",
        placeholder="Enter a medicine ID, e.g. MED1001",
    ).strip().upper()

    if st.button("Verify Record", type="primary"):
        if not medicine_id:
            st.warning("Enter a medicine ID.")

        else:
            valid, message, record = (
                verify_registered_medicine(medicine_id)
            )

            if valid:
                st.success(
                    "SIGNATURE VALID — " + message
                )

                show_medicine_card(record)

                count, suspicious = record_scan(medicine_id)

                log_event(
                    "Verify medicine",
                    medicine_id,
                    "ACCEPTED",
                    message,
                )

                if suspicious:
                    st.warning(
                        f"Repeated scan alert: {count} scans "
                        "in 24 hours. Review this activity."
                    )
                else:
                    st.info(
                        f"Scans in the last 24 hours: {count}"
                    )

                status = expiry_status(record["expiry"])

                if status == "EXPIRED":
                    st.error(
                        "Expiry alert: this registered record is expired. "
                        "Do not use this demonstration result as real medical advice."
                    )

                elif status == "EXPIRING SOON":
                    st.warning(
                        "Expiry alert: this record is approaching its expiry month."
                    )

            else:
                st.error("VERIFICATION FAILED — " + message)

                log_event(
                    "Verify medicine",
                    medicine_id,
                    "REJECTED",
                    message,
                )

    st.caption(
        "A valid signature confirms the record matches signed data; "
        "it does not prove the physical package is genuine."
    )


# ============================================================
# EXPIRY ALERTS
# ============================================================

elif page.endswith("Expiry Alerts"):
    require_roles("Admin", "Pharmacist")

    st.title("⏳ Medicine Expiry Alerts")

    medicines = get_medicines()

    rows = [
        {
            "Medicine ID": medicine["medicine_id"],
            "Name": medicine["name"],
            "Batch": medicine["batch"],
            "Manufacturer": medicine["manufacturer"],
            "Expiry": medicine["expiry"],
            "Status": expiry_status(medicine["expiry"]),
        }
        for medicine in medicines
    ]

    dataframe = pd.DataFrame(rows)

    if dataframe.empty:
        st.info("No medicine records found.")

    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            show_metric(
                "Expired",
                int((dataframe["Status"] == "EXPIRED").sum()),
            )

        with col2:
            show_metric(
                "Expiring Soon",
                int(
                    (
                        dataframe["Status"] == "EXPIRING SOON"
                    ).sum()
                ),
            )

        with col3:
            show_metric(
                "Valid",
                int((dataframe["Status"] == "VALID").sum()),
            )

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

        expiring = dataframe[
            dataframe["Status"].isin(
                ["EXPIRED", "EXPIRING SOON"]
            )
        ]

        if expiring.empty:
            st.success(
                "No expired or soon-to-expire records in the current dataset."
            )
        else:
            st.warning("Review these expiry alerts:")

            st.dataframe(
                expiring,
                use_container_width=True,
                hide_index=True,
            )

        st.download_button(
            "Download Expiry Report CSV",
            dataframe.to_csv(index=False).encode("utf-8"),
            "medishield_expiry_report.csv",
            "text/csv",
        )


# ============================================================
# FRAUD RISK REVIEW
# ============================================================

elif page.endswith("Fraud Risk Review"):
    require_roles("Admin", "Pharmacist")

    st.title("🚨 Fraud Risk Review")

    medicines = get_medicines()
    risk_rows = []

    for medicine in medicines:
        valid, message, _ = verify_registered_medicine(
            medicine["medicine_id"]
        )

        scans = get_scan_count_24h(
            medicine["medicine_id"]
        )

        status = expiry_status(medicine["expiry"])

        indicators = []
        score = 0

        if not valid:
            indicators.append("Signature/integrity failure")
            score += 60

        if scans > SCAN_LIMIT:
            indicators.append(f"Repeated scans ({scans}/24h)")
            score += 30

        if status == "EXPIRED":
            indicators.append("Expired record")
            score += 25

        elif status == "EXPIRING SOON":
            indicators.append("Expiring soon")
            score += 10

        if not indicators:
            indicators.append("No current risk indicator")

        score = min(score, 100)

        if score >= 60:
            risk_level = "HIGH"
        elif score >= 25:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        risk_rows.append(
            {
                "Medicine ID": medicine["medicine_id"],
                "Name": medicine["name"],
                "Risk Score": score,
                "Risk Level": risk_level,
                "Scans (24h)": scans,
                "Expiry Status": status,
                "Indicators": "; ".join(indicators),
            }
        )

    dataframe = pd.DataFrame(risk_rows)

    if dataframe.empty:
        st.info("No medicine records available for risk review.")

    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            show_metric(
                "High Risk",
                int((dataframe["Risk Level"] == "HIGH").sum()),
            )

        with col2:
            show_metric(
                "Medium Risk",
                int((dataframe["Risk Level"] == "MEDIUM").sum()),
            )

        with col3:
            show_metric(
                "Low Risk",
                int((dataframe["Risk Level"] == "LOW").sum()),
            )

        st.dataframe(
            dataframe.sort_values(
                "Risk Score",
                ascending=False,
            ),
            use_container_width=True,
            hide_index=True,
        )

        st.caption(
            "Risk scores are demonstration indicators, "
            "not proof of counterfeit medicine."
        )

        st.download_button(
            "Download Fraud Risk CSV",
            dataframe.to_csv(index=False).encode("utf-8"),
            "medishield_fraud_risk.csv",
            "text/csv",
        )


# ============================================================
# MEDICINE INTEGRITY TESTING
# ============================================================

elif page.endswith("Medicine Integrity Testing"):
    require_roles("Admin", "Security Tester")

    st.title("🛡️ Medicine Integrity Testing")

    st.info(
        "Controlled tests run only against synthetic records in this app."
    )

    medicines = get_medicines()
    medicine_ids = [
        medicine["medicine_id"]
        for medicine in medicines
    ]

    if medicine_ids:
        medicine_id = st.selectbox(
            "Choose a test record",
            medicine_ids,
        )

        test_name = st.selectbox(
            "Security Test",
            [
                "Tamper with medicine name",
                "Tamper with expiry date",
                "Modify signature",
                "Unknown medicine ID",
                "Replay scan simulation",
                "Record integrity check",
            ],
        )

        if st.button("Run Security Test", type="primary"):
            stored = get_medicine(medicine_id)
            original = record_to_dict(stored)
            signature = stored.get("signature") or b""

            passed = False
            outcome = "REJECTED"
            detail = ""

            if test_name == "Tamper with medicine name":
                modified = original.copy()
                modified["name"] += " ALTERED"

                passed = not verify_signature(
                    modified,
                    signature,
                )

                detail = (
                    "Modified medicine name should fail signature validation."
                )

            elif test_name == "Tamper with expiry date":
                modified = original.copy()
                modified["expiry"] = "2099-12"

                passed = not verify_signature(
                    modified,
                    signature,
                )

                detail = (
                    "Modified expiry should fail signature validation."
                )

            elif test_name == "Modify signature":
                if signature:
                    altered = bytearray(signature)
                    altered[0] ^= 1

                    passed = not verify_signature(
                        original,
                        bytes(altered),
                    )
                else:
                    passed = True

                detail = "Modified signature should be rejected."

            elif test_name == "Unknown medicine ID":
                fake_id = "FAKE-" + secrets.token_hex(4).upper()
                passed = get_medicine(fake_id) is None
                detail = f"Unknown ID checked: {fake_id}"

            elif test_name == "Replay scan simulation":
                count, suspicious = record_scan(medicine_id)

                passed = True
                outcome = (
                    "SUSPICIOUS"
                    if suspicious
                    else "ACCEPTED"
                )

                detail = (
                    f"Simulated scan {count} within 24 hours."
                )

                st.write(
                    f"Scans in 24 hours: **{count}**"
                )

            elif test_name == "Record integrity check":
                valid, message, _ = verify_registered_medicine(
                    medicine_id
                )

                # The security test passes when the verification result is
                # correctly interpreted, whether the record is valid or tampered.
                passed = True
                outcome = "ACCEPTED" if valid else "REJECTED"
                detail = (
                    "Record integrity verified; signature is valid."
                    if valid
                    else f"Tampering or invalid security metadata detected: {message}"
                )

            # For attack simulations, PASS means the attack was blocked.
            # Do not overwrite the real verification outcome for the integrity check.
            if test_name not in ("Replay scan simulation", "Record integrity check"):
                outcome = "REJECTED" if passed else "ACCEPTED"

            log_event(
                test_name,
                medicine_id,
                outcome,
                detail,
            )

            if passed:
                st.success(
                    "TEST PASSED: expected security behavior observed."
                )
            else:
                st.error(
                    "TEST FAILED: expected security behavior was not observed."
                )

            st.write(f"**Outcome:** {outcome}")
            st.caption(detail)

    else:
        st.warning("Register a synthetic medicine first.")


# ============================================================
# AUTOMATED SECURITY TESTS
# ============================================================

elif page.endswith("Automated Security Tests"):
    require_roles("Admin", "Security Tester")

    st.title("🧪 Automated Security Test Suite")

    medicines = get_medicines()

    st.write(
        "Run six checks for every registered medicine. "
        f"Current records: **{len(medicines)}**."
    )

    if not medicines:
        st.warning("No registered medicines to test.")

    if st.button(
        "Run All Automated Tests",
        type="primary",
        disabled=not medicines,
    ):
        results = []

        for medicine in medicines:
            medicine_id = medicine["medicine_id"]
            stored = get_medicine(medicine_id)

            record = record_to_dict(stored)
            signature = stored.get("signature") or b""
            digest = stored.get("record_hash") or ""

            checks = []

            valid_registered, validation_message, _ = verify_registered_medicine(medicine_id)
            checks.append(
                (
                    "Valid record integrity and signature",
                    valid_registered,
                    validation_message,
                )
            )

            modified = record.copy()
            modified["name"] += " ALTERED"

            checks.append(
                (
                    "Name tampering detection",
                    not verify_signature(modified, signature),
                    "Modified name should fail signature validation.",
                )
            )

            modified = record.copy()
            modified["expiry"] = "2099-12"

            checks.append(
                (
                    "Expiry tampering detection",
                    not verify_signature(modified, signature),
                    "Modified expiry should fail signature validation.",
                )
            )

            altered = bytearray(signature) if signature else bytearray()

            if altered:
                altered[0] ^= 1

            checks.append(
                (
                    "Modified signature detection",
                    (
                        not verify_signature(record, bytes(altered))
                    ) if altered else True,
                    "Modified signature should be rejected.",
                )
            )

            fake_id = "UNKNOWN-" + secrets.token_hex(6)

            checks.append(
                (
                    "Unknown medicine ID",
                    get_medicine(fake_id) is None,
                    "Unregistered ID must not return a record.",
                )
            )

            checks.append(
                (
                    "Stored record hash",
                    bool(digest) and record_hash(record) == digest,
                    "Recalculated hash compared with stored hash.",
                )
            )

            for label, passed, detail in checks:
                results.append(
                    {
                        "Medicine ID": medicine_id,
                        "Test": label,
                        "Status": "PASS" if passed else "FAIL",
                        "Details": detail,
                    }
                )

        dataframe = pd.DataFrame(results)

        st.session_state["automated_test_results"] = (
            dataframe.to_dict("records")
        )

        passed_count = int(
            (dataframe["Status"] == "PASS").sum()
        )

        failed_count = int(
            (dataframe["Status"] == "FAIL").sum()
        )

        log_event(
            "Automated security test suite",
            "ALL_REGISTERED_MEDICINES",
            "ACCEPTED" if failed_count == 0 else "SUSPICIOUS",
            (
                f"Tested {len(medicines)} medicines; "
                f"{passed_count} checks passed and "
                f"{failed_count} failed."
            ),
        )

    saved_results = st.session_state.get(
        "automated_test_results",
        [],
    )

    if saved_results:
        dataframe = pd.DataFrame(saved_results)

        passed_count = int(
            (dataframe["Status"] == "PASS").sum()
        )

        failed_count = int(
            (dataframe["Status"] == "FAIL").sum()
        )

        columns = st.columns(3)

        with columns[0]:
            show_metric("Total Checks", len(dataframe))

        with columns[1]:
            show_metric("Tests Passed", passed_count)

        with columns[2]:
            show_metric("Tests Failed", failed_count)

        st.dataframe(
            dataframe,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download Automated Test Results",
            dataframe.to_csv(index=False).encode("utf-8"),
            "medishield_automated_test_results.csv",
            "text/csv",
        )

        st.caption(
            f"Each medicine receives six checks. "
            f"Expected total: {len(medicines) * 6} checks."
        )


# ============================================================
# THREAT DETECTION AND MONITORING
# ============================================================

elif page.endswith("Threat Detection & Monitoring"):
    require_roles("Admin", "Security Tester")

    st.title("🔎 Threat Detection & Monitoring")
    st.write(
        "Rule-based monitoring of recorded security events plus a live integrity scan. "
        "Findings are indicators for review, not proof of fraud."
    )

    # A live scan ensures the page can detect current database tampering even
    # if the earlier edit/verification path did not create an audit event.
    if st.button("Run Live Medicine Integrity Scan", type="primary"):
        medicines_to_scan = get_medicines()
        flagged = 0
        if not medicines_to_scan:
            st.warning("No registered medicines were found. Add a synthetic medicine before running an integrity scan.")
        else:
            for item in medicines_to_scan:
                mid = item["medicine_id"]
                valid, message, _ = verify_registered_medicine(mid)
                if not valid:
                    flagged += 1
                    log_event(
                        "Live integrity scan",
                        mid,
                        "SUSPICIOUS",
                        f"Integrity scan detected a problem: {message}",
                    )
            if flagged:
                log_event(
                    "Live integrity scan summary",
                    "ALL_REGISTERED_MEDICINES",
                    "SUSPICIOUS",
                    f"Scan checked {len(medicines_to_scan)} record(s); {flagged} failed integrity verification.",
                )
                st.error(f"Scan complete: {flagged} of {len(medicines_to_scan)} medicine record(s) failed integrity verification. See Security Events for details.")
            else:
                log_event(
                    "Live integrity scan summary",
                    "ALL_REGISTERED_MEDICINES",
                    "ACCEPTED",
                    f"Scan checked {len(medicines_to_scan)} record(s); all passed integrity verification.",
                )
                st.success(f"Scan complete: all {len(medicines_to_scan)} registered medicine record(s) passed signature and hash checks.")
            st.rerun()

    events = get_events()
    if events.empty:
        st.info(
            "No security events have been recorded yet. Verify a medicine, "
            "run a security test, or use the demo tampering editor to create events."
        )
    else:
        detections = []
        for _, event in events.iterrows():
            result = str(event.get("result", "")).strip().upper()
            action = str(event.get("action", "")).strip()
            detail = str(event.get("detail", "")).strip()
            action_lower = action.lower()
            detail_lower = detail.lower()

            severity = "INFO"
            reason = "Routine recorded activity"
            recommendation = "No action required unless context suggests otherwise."

            # Match explicit results and also the event's action/details. This
            # catches tampering events whose result is TEST MODIFICATION rather
            # than REJECTED, and avoids depending on exact capitalization.
            if result == "SUSPICIOUS":
                severity = "HIGH"
                reason = "Event was explicitly flagged as suspicious"
                recommendation = "Review the user, target, timestamp, and related events."
            elif result in {"REJECTED", "INVALID", "FAILED"}:
                severity = "MEDIUM"
                reason = "A verification or operation was rejected"
                recommendation = "Check the target record and event details."

            if any(term in (action_lower + " " + detail_lower) for term in (
                "digital signature invalid", "signature invalid", "invalid signature",
                "record integrity check failed", "security metadata is missing",
                "integrity scan detected a problem", "record data has changed",
            )):
                severity = "HIGH"
                reason = "Digital signature or record integrity verification failed"
                recommendation = "Preserve the original signature and audit record; inspect the medicine record for unauthorized changes."

            if "login" in action_lower and result in {"REJECTED", "INVALID", "FAILED"}:
                severity = "HIGH"
                reason = "Failed login attempt"
                recommendation = "Confirm whether the attempt was expected; consider rate limiting."

            if any(term in action_lower or term in detail_lower for term in (
                "tamper", "integrity failure", "signature invalid", "invalid signature",
                "record data has changed", "modified after signing", "modified data",
            )):
                severity = "HIGH"
                reason = "Possible medicine-record tampering or integrity failure"
                recommendation = "Verify the medicine again, preserve the event, and review the original signed record."

            if result == "TEST MODIFICATION":
                severity = "HIGH"
                reason = "Tampering demonstration changed data while preserving the original signature"
                recommendation = "Run Verify Medicine for this same ID and confirm the signature is rejected."

            if (
                "repeated scan" in action_lower
                or "repeated scan" in detail_lower
                or ("scan" in action_lower and "within 24 hours" in detail_lower and result == "SUSPICIOUS")
            ):
                severity = "HIGH"
                reason = "Repeated scan threshold triggered"
                recommendation = "Investigate the scan pattern and context; repeated scans can also be legitimate."

            if "unknown medicine" in action_lower or "unknown id" in detail_lower:
                severity = "MEDIUM" if severity != "HIGH" else severity
                reason = "Unknown medicine identifier was checked"
                recommendation = "Confirm whether the identifier is registered and whether the attempt was expected."

            detections.append({
                "Event ID": event.get("event_id"),
                "Time": event.get("event_time"),
                "Action": action,
                "Target": event.get("target"),
                "Result": result,
                "Severity": severity,
                "Detection Reason": reason,
                "User": event.get("username", "system"),
                "Details": detail,
                "Recommendation": recommendation,
            })

        dataframe = pd.DataFrame(detections)
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            show_metric("High Severity", int((dataframe["Severity"] == "HIGH").sum()))
        with col2:
            show_metric("Medium Severity", int((dataframe["Severity"] == "MEDIUM").sum()))
        with col3:
            show_metric("Info Events", int((dataframe["Severity"] == "INFO").sum()))
        with col4:
            show_metric("Events Analysed", len(dataframe))

        # Put the newest/highest-priority detections first for easier review.
        severity_order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
        dataframe["_priority"] = dataframe["Severity"].map(severity_order)
        dataframe = dataframe.sort_values(["_priority", "Event ID"], ascending=[True, False]).drop(columns=["_priority"])

        severities = st.multiselect(
            "Filter severity", ["HIGH", "MEDIUM", "INFO"],
            default=["HIGH", "MEDIUM", "INFO"],
        )
        search_text = st.text_input(
            "Search events", placeholder="Search medicine ID, action, user, or details..."
        ).strip().lower()
        filtered = dataframe[dataframe["Severity"].isin(severities)].copy()
        if search_text:
            searchable = filtered.astype(str).apply(lambda col: col.str.lower().str.contains(search_text, regex=False))
            filtered = filtered[searchable.any(axis=1)]

        st.dataframe(filtered, use_container_width=True, hide_index=True)
        st.download_button(
            "Download Threat Detection CSV",
            filtered.to_csv(index=False).encode("utf-8"),
            "medishield_threat_detection.csv",
            "text/csv",
        )
        st.caption(
            "Detection uses transparent rules over recorded audit events. "
            "Events appear here only after the relevant action is logged."
        )


# ============================================================
# SECURITY EVENTS AND AUDIT TRAIL
# ============================================================

elif page.endswith("Security Events"):
    require_roles("Admin", "Security Tester")

    st.title("📋 Security Events & Audit Trail")

    events = get_events()

    if events.empty:
        st.info("No events recorded yet.")

    else:
        col1, col2, col3 = st.columns(3)

        with col1:
            show_metric("Total Events", len(events))

        with col2:
            show_metric(
                "Accepted",
                int((events["result"] == "ACCEPTED").sum()),
            )

        with col3:
            show_metric(
                "Rejected / Flagged",
                int(
                    events["result"].isin(
                        ["REJECTED", "SUSPICIOUS"]
                    ).sum()
                ),
            )

        st.dataframe(
            events,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download Event Log CSV",
            events.to_csv(index=False).encode("utf-8"),
            "medishield_security_events.csv",
            "text/csv",
        )

        st.download_button(
            "Download Audit Trail TXT",
            events.to_string(index=False),
            "medishield_audit_trail.txt",
            "text/plain",
        )


# ============================================================
# PDF SECURITY REPORT
# ============================================================

elif page.endswith("PDF Report"):
    require_roles("Admin")

    st.title("📄 PDF Security Report")

    st.write(
        "Generate a downloadable snapshot of the current "
        "synthetic demonstration database."
    )

    if st.button("Generate PDF Report", type="primary"):
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, landscape
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
            )

            buffer = io.BytesIO()

            document = SimpleDocTemplate(
                buffer,
                pagesize=landscape(A4),
                rightMargin=14 * mm,
                leftMargin=14 * mm,
                topMargin=14 * mm,
                bottomMargin=14 * mm,
            )

            styles = getSampleStyleSheet()
            story = []

            events = get_events()
            medicines = get_medicines()
            users = get_users_df()

            story.append(
                Paragraph(
                    "MediShield Security Report",
                    styles["Title"],
                )
            )

            story.append(
                Paragraph(
                    "Fake Medicine Detection — Educational Prototype",
                    styles["Normal"],
                )
            )

            story.append(
                Paragraph(
                    "Generated: "
                    + datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    styles["Normal"],
                )
            )

            story.append(Spacer(1, 8 * mm))

            accepted = (
                int((events["result"] == "ACCEPTED").sum())
                if not events.empty else 0
            )

            rejected = (
                int((events["result"] == "REJECTED").sum())
                if not events.empty else 0
            )

            suspicious = (
                int((events["result"] == "SUSPICIOUS").sum())
                if not events.empty else 0
            )

            story.append(
                Paragraph(
                    "Executive Summary",
                    styles["Heading2"],
                )
            )

            summary_data = [
                ["Metric", "Value"],
                ["Registered medicine records", str(len(medicines))],
                ["Security events", str(len(events))],
                ["Accepted events", str(accepted)],
                ["Rejected events", str(rejected)],
                ["Suspicious events", str(suspicious)],
                ["Registered user accounts", str(len(users))],
            ]

            summary_table = Table(
                summary_data,
                repeatRows=1,
                hAlign="LEFT",
                colWidths=[85 * mm, 35 * mm],
            )

            summary_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#123b39"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.4,
                            colors.grey,
                        ),
                        (
                            "PADDING",
                            (0, 0),
                            (-1, -1),
                            5,
                        ),
                    ]
                )
            )

            story.append(summary_table)
            story.append(Spacer(1, 6 * mm))

            story.append(
                Paragraph(
                    "Medicine Expiry Review",
                    styles["Heading2"],
                )
            )

            medicine_data = [
                ["Medicine ID", "Name", "Batch", "Expiry", "Status"]
            ]

            for medicine in medicines:
                medicine_data.append(
                    [
                        medicine["medicine_id"],
                        medicine["name"],
                        medicine["batch"],
                        medicine["expiry"],
                        expiry_status(medicine["expiry"]),
                    ]
                )

            medicine_table = Table(
                medicine_data,
                repeatRows=1,
                hAlign="LEFT",
            )

            medicine_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#123b39"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.35,
                            colors.grey,
                        ),
                        (
                            "FONTSIZE",
                            (0, 0),
                            (-1, -1),
                            8,
                        ),
                        (
                            "PADDING",
                            (0, 0),
                            (-1, -1),
                            4,
                        ),
                    ]
                )
            )

            story.append(medicine_table)
            story.append(Spacer(1, 6 * mm))

            story.append(
                Paragraph(
                    "Recent Security Events",
                    styles["Heading2"],
                )
            )

            event_data = [
                ["Time", "Action", "Target", "Result", "User"]
            ]

            if not events.empty:
                for _, event in events.head(35).iterrows():
                    event_data.append(
                        [
                            str(event["event_time"]),
                            str(event["action"])[:32],
                            str(event["target"])[:25],
                            str(event["result"]),
                            str(event.get("username", "system"))[:20],
                        ]
                    )

            event_table = Table(
                event_data,
                repeatRows=1,
                hAlign="LEFT",
            )

            event_table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, 0),
                            colors.HexColor("#123b39"),
                        ),
                        (
                            "TEXTCOLOR",
                            (0, 0),
                            (-1, 0),
                            colors.white,
                        ),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            0.35,
                            colors.grey,
                        ),
                        (
                            "FONTSIZE",
                            (0, 0),
                            (-1, -1),
                            7,
                        ),
                        (
                            "PADDING",
                            (0, 0),
                            (-1, -1),
                            3,
                        ),
                    ]
                )
            )

            story.append(event_table)
            story.append(Spacer(1, 6 * mm))

            story.append(
                Paragraph(
                    "Security Limitations & Recommendations",
                    styles["Heading2"],
                )
            )

            recommendations = [
                (
                    "This report uses synthetic educational records "
                    "and is not a certified pharmaceutical verification service."
                ),
                (
                    "A digital signature confirms signed-record integrity; "
                    "it does not independently authenticate a physical package."
                ),
                (
                    "Repeated scans and risk scores are indicators for "
                    "investigation, not proof of counterfeit medicine."
                ),
                (
                    "Protect private signing keys, restrict access, back up "
                    "the database, and add login rate limiting before deployment."
                ),
            ]

            for recommendation in recommendations:
                story.append(
                    Paragraph(
                        "• " + recommendation,
                        styles["BodyText"],
                    )
                )

            def footer(canvas, doc):
                canvas.saveState()
                canvas.setFont("Helvetica", 8)
                canvas.setFillColor(colors.grey)

                canvas.drawString(
                    14 * mm,
                    7 * mm,
                    "MediShield | Fake Medicine Detection | Educational prototype",
                )

                canvas.drawRightString(
                    landscape(A4)[0] - 14 * mm,
                    7 * mm,
                    f"Page {doc.page}",
                )

                canvas.restoreState()

            document.build(
                story,
                onFirstPage=footer,
                onLaterPages=footer,
            )

            buffer.seek(0)

            st.download_button(
                "Download MediShield PDF Report",
                buffer.getvalue(),
                "medishield_security_report.pdf",
                "application/pdf",
            )

            log_event(
                "Generate PDF report",
                "MEDISHIELD",
                "ACCEPTED",
                "PDF security report generated.",
            )

            st.success(
                "PDF report generated. Click the download button above."
            )

        except ImportError:
            st.error(
                "PDF dependency missing. Install it with: "
                "pip install reportlab"
            )

        except Exception as exc:
            st.error(f"Could not generate PDF: {exc}")


# ============================================================
# USER MANAGEMENT
# ============================================================

elif page.endswith("User Management"):
    require_roles("Admin")

    st.title("👥 User Management")

    with st.form("create_user_form"):
        username = st.text_input("Username")

        password = st.text_input(
            "Password (minimum 10 characters)",
            type="password",
        )

        role = st.selectbox("Role", ROLES)

        submitted = st.form_submit_button(
            "Create User",
            type="primary",
        )

    if submitted:
        success, message = create_user(
            username,
            password,
            role,
        )

        if success:
            st.success(message)
            st.rerun()
        else:
            st.error(message)

    st.subheader("Existing Users")

    users_dataframe = get_users_df()

    if users_dataframe.empty:
        st.info("No users found.")

    else:
        st.dataframe(
            users_dataframe,
            use_container_width=True,
            hide_index=True,
        )


# ============================================================
# FOOTER
# ============================================================

st.markdown("---")

st.caption(
    "MediShield | Fake Medicine Detection | Educational security prototype. "
    "All demonstration records are synthetic. "
    "Risk indicators are not proof of counterfeit medicine."
)