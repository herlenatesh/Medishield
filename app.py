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
    salt = salt or secrets.token_bytes
