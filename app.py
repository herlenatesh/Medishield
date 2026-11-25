import io
import os
import json
import sqlite3
import hashlib
import secrets
import html
import hmac
import tempfile
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
DATA_DIR = tempfile.gettempdir()
DB_NAME = os.path.join(DATA_DIR, "medishield.db")
PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "medishield_private.pem")
PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "medishield_public.pem")

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
        color: #
