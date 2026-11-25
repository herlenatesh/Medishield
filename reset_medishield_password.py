"""Safely reset a MediShield local account password.

Run this script from the same project folder as app.py and medishield.db.
It uses the same PBKDF2-HMAC-SHA256 settings as MediShield's app source.
"""
import getpass
import hashlib
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

DB_PATH = Path.cwd() / "medishield.db"
ITERATIONS = 200_000
MIN_PASSWORD_LENGTH = 10


def main() -> int:
    if not DB_PATH.is_file():
        print("ERROR: medishield.db was not found in this folder:")
        print(f"  {Path.cwd()}")
        print("Open PowerShell in the folder containing app.py and medishield.db, then run this script again.")
        return 1

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            table = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone()
            if not table:
                print("ERROR: This database does not contain the MediShield 'users' table.")
                return 1

            users = conn.execute(
                "SELECT username, role FROM users ORDER BY username"
            ).fetchall()
            if not users:
                print("No users exist in this database. Start app.py and create the first Admin account from the login page.")
                return 1

            print("MediShield accounts found:")
            for row in users:
                print(f"  - {row['username']}  (role: {row['role']})")
            print("\nThis only resets the selected account's password. It does not change the role or delete data.")

            username = input("Enter the exact username to reset: ").strip()
            user = conn.execute(
                "SELECT username FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not user:
                print("ERROR: Username not found. Copy the exact spelling from the list above.")
                return 1

            new_password = getpass.getpass("Enter new password (minimum 10 characters): ")
            confirm = getpass.getpass("Confirm new password: ")
            if len(new_password) < MIN_PASSWORD_LENGTH:
                print("ERROR: Password must contain at least 10 characters.")
                return 1
            if new_password != confirm:
                print("ERROR: Passwords do not match. No changes were made.")
                return 1

            # Make a dated backup before modifying the database.
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = Path.cwd() / f"medishield.db.backup_{stamp}"
            shutil.copy2(DB_PATH, backup_path)

            # Match app.py's hash_password(): random 16-byte salt represented as hex,
            # PBKDF2-HMAC-SHA256 with 200,000 iterations, result stored as hex.
            import secrets
            salt = secrets.token_bytes(16).hex()
            digest = hashlib.pbkdf2_hmac(
                "sha256",
                new_password.encode("utf-8"),
                bytes.fromhex(salt),
                ITERATIONS,
            ).hex()

            conn.execute(
                "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
                (digest, salt, username),
            )
            conn.commit()

            print("\nSUCCESS: Password updated.")
            print(f"Account: {username}")
            print(f"Database backup: {backup_path.name}")
            print("Return to the MediShield login page and sign in using the new password.")
            return 0

    except sqlite3.Error as exc:
        print(f"Database error: {exc}")
        print("Stop Streamlit and make sure you are using the correct project folder/database.")
        return 1
    except KeyboardInterrupt:
        print("\nCancelled. No password reset completed.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
