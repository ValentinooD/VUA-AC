#!/usr/bin/env python3

import os
import sqlite3
import hashlib
import secrets
import getpass
import argparse


def register_user(db_path, username, password):
    username_lower = username.strip().lower()

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100_000
    )

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
            (username_lower, salt, password_hash)
        )
        conn.commit()
        print(f"[+] User '{username_lower}' successfully registered in database.")
        conn.close()

    except sqlite3.IntegrityError:
        print(f"[!] Error: Username '{username_lower}' already exists in this database.")


def main():
    parser = argparse.ArgumentParser(description="Create user utility")
    parser.add_argument(
        '-d', '--db',
        required=True,
        help="Database file"
    )
    parser.add_argument(
        '-u', '--username',
        required=True,
        help="Username to register"
    )

    args = parser.parse_args()
    db_path = os.path.abspath(args.db)

    if not os.path.isfile(db_path):
        print(f"[!] Error: Database file '{db_path}' does not exist.")
        return

    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("[!] Error: Passwords do not match.")
        return

    register_user(db_path, args.username, password)


if __name__ == "__main__":
    main()
