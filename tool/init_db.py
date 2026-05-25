#!/usr/bin/env python3

import sqlite3
from pathlib import Path
import argparse


def main():
    parser = argparse.ArgumentParser(description="Init DB utility")
    parser.add_argument(
        '-d', '--db',
        required=True,
        help="Database file"
    )

    args = parser.parse_args()

    db_path = Path(args.db)
    sql_path = Path(f"{Path(__file__).parent.resolve()}/build_db.sql")

    if not sql_path.is_file():
        print("[!] Error: Could not find build script.")
        return

    if db_path.is_file():
        print(f"[!] Warning: Target '{db_path.name}' already exists.")
        is_ok = input("Do you want to run the initialization script anyway? [y/N]: ").strip().lower()
        if is_ok != 'y':
            print("[*] Cancelled. No changes made.")
            return

    db_dir = db_path.parent
    if str(db_dir) and not db_dir.is_dir():
        print(f"[+] Creating missing directory structure: {db_dir.resolve()}")
        db_dir.mkdir(parents=True, exist_ok=True)

    try:
        print(f"[*] Creating database from '{sql_path.name}'...")
        with open(sql_path, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.executescript(sql_script)

        conn.commit()
        conn.close()
        print(f"[+] Success: Database fully initialized at '{db_path.resolve()}' using schema configuration.")

    except sqlite3.Error as e:
        print(f"[!] SQLite Error during execution: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()
