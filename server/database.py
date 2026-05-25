import sqlite3


class DatabaseConnection:
    def __init__(self, db_path):
        self.db_path = db_path

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn


def get_user_data(db_conn, username):
    username_clean = username.strip().lower()

    conn = db_conn.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, salt, password_hash FROM users WHERE username = ?",
            (username_clean,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return {
                "username": row["username"],
                "password_hash": row["password_hash"],
                "salt": row["salt"]
            }
        return None
    except sqlite3.Error as e:
        print(f"[!] Database query failure: {e}")
        return None
