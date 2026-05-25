CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL
)