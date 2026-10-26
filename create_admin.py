
from getpass import getpass

from werkzeug.security import generate_password_hash
from mysql.connector import Error

from config import DB_CONFIG
import mysql.connector


def create_admin():
    username = input("Enter admin username: ").strip()
    password = getpass("Enter admin password (minimum 8 characters): ")

    if not username:
        print("Username cannot be empty.")
        return

    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return

    password_hash = generate_password_hash(password)
    conn = None
    cursor = None

    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO admins (username, password_hash)
            VALUES (%s, %s)
            """,
            (username, password_hash)
        )

        conn.commit()
        print("Admin account created successfully!")

    except Error as e:
        if conn:
            conn.rollback()
        print("Could not create admin:", e)

    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()


if __name__ == "__main__":
    create_admin()
