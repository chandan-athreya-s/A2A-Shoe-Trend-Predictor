import duckdb
import hashlib
import uuid
import streamlit as st
from datetime import datetime, timedelta

DB_FILE        = "users.db"
SESSION_TTL_H  = 2          

def get_conn():
    return duckdb.connect(DB_FILE)

def init_db():
    with get_conn() as con:
        
        con.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username   VARCHAR PRIMARY KEY,
                password   VARCHAR NOT NULL,
                created_at TIMESTAMP DEFAULT current_timestamp
            )
        """)
        
        con.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token      VARCHAR PRIMARY KEY,
                username   VARCHAR NOT NULL,
                expires_at TIMESTAMP NOT NULL
            )
        """)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def register_user(username: str, password: str) -> tuple[bool, str]:
    with get_conn() as con:
        if con.execute("SELECT 1 FROM users WHERE username = ?", [username]).fetchone():
            return False, "Username already taken."
        con.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                    [username, hash_password(password)])
    return True, "Account created! You can now log in."

def verify_user(username: str, password: str) -> bool:
    with get_conn() as con:
        row = con.execute("SELECT password FROM users WHERE username = ?",
                          [username]).fetchone()
    return bool(row and row[0] == hash_password(password))


def create_session(username: str) -> str:
    """Generate a token, store it in DuckDB, return it."""
    token      = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=SESSION_TTL_H)
    with get_conn() as con:
        con.execute("INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)",
                    [token, username, expires_at])
    return token

def validate_session(token: str) -> str | None:
    """Return username if token is valid and not expired, else None."""
    if not token:
        return None
    with get_conn() as con:
        row = con.execute(
            "SELECT username, expires_at FROM sessions WHERE token = ?", [token]
        ).fetchone()
    if not row:
        return None
    username, expires_at = row
    if datetime.utcnow() > expires_at:
        delete_session(token)   
        return None
    return username

def delete_session(token: str):
    """Invalidate a session token (logout)."""
    with get_conn() as con:
        con.execute("DELETE FROM sessions WHERE token = ?", [token])

def purge_expired_sessions():
    """Housekeeping — remove all expired rows."""
    with get_conn() as con:
        con.execute("DELETE FROM sessions WHERE expires_at < ?", [datetime.utcnow()])


def show_auth_page() -> bool:
    """
    Call at the top of your app.
    - Checks st.session_state for a token, validates it against DuckDB.
    - Renders Login / Register UI if not authenticated.
    - Returns True when the user is authenticated.
    """
    init_db()
    purge_expired_sessions()


    token    = st.session_state.get("session_token")
    username = validate_session(token)

    if username:
   
        st.session_state["authenticated"] = True
        st.session_state["username"]      = username
        return True

    # ── Auth UI ────────────────────────────────────────────────────────────────
    st.title("Shoe Popularity Predictor")
    st.caption("Please log in or create an account to continue.")
    st.divider()

    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        username_input = st.text_input("Username", key="login_user")
        password_input = st.text_input("Password", type="password", key="login_pass")
        if st.button("Log In", use_container_width=True):
            u = username_input.strip()
            if verify_user(u, password_input):
                token = create_session(u)               
                st.session_state["session_token"] = token
                st.session_state["authenticated"] = True
                st.session_state["username"]      = u
                st.success("Login successful!")
                st.rerun()
            else:
                st.error("Invalid username or password.")

    with tab_register:
        new_user = st.text_input("Choose a username", key="reg_user")
        new_pass = st.text_input("Choose a password", type="password", key="reg_pass")
        confirm  = st.text_input("Confirm password",  type="password", key="reg_confirm")
        if st.button("Create Account", use_container_width=True):
            if not new_user or not new_pass:
                st.warning("Username and password are required.")
            elif new_pass != confirm:
                st.error("Passwords do not match.")
            elif len(new_pass) < 6:
                st.warning("Password must be at least 6 characters.")
            else:
                ok, msg = register_user(new_user.strip(), new_pass)
                st.success(msg) if ok else st.error(msg)

    return False

def logout():
    """Call when user clicks Logout."""
    token = st.session_state.get("session_token")
    if token:
        delete_session(token)         
    st.session_state.clear()
    st.rerun()