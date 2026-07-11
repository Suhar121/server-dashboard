import time
import os
import shutil
import secrets
from fastapi import APIRouter, HTTPException, Depends, Request, Response, Cookie, File, UploadFile, Form
from pydantic import BaseModel
import config
import database

router = APIRouter(prefix="/auth", tags=["auth"])

class LoginRequest(BaseModel):
    username: str
    password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str

class UpdateUserRoleRequest(BaseModel):
    role: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str


def create_session(username: str, role: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + config.SESSION_TIMEOUT_SECONDS
    session = {"username": username, "role": role, "expires_at": expires_at}
    config.active_sessions[token] = session
    database._save_session_to_db(token, username, role, expires_at)
    return token


def get_current_user(
    session_id: str | None = Cookie(default=None, alias=config.SESSION_COOKIE_NAME),
):
    if not session_id:
        raise HTTPException(status_code=401, detail="Not authenticated")

    session = config.active_sessions.get(session_id)
    if not session:
        session = database._load_session_from_db(session_id)
        if session:
            config.active_sessions[session_id] = session

    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")

    now = time.time()
    if session["expires_at"] < now:
        config.active_sessions.pop(session_id, None)
        database._delete_session_from_db(session_id)
        raise HTTPException(status_code=401, detail="Session expired")

    session["expires_at"] = now + config.SESSION_TIMEOUT_SECONDS
    database._save_session_to_db(session_id, session["username"], session["role"], session["expires_at"])

    return {
        "username": session["username"],
        "role": session["role"],
        "session_id": session_id,
        "expires_at": session["expires_at"],
    }


def require_role(min_role: str):
    min_rank = config.ROLE_ORDER[min_role]

    def _checker(user=Depends(get_current_user)):
        user_rank = config.ROLE_ORDER.get(user["role"], 0)
        if user_rank < min_rank:
            raise HTTPException(status_code=403, detail="Forbidden: Insufficient permissions")
        return user

    return _checker


def get_valid_session(session_id: str | None):
    if not session_id:
        return None

    session = config.active_sessions.get(session_id)
    if not session:
        session = database._load_session_from_db(session_id)
        if session:
            config.active_sessions[session_id] = session

    if not session:
        return None

    now = time.time()
    if session["expires_at"] < now:
        config.active_sessions.pop(session_id, None)
        database._delete_session_from_db(session_id)
        return None

    session["expires_at"] = now + config.SESSION_TIMEOUT_SECONDS
    database._save_session_to_db(session_id, session["username"], session["role"], session["expires_at"])
    return session



@router.post("/login")
async def login(data: LoginRequest, request: Request, response: Response):
    username = data.username.strip()
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    login_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    login_alerts_on = database.get_setting("login_alerts_enabled", "true") == "true"

    row = database.get_user_record(username)

    if not row:
        if login_alerts_on:
            config.send_telegram(
                f"🚨 Failed Login Attempt\n"
                f"Username: {username} (not found)\n"
                f"Time: {login_time}\n"
                f"IP: {client_ip}\n"
                f"User-Agent: {user_agent}"
            )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    _, password_hash, salt, role, _, _ = row
    if not database.verify_password(data.password, password_hash, salt):
        if login_alerts_on:
            config.send_telegram(
                f"🚨 Failed Login Attempt\n"
                f"Username: {username}\n"
                f"Role: {role}\n"
                f"Time: {login_time}\n"
                f"IP: {client_ip}\n"
                f"User-Agent: {user_agent}"
            )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    database.update_user_last_login(username)
    database.log_audit(username, "login", f"Logged in with role: {role}")

    token = create_session(username=username, role=role)
    response.set_cookie(
        key=config.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=config.SESSION_TIMEOUT_SECONDS,
    )
    return {"status": "ok", "username": username, "role": role}


@router.post("/register")
async def register(data: LoginRequest, request: Request):
    username = data.username.strip()
    if not config.USERNAME_PATTERN.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-64 chars (letters, numbers, underscores, dots, hyphens)",
        )

    # Allow registration only if no users exist (initial setup)
    conn = database.db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()

    if count > 0:
        raise HTTPException(status_code=400, detail="Registration is disabled after initial setup.")

    database.create_user_record(username, data.password, "admin")
    database.log_audit(username, "register", "Initial admin registration")
    return {"status": "ok"}


@router.post("/logout")
async def logout_endpoint(response: Response, user=Depends(get_current_user)):
    session_id = user["session_id"]
    config.active_sessions.pop(session_id, None)
    database._delete_session_from_db(session_id)
    database.log_audit(user["username"], "logout", "Logged out")
    response.delete_cookie(config.SESSION_COOKIE_NAME)
    return {"status": "ok"}


@router.post("/change-password")
async def change_password(data: ChangePasswordRequest, user=Depends(get_current_user)):
    username = user["username"]
    row = database.get_user_record(username)
    if not row:
         raise HTTPException(status_code=404, detail="User not found")
    _, password_hash, salt, _, _, _ = row
    if not database.verify_password(data.old_password, password_hash, salt):
         raise HTTPException(status_code=400, detail="Invalid old password")
    
    database.create_user_record(username, data.new_password, user["role"], overwrite=True)
    database.log_audit(username, "change-password", "Changed password")
    return {"status": "ok"}


@router.post("/failed-login-photo")
async def failed_login_photo(
    photo: UploadFile = File(...),
    username: str = Form(...),
):
    try:
        intruder_dir = os.path.join(config.LOG_DIR, "intruders")
        os.makedirs(intruder_dir, exist_ok=True)
        filename = f"intruder_{int(time.time())}_{username.replace('/', '_')}.jpg"
        filepath = os.path.join(intruder_dir, filename)
        with open(filepath, "wb") as buffer:
            shutil.copyfileobj(photo.file, buffer)
        print(f"[auth] Intruder photo saved to {filepath}")
    except Exception as e:
        print("[auth] Failed to save intruder photo:", e)
    return {"status": "ok"}


@router.get("/status")
async def auth_status():
    conn = database.db_connect()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    count = cur.fetchone()[0]
    conn.close()
    return {"needs_setup": count == 0}


@router.get("/me")
async def get_me(user=Depends(get_current_user)):
    return user


@router.get("/users")
async def get_users(user=Depends(require_role("admin"))):
    return database.list_users()


@router.post("/users")
async def create_user(data: CreateUserRequest, user=Depends(require_role("admin"))):
    username = data.username.strip()
    if not config.USERNAME_PATTERN.match(username):
        raise HTTPException(
            status_code=400,
            detail="Username must be 3-64 chars (letters, numbers, underscores, dots, hyphens)",
        )

    if database.get_user_record(username):
        raise HTTPException(status_code=400, detail="User already exists")

    if data.role not in config.ROLE_ORDER:
        raise HTTPException(status_code=400, detail="Invalid role")

    database.create_user_record(username, data.password, data.role)
    database.log_audit(user["username"], "create_user", f"Created user {username} with role {data.role}")
    return {"status": "ok"}


@router.patch("/users/{username}/role")
async def patch_user_role(username: str, data: UpdateUserRoleRequest, user=Depends(require_role("admin"))):
    if username == user["username"]:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    if data.role not in config.ROLE_ORDER:
        raise HTTPException(status_code=400, detail="Invalid role")

    if database.update_user_role(username, data.role):
        tokens_to_remove = [t for t, s in config.active_sessions.items() if s["username"] == username]
        for t in tokens_to_remove:
            config.active_sessions.pop(t, None)
            database._delete_session_from_db(t)
        database.log_audit(user["username"], "update_user_role", f"Changed role of user {username} to {data.role}")
        return {"status": "ok"}

    raise HTTPException(status_code=404, detail="User not found")


@router.delete("/users/{username}")
async def delete_user(username: str, user=Depends(require_role("admin"))):
    if username == user["username"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own user record")

    user_to_delete = database.get_user_record(username)
    if not user_to_delete:
         raise HTTPException(status_code=404, detail="User not found")

    if user_to_delete[3] == "admin" and database.count_admin_users() <= 1:
         raise HTTPException(status_code=400, detail="Cannot delete the last admin user")

    if database.delete_user_record(username):
         tokens_to_remove = [t for t, s in config.active_sessions.items() if s["username"] == username]
         for t in tokens_to_remove:
             config.active_sessions.pop(t, None)
             database._delete_session_from_db(t)
         database.log_audit(user["username"], "delete_user", f"Deleted user {username}")
         return {"status": "ok"}

    raise HTTPException(status_code=404, detail="User not found")
