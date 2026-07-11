import os
import sys
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Insert backend directory to module search path so internal imports continue to resolve
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Load environment variables before doing other imports
def load_env_file(path: str = ".env"):
    if not os.path.exists(path):
        # Fallback to parent folder if run from inside backend/
        parent_env = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        if os.path.exists(parent_env):
            path = parent_env
        else:
            return

    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key:
                    os.environ.setdefault(key, value)
    except Exception as e:
        print("Failed to load .env:", e)

load_env_file()

# Import config and database helpers
import config
import database

# Import routers
from routers.auth import router as auth_router, get_valid_session, require_role
from routers.metrics import router as metrics_router
from routers.docker_manager import router as docker_router
from routers.pm2_manager import router as pm2_router
from routers.file_manager import router as file_router
from routers.terminal import router as terminal_router
from routers.admin import router as admin_router
from routers.ai_chat import router as ai_router
from routers.deploy import router as deploy_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the database schema
    database.init_user_db()
    
    # Bootstrap the default admin user from environment variables
    admin_username = os.getenv("ADMIN_USERNAME", "admin").strip()
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")
    if len(admin_password) < 8:
        raise RuntimeError("ADMIN_PASSWORD must be at least 8 characters")
    
    existing = database.get_user_record(admin_username)
    if not existing:
        database.create_user_record(admin_username, admin_password, "admin", overwrite=False)
        
    # Seed default application templates
    database.seed_app_templates()
    
    # Load active sessions from DB into memory (so it survives uvicorn reload)
    try:
        now = time.time()
        conn = database.db_connect()
        cur = conn.cursor()
        cur.execute("SELECT token, username, role, expires_at FROM sessions WHERE expires_at > ?", (now,))
        for row in cur.fetchall():
            config.active_sessions[row[0]] = {"username": row[1], "role": row[2], "expires_at": row[3]}
        conn.close()
    except Exception as e:
        print("Failed to restore active sessions from database:", e)
        
    # Configure AI models
    if config.AI_PROVIDER == "nvidia" and config.NVIDIA_API_KEY:
        print(f"[AI] NVIDIA provider configured with model {config.NVIDIA_MODEL}")
    elif config.GEMINI_API_KEY and config.GEMINI_API_KEY != "YOUR_KEY":
        try:
            from ai.gemini_client import GeminiChat
            GeminiChat.configure()
            print(f"[AI] Gemini configured with model {config.GEMINI_MODEL}")
        except Exception as e:
            print(f"[AI] Warning: Gemini configuration failed: {e}")
            
    yield


app = FastAPI(lifespan=lifespan)

# Allow CORS for development environments
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Restrict OpenAPI & Swagger Docs to admin role only
@app.middleware("http")
async def restrict_docs_to_admin(request: Request, call_next):
    path = request.url.path
    is_docs_path = (
        path == "/docs"
        or path.startswith("/docs/")
        or path == "/redoc"
        or path.startswith("/redoc/")
        or path == "/openapi.json"
    )

    if is_docs_path:
        session_id = request.cookies.get(config.SESSION_COOKIE_NAME)
        session = get_valid_session(session_id)

        if not session:
            return JSONResponse(status_code=401, content={"detail": "Not authenticated"})

        if session.get("role") != "admin":
            return JSONResponse(status_code=403, content={"detail": "admin role required for docs"})

    return await call_next(request)


# Mount static assets directory
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Include modular API routers
app.include_router(auth_router)
app.include_router(metrics_router)
app.include_router(docker_router)
app.include_router(pm2_router)
app.include_router(file_router)
app.include_router(terminal_router)
app.include_router(admin_router)
app.include_router(ai_router)
app.include_router(deploy_router)

# Serve the single-page application index
@app.get("/")
def get_dashboard():
    return FileResponse("frontend/index.html")

# Serve the application logo
@app.get("/logo")
def get_logo():
    return FileResponse("frontend/gridcore.jpg", media_type="image/jpeg")
