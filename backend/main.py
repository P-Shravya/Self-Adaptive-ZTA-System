from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from backend.auth.auth_router import router as auth_router
from backend.database import create_tables
from fastapi.middleware.cors import CORSMiddleware

from backend.security.monitor_middleware import monitor_middleware

from backend.routers.admin_router import router as admin_router
from backend.approval.approval_router import router as approval_router
from backend.routers.dashboard_router import router as dashboard_router
from backend.routers.pharmacy_router import router as pharmacy_router
from backend.routers.lab_router import router as lab_router
from backend.mfa.mfa_router import router as mfa_router
from backend.biometric.biometric_router import router as biometric_router



@asynccontextmanager
async def lifespan(app: FastAPI):
    # 🔹 Startup logic
    create_tables()
    yield
    # 🔹 Shutdown logic (optional)
    # You can close connections or cleanup here


app = FastAPI(
    title="ZTA System",
    lifespan=lifespan
)

# Activate adaptive monitoring
app.middleware("http")(monitor_middleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allow frontend access
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(approval_router)
app.include_router(dashboard_router)
app.include_router(pharmacy_router)
app.include_router(lab_router)
app.include_router(mfa_router)
app.include_router(biometric_router)

# Serve frontend static files (HTML, CSS, JS) under /frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.is_dir():
    app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")

@app.get("/api/health")
def root():
    return {"status": "ZTA Backend Running"}

@app.get("/")
def frontend_root():
    # convenience: open base URL and land on login
    return {"open": "/frontend/login.html"}

