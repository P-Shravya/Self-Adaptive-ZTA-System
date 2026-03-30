from backend.database import create_tables
from fastapi import FastAPI
from contextlib import asynccontextmanager
from backend.auth.auth_router import router as auth_router
from fastapi.middleware.cors import CORSMiddleware

from backend.routers.admin_router import router as admin_router
from backend.approval.approval_router import router as approval_router
from backend.routers.dashboard_router import router as dashboard_router
from backend.routers.pharmacy_router import router as pharmacy_router
from backend.routers.lab_router import router as lab_router



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

@app.get("/")
def root():
    return {"status": "ZTA Backend Running"}

