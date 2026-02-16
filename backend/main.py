from fastapi import FastAPI
from contextlib import asynccontextmanager
from backend.auth.auth_router import router as auth_router
from backend.database import create_tables
from fastapi.middleware.cors import CORSMiddleware


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


@app.get("/")
def root():
    return {"status": "ZTA Backend Running"}

