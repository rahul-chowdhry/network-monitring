from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api import router


app = FastAPI(
    title="HOMENET SENTINEL",
    description="Local home-network monitoring and device management API",
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "database": "configured",
        "nmap": "configured",
    }


@app.get("/")
def root():
    return {
        "name": "HOMENET SENTINEL",
        "status": "running",
        "version": "1.0.0",
    }