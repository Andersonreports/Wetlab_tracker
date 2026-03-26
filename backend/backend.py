from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from tracker_auth import router as tracker_router

app = FastAPI(title="Anderson Lab Report Tracker")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tracker_router)


@app.get("/")
def root():
    return {"status": "Anderson Report Tracker running"}
