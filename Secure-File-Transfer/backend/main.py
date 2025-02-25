from fastapi import FastAPI, Depends
from fastapi.responses import FileResponse
from routes.auth import auth_router
from routes.files import file_router
import os


# Initialize FastAPI app
app = FastAPI(title="Secure File Transfer API", description="Upload & download encrypted files securely")

# Include authentication and file management routes
app.include_router(auth_router, prefix="/auth")
app.include_router(file_router, prefix="/files")


# Root endpoint

@app.get("/")
def home():
    return {"message": "Welcome to Secure File Transfer API"}
