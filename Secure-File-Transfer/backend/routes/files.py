from fastapi import FastAPI, APIRouter, UploadFile, Form, File, Depends, HTTPException
from fastapi.responses import FileResponse
import os
from routes.auth import get_current_user
from cryptography.fernet import Fernet

file_router = APIRouter()
app = FastAPI()
UPLOAD_FOLDER = "files/uploaded_files"
ENCRYPTED_FOLDER = "files/encrypted_files"
DECRYPTED_FOLDER = "files/decrypted_files"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
# Generate & Save Key (Should be stored securely)
KEY_FILE = "secret.key"


def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
        return key

SECRET_KEY = load_or_generate_key()
cipher = Fernet(SECRET_KEY)


# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
@file_router.post("/upload")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    """Uploads a file to the server."""
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())  # FIX: Use `await` for async file read
    return {"message": "File uploaded successfully", "filename": file.filename}

@file_router.post("/encrypt")
async def encrypt_file(filename: str, user: dict = Depends(get_current_user)):
    """Encrypts a file and saves it in the encrypted folder."""
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + ".enc")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    # Read the file data
    with open(file_path, "rb") as f:
        data = f.read()

    encrypted_data = cipher.encrypt(data)  # Encrypt the file data

    # Write encrypted data to a new file
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    return {"message": "File encrypted successfully", "encrypted_filename": filename + ".enc"}

@file_router.get("/download/{filename}")
async def download_file(filename: str, user: dict = Depends(get_current_user)):
    """Allows the user to download the encrypted file."""
    file_path = os.path.join(ENCRYPTED_FOLDER, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path, filename=filename)

#----------------------------------------------------------------------------#


@file_router.post("/decrypt")
async def decrypt_file(file: UploadFile = File(...)):
    """Decrypts an uploaded encrypted file using the stored secret key."""
    try:
        encrypted_data = await file.read()
        decrypted_data = cipher.decrypt(encrypted_data).decode("utf-8").strip()  # Decode and remove extra spaces

        return {"decrypted_text": decrypted_data}
    
    except Exception:
        raise HTTPException(status_code=400, detail="Decryption failed. Invalid file or key.")
    

@file_router.get("/download-decrypted/{filename}")
async def download_decrypted_file(filename: str, user: dict = Depends(get_current_user)):
    file_path = os.path.join(DECRYPTED_FOLDER, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Decrypted file not found")

    return FileResponse(file_path, filename=filename)
