from fastapi import FastAPI, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict
import bcrypt

app = FastAPI()

# Allow frontend (React) to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can replace "*" with your frontend URL for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory 'database'
users_db: Dict[str, Dict] = {}

class User(BaseModel):
    username: str
    password: str

@app.post("/register")
def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists.")

    # Hash password
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    users_db[user.username] = {
        "username": user.username,
        "password": hashed_password
    }

    return {"message": "User registered successfully"}

@app.post("/login")
def login(user: User):
    if user.username not in users_db:
        raise HTTPException(status_code=400, detail="Invalid username or password")

    stored_user = users_db[user.username]
    if not bcrypt.checkpw(user.password.encode('utf-8'), stored_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid username or password")

    return {"message": "Login successful"}
