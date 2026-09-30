import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, EmailStr
from jose import jwt

app = FastAPI(title="VJK Backend", version="0.1.0")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-in-production")
API_KEY = os.getenv("API_KEY", "vjk-dev-key")

class AuthRequest(BaseModel):
    email: EmailStr
    password: str

def require_api_key(value):
    if value != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")

@app.get("/health")
def health():
    return {"status":"ok","service":"vjk"}

@app.post("/auth/signup")
def signup(body: AuthRequest, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    return {"message":"signup endpoint ready","email":body.email}

@app.post("/auth/login")
def login(body: AuthRequest, x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    token=jwt.encode({"sub":body.email,"exp":datetime.now(timezone.utc)+timedelta(hours=1)},JWT_SECRET,algorithm="HS256")
    return {"access_token":token,"token_type":"bearer"}

@app.get("/rest/v1/health")
def rest_health(x_api_key: str | None = Header(default=None)):
    require_api_key(x_api_key)
    return {"data":[{"status":"ok"}]}
