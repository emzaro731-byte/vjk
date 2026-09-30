import os, uuid, secrets, hashlib, json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, Header, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import jwt
import psycopg
from psycopg.rows import dict_row
from passlib.context import CryptContext

DATABASE_URL=os.getenv("DATABASE_URL","postgresql://vjk:change-me@postgres:5432/vjk")
JWT_SECRET=os.getenv("JWT_SECRET","change-this-in-production")
MASTER_API_KEY=os.getenv("API_KEY","vjk-dev-key")
STORAGE_DIR=Path(os.getenv("STORAGE_DIR","/data/storage")); STORAGE_DIR.mkdir(parents=True,exist_ok=True)
pwd=CryptContext(schemes=["bcrypt"],deprecated="auto")
app=FastAPI(title="VJK",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

class Auth(BaseModel): email:EmailStr; password:str
class TableRow(BaseModel): data:dict
class Project(BaseModel): name:str

def db():
    return psycopg.connect(DATABASE_URL,row_factory=dict_row)
def init_db():
    with db() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users(id UUID PRIMARY KEY,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
        CREATE TABLE IF NOT EXISTS api_keys(id UUID PRIMARY KEY,name TEXT NOT NULL,key_hash TEXT UNIQUE NOT NULL,key_prefix TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
        CREATE TABLE IF NOT EXISTS projects(id UUID PRIMARY KEY,name TEXT NOT NULL,created_at TIMESTAMPTZ DEFAULT now());
        CREATE TABLE IF NOT EXISTS files(id UUID PRIMARY KEY,bucket TEXT NOT NULL,path TEXT NOT NULL,size BIGINT NOT NULL,content_type TEXT,created_at TIMESTAMPTZ DEFAULT now(),UNIQUE(bucket,path));""")
        c.execute("SELECT 1 FROM api_keys LIMIT 1")
        if c.fetchone() is None:
            raw="vjk_"+secrets.token_urlsafe(32); h=hashlib.sha256(raw.encode()).hexdigest()
            c.execute("INSERT INTO api_keys(id,name,key_hash,key_prefix) VALUES(%s,%s,%s,%s)",(uuid.uuid4(),"Default server key",h,raw[:12]))
        c.commit()
@app.on_event("startup")
def startup(): init_db()

def check_key(x_api_key):
    if x_api_key==MASTER_API_KEY:return
    if not x_api_key: raise HTTPException(401,"API key required")
    h=hashlib.sha256(x_api_key.encode()).hexdigest()
    with db() as c:
        if not c.execute("SELECT id FROM api_keys WHERE key_hash=%s",(h,)).fetchone(): raise HTTPException(401,"Invalid API key")
def token_for(uid):
    return jwt.encode({"sub":str(uid),"exp":datetime.now(timezone.utc)+timedelta(days=7)},JWT_SECRET,algorithm="HS256")

@app.get("/")
def root(): return FileResponse("dashboard/index.html")
@app.get("/health")
def health(): return {"status":"ok","service":"vjk","version":"1.0.0"}

@app.post("/auth/signup")
def signup(a:Auth,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c:
        if c.execute("SELECT id FROM users WHERE email=%s",(a.email,)).fetchone(): raise HTTPException(409,"Email already registered")
        uid=uuid.uuid4(); c.execute("INSERT INTO users(id,email,password_hash) VALUES(%s,%s,%s)",(uid,a.email,pwd.hash(a.password))); c.commit()
    return {"access_token":token_for(uid),"user":{"id":str(uid),"email":a.email}}
@app.post("/auth/login")
def login(a:Auth,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c: u=c.execute("SELECT * FROM users WHERE email=%s",(a.email,)).fetchone()
    if not u or not pwd.verify(a.password,u["password_hash"]): raise HTTPException(401,"Invalid email or password")
    return {"access_token":token_for(u["id"]),"user":{"id":str(u["id"]),"email":u["email"]}}

@app.get("/api/projects")
def projects(x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c: return {"projects":c.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()}
@app.post("/api/projects")
def create_project(p:Project,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key); pid=uuid.uuid4()
    with db() as c: c.execute("INSERT INTO projects(id,name) VALUES(%s,%s)",(pid,p.name)); c.commit()
    return {"id":str(pid),"name":p.name}

@app.get("/api/tables")
def tables(x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c:
        rows=c.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name").fetchall()
    return {"tables":[r["table_name"] for r in rows]}
@app.get("/api/tables/{table}/rows")
def rows(table:str,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    if not table.replace("_","").isalnum(): raise HTTPException(400,"Invalid table")
    with db() as c: return {"rows":c.execute(f'SELECT * FROM "{table}" LIMIT 500').fetchall()}
@app.post("/api/tables/{table}/rows")
def insert_row(table:str,r:TableRow,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    if not table.replace("_","").isalnum() or not r.data: raise HTTPException(400,"Invalid request")
    cols=list(r.data); vals=list(r.data.values())
    q=f'INSERT INTO "{table}" ({",".join(chr(34)+x+chr(34) for x in cols)}) VALUES ({",".join("%s" for _ in vals)}) RETURNING *'
    with db() as c: out=c.execute(q,vals).fetchone(); c.commit()
    await_broadcast({"type":"row_inserted","table":table,"row":out})
    return out

@app.post("/api/storage/{bucket}")
async def upload(bucket:str,file:UploadFile=File(...),x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key); fid=str(uuid.uuid4()); path=STORAGE_DIR/bucket; path.mkdir(parents=True,exist_ok=True)
    target=path/fid+"_"+Path(file.filename or "file").name
    data=await file.read(); target.write_bytes(data)
    with db() as c: c.execute("INSERT INTO files(id,bucket,path,size,content_type) VALUES(%s,%s,%s,%s,%s)",(fid,bucket,target.name,len(data),file.content_type)); c.commit()
    return {"id":fid,"bucket":bucket,"path":target.name,"size":len(data)}
@app.get("/api/storage/{bucket}")
def list_files(bucket:str,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c:return {"files":c.execute("SELECT * FROM files WHERE bucket=%s ORDER BY created_at DESC",(bucket,)).fetchall()}
@app.get("/api/storage/{bucket}/{file_id}")
def get_file(bucket:str,file_id:str,x_api_key:Optional[str]=Header(None)):
    check_key(x_api_key)
    with db() as c:f=c.execute("SELECT * FROM files WHERE id=%s AND bucket=%s",(file_id,bucket)).fetchone()
    if not f: raise HTTPException(404,"File not found")
    return FileResponse(STORAGE_DIR/bucket/f["path"],media_type=f["content_type"] or "application/octet-stream")

clients=set()
async def await_broadcast(event):
    dead=[]
    for ws in clients:
        try: await ws.send_json(event)
        except: dead.append(ws)
    for ws in dead: clients.discard(ws)
@app.websocket("/realtime")
async def realtime(ws:WebSocket):
    key=ws.query_params.get("apikey")
    if key!=MASTER_API_KEY:
        await ws.close(code=1008); return
    await ws.accept(); clients.add(ws)
    try:
        while True: await ws.receive_text()
    except WebSocketDisconnect: clients.discard(ws)
