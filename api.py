import os
from fastapi import FastAPI, WebSocket, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from pydantic import BaseModel
from typing import Optional, List
import jwt
import asyncio
import json
from Crypto.Cipher import AES
import base64
import logging
from datetime import datetime, timedelta
import bcrypt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
import databases
import sqlalchemy

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Definition of the tables
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("username", sqlalchemy.String, unique=True),
    sqlalchemy.Column("hashed_password", sqlalchemy.String),
)

servers = sqlalchemy.Table(
    "servers",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String, unique=True),
    sqlalchemy.Column("status", sqlalchemy.String),
)

# Database engine creation
engine = sqlalchemy.create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)
metadata.create_all(engine)

app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your allowed origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Secret keys (obtained from environment variables)
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
AES_KEY = base64.b64decode(os.getenv("AES_KEY"))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header = APIKeyHeader(name="X-API-Key")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str

class UserInDB(User):
    hashed_password: str

class VMCommand(BaseModel):
    action: str
    params: Optional[dict] = None

class ServerInfo(BaseModel):
    id: int
    name: str
    status: str

# Encryption functions
def encrypt_message(message: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message: str) -> str:
    encrypted = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted[:16], encrypted[16:32], encrypted[32:]
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Authentication functions
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def get_password_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

async def get_user(username: str):
    query = users.select().where(users.c.username == username)
    return await database.fetch_one(query)

async def authenticate_user(username: str, password: str):
    user = await get_user(username)
    if not user:
        return False
    if not verify_password(password, user["hashed_password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except jwt.PyJWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

# API routes
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/execute_command")
async def execute_command(command: VMCommand, current_user: User = Depends(get_current_user)):
    try:
        logger.info(f"User {current_user['username']} executed command: {command.action}")
        
        if command.action == "start":
            response = "Server is starting..."
        elif command.action == "stop":
            response = "Server is stopping..."
        elif command.action == "reboot":
            response = "Server is rebooting..."
        elif command.action == "status":
            response = "Server status: Online"
        else:
            raise HTTPException(status_code=400, detail="Invalid command")
        
        return {"response": encrypt_message(response)}
    except Exception as e:
        logger.error(f"Error executing command: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/servers", response_model=List[ServerInfo])
async def list_servers(current_user: User = Depends(get_current_user)):
    query = servers.select()
    return await database.fetch_all(query)

@app.post("/servers/{server_id}/backup")
async def backup_server(server_id: int, current_user: User = Depends(get_current_user)):
    # Implement backup logic
    return {"message": f"Backup initiated for server {server_id}"}

@app.get("/servers/{server_id}/resources")
async def get_server_resources(server_id: int, current_user: User = Depends(get_current_user)):
    # Implement logic to get server resources
    return {"cpu": "30%", "memory": "50%", "disk": "70%"}

@app.get("/servers/{server_id}/logs")
async def get_server_logs(server_id: int, current_user: User = Depends(get_current_user)):
    # Implement logic to obtain server logs
    return {"logs": "Server logs..."}

@app.post("/servers/{server_id}/schedule")
async def schedule_task(server_id: int, task: dict, current_user: User = Depends(get_current_user)):
    # Implement logic to schedule tasks
    return {"message": f"Task scheduled for server {server_id}"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, api_key: str = Security(api_key_header)):
    if api_key != os.getenv("WS_API_KEY"):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            decrypted_data = decrypt_message(data)
            command = json.loads(decrypted_data)
            
            if command['action'] == 'status':
                response = "Server status: Online"
            elif command['action'] == 'resources':
                response = "CPU: 30%, Memory: 50%, Disk: 70%"
            else:
                response = f"Processed command: {command['action']}"
            
            encrypted_response = encrypt_message(response)
            await websocket.send_text(encrypted_response)
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
    finally:
        await websocket.close()

# Startup and shutdown events
@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Swagger/OpenAPI configuration
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Server Management API",
        version="1.0.0",
        description="API for managing virtual servers",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
