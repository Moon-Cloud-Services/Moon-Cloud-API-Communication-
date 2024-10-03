import os
from fastapi import FastAPI, WebSocket, Depends, HTTPException, status, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from pydantic import BaseModel, Field
from typing import Optional, List
import jwt
import asyncio
import json
from cryptography.fernet import Fernet
import logging
from datetime import datetime, timedelta
import bcrypt
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
import databases
import sqlalchemy
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime
from starlette.requests import Request
from starlette.responses import JSONResponse

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./moon_cloud.db")
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# SQLAlchemy models
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Server(Base):
    __tablename__ = "servers"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    status = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

# Database engine creation
engine = sqlalchemy.create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

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
FERNET_KEY = Fernet.generate_key() if not os.getenv("FERNET_KEY") else os.getenv("FERNET_KEY").encode()
fernet = Fernet(FERNET_KEY)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
api_key_header = APIKeyHeader(name="X-API-Key")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)

class UserInDB(BaseModel):
    id: int
    username: str
    created_at: datetime
    updated_at: datetime

class VMCommand(BaseModel):
    action: str
    params: Optional[dict] = None

class ServerInfo(BaseModel):
    id: int
    name: str
    status: str
    created_at: datetime
    updated_at: datetime

# Encryption functions
def encrypt_message(message: str) -> str:
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message: str) -> str:
    return fernet.decrypt(encrypted_message.encode()).decode()

# Authentication functions
def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def get_password_hash(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

async def get_user(username: str):
    async with database.transaction():
        query = sqlalchemy.select([User]).where(User.username == username)
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

# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.utcnow()
    response = await call_next(request)
    process_time = (datetime.utcnow() - start_time).total_seconds() * 1000
    logger.info(f"Request: {request.method} {request.url.path} - Status: {response.status_code} - Process Time: {process_time:.2f}ms")
    return response

# Error handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An unexpected error occurred. Please try again later."},
    )

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

@app.post("/users", response_model=UserInDB)
async def create_user(user: UserCreate):
    async with database.transaction():
        existing_user = await get_user(user.username)
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already registered")
        hashed_password = get_password_hash(user.password)
        query = User.__table__.insert().values(username=user.username, hashed_password=hashed_password)
        user_id = await database.execute(query)
        return {"id": user_id, "username": user.username, "created_at": datetime.utcnow(), "updated_at": datetime.utcnow()}

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
    async with database.transaction():
        query = sqlalchemy.select([Server])
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
        title="Moon Cloud Services API",
        version="1.0.0",
        description="API for managing virtual servers in the Moon Cloud Services platform",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
