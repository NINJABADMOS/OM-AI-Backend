# OM-AI-Backend
OM AI FastAPI backend
🧠 om_ai_full_app.py (One File — Copy/Paste Ready)

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from datetime import datetime
import hashlib

# ======= DATABASE SETUP ========
SQLALCHEMY_DATABASE_URL = "sqlite:///./om_ai.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

# ======= MODELS ========
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_pro = Column(Boolean, default=False)
    is_blocked = Column(Boolean, default=False)

class RequestLog(Base):
    __tablename__ = "request_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    request_type = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

# ======= SCHEMAS ========
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: EmailStr
    is_pro: bool
    is_blocked: bool
    class Config:
        orm_mode = True

class RequestInput(BaseModel):
    input_text: str
    input_type: str  # image or video

# ======= UTILS ========
def get_password_hash(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return get_password_hash(plain) == hashed

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ======= APP INIT ========
app = FastAPI()
Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True
)

# ======= ROUTES ========

@app.post("/register", response_model=UserOut)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter((User.username == user.username) | (User.email == user.email)).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    new_user = User(
        username=user.username,
        email=user.email,
        password=get_password_hash(user.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login", response_model=UserOut)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    if db_user.is_blocked:
        raise HTTPException(status_code=403, detail="Account is blocked")
    return db_user

@app.post("/generate")
def generate(request: RequestInput, username: str, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == username).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.is_blocked:
        raise HTTPException(status_code=403, detail="User is blocked")
    log = RequestLog(user_id=db_user.id, request_type=request.input_type)
    db.add(log)
    db.commit()
    return {"result": f"{request.input_type} generated for '{request.input_text}' by {username}"}

@app.get("/admin/users")
def all_users(secret: str, db: Session = Depends(get_db)):
    if secret != "om_admin_123":
        raise HTTPException(status_code=401, detail="Unauthorized")
    return db.query(User).all()

@app.post("/admin/block_user")
def block(username: str, secret: str, db: Session = Depends(get_db)):
    if secret != "om_admin_123":
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_blocked = True
    db.commit()
    return {"msg": f"{username} blocked"}

@app.post("/admin/unblock_user")
def unblock(username: str, secret: str, db: Session = Depends(get_db)):
    if secret != "om_admin_123":
        raise HTTPException(status_code=401, detail="Unauthorized")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_blocked = False
    db.commit()
    return {"msg": f"{username} unblocked"}
    
#Requirment.txt

fastapi==0.111.0
uvicorn==0.30.1
python-multipart==0.0.9
pydantic==2.7.1
sqlalchemy==2.0.30
passlib[bcrypt]==1.7.4
python-jose==3.3.0
requests==2.31.0
email-validator==2.1.1
aiofiles==23.2.1
