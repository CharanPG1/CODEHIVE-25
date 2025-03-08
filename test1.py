from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

# App Initialization
app = FastAPI()

# Database Configuration
DATABASE_URL = "sqlite:///./test1.db"
engine = create_engine(DATABASE_URL)
sessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Config
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User Model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String)

# Incident Model
class Incident(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String, index=True)
    attack_type = Column(String)

Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class UserCreate(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class IncidentCreate(BaseModel):
    ip: str
    attack_type: str

# Dependency: Database Session
def get_db():
    db = sessionLocal()
    try:
        yield db
    finally:
        db.close()

# Generate JWT Token
def create_token(username: str):
    payload = {"sub": username, "exp": datetime.utcnow() + timedelta(hours=2)}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

# Verify JWT Token
def verify_token(authorization: str = Header(None)):
    if authorization is None:
        raise HTTPException(status_code=401, detail="Missing Token")
    try:
        token = authorization.split("Bearer ")[1]
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token Expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid Token")

# Register User
@app.post("/users/register/")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(username=user.username, password_hash=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

# Login
@app.post("/users/login/")
def login(user: LoginRequest, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not pwd_context.verify(user.password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    return {"token": create_token(user.username)}

# Report an Incident (🔒 Protected)
@app.post("/incidents/report/")
def report_incident(incident: IncidentCreate, db: Session = Depends(get_db), username: str = Depends(verify_token)):
    db_incident = Incident(ip=incident.ip, attack_type=incident.attack_type)
    db.add(db_incident)
    db.commit()
    db.refresh(db_incident)
    return {"message": "Incident reported successfully", "id": db_incident.id}

# View Incidents (🔒 Protected)
@app.get("/incidents/")
def view_incidents(db: Session = Depends(get_db), username: str = Depends(verify_token)):
    incidents = db.query(Incident).all()
    return incidents

# Home Page
@app.get("/", response_class=HTMLResponse)
async def root():
    return '''
    <html>
        <h1>Welcome to Cybersecurity Incident System</h1>
    </html>
    '''
