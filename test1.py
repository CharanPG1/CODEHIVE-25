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
@app.get("/users/register/", response_class=HTMLResponse)
def reg():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Log In - QNote</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100">
  <div class="flex flex-col justify-center items-center min-h-screen">
    <!-- Logo -->
    <div class="mb-6">
        <img src="\assets\logobg.png" class="w-48 h-auto" alt="logo">
    </div>

    <!-- Log-In Form -->
    <div class="bg-white shadow-md rounded-lg w-full max-w-md p-6">
      <h2 class="text-2xl font-semibold text-gray-800 mb-4">Log In to Your Account</h2>
      <form action="#" method="POST" class="space-y-4">
        <!-- Email -->
        <div>
          <label for="email" class="block text-sm font-medium text-gray-700">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            required
            class="mt-1 w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-purple-500 focus:border-purple-500"
            placeholder="Enter your email"
          />
        </div>

        <!-- Password -->
        <div>
          <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
          <input
            type="password"
            id="password"
            name="password"
            required
            class="mt-1 w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-purple-500 focus:border-purple-500"
            placeholder="Enter your password"
          />
        </div>

        <!-- Submit Button -->
        <div>
          <button
            type="submit"
            class="w-full bg-purple-600 text-white py-2 px-4 rounded-lg hover:bg-purple-500 focus:outline-none focus:ring-2 focus:ring-purple-500 focus:ring-offset-2"
          >
            Log In
          </button>
        </div>
      </form>

      <!-- Don't have an account? -->
      <p class="mt-4 text-sm text-gray-800">
        Don't have an account?
        <a href="\frontend\signUp\signup.html" class="text-purple-500 hover:underline"> <strong>Sign up</strong></a>
      </p>
    </div>
  </div>
</body>
</html>
'''

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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="flex items-center justify-center h-screen bg-gray-100">
    <button class="px-6 py-3 mt-4 text-sm text-gray-800 bg-blue-500 rounded-lg shadow-md hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-400">
        Login
    </button>
</body>
</html>

    '''
