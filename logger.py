from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel, Field
import logging
import re
from datetime import datetime

#Set up General Activity Logger
app_logger = logging.getLogger("app_logger")
app_logger.setLevel(logging.INFO)
app_handler = logging.FileHandler("app_activity.log")  # General activity log
app_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
app_handler.setFormatter(app_formatter)
app_logger.addHandler(app_handler)

#Set up Security Logger
security_logger = logging.getLogger("security_logger")
security_logger.setLevel(logging.WARNING)
security_handler = logging.FileHandler("security_events.log")  # Security-specific log
security_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
security_handler.setFormatter(security_formatter)
security_logger.addHandler(security_handler)

app = FastAPI()

# Middleware for Logging All Requests (General Activity)
@app.middleware("http")
async def log_requests(request: Request, call_next):
    app_logger.info(f"Incoming Request - Method: {request.method}, Path: {request.url}")
    response = await call_next(request)
    return response

# Function for SQL Injection Prevention (Security)
def validate_input(value: str):
    sql_injection_pattern = re.compile(r"(?:--|\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|UNION|EXEC)\b)", re.IGNORECASE)
    if sql_injection_pattern.search(value):
        security_logger.warning(f"SQL Injection Attempt Detected: {value}")
        raise HTTPException(status_code=400, detail="Invalid input detected")
    return value

# Pydantic Model for Secure User Input
class SecureInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=20, regex="^[a-zA-Z0-9_]+$")
    email: str
    comment: str

#API Route with Input Validation & Logging (General Activity)
@app.post("/submit/")
async def submit_form(data: SecureInput):
    validate_input(data.comment)  # Validate input for SQL Injection
    app_logger.info(f"User {data.username} submitted a form with email {data.email}")
    return {"message": "Form submitted successfully!"}

#Logging Unauthorized Access Attempt (Security)
@app.get("/admin/")
async def admin_access(request: Request):
    client_ip = request.client.host
    security_logger.warning(f"Unauthorized Access Attempt from {client_ip}")
    raise HTTPException(status_code=403, detail="Access Denied")

#Example General Activity Log
@app.get("/user/{user_id}")
async def get_user(user_id: int):
    app_logger.info(f"👤 User data requested for User ID: {user_id}")
    return {"user_id": user_id, "name": "John Doe"}

