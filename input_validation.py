from fastapi import FastAPI, Request, HTTPException, Depends
from pydantic import BaseModel, Field
import logging
import re
from datetime import datetime

# Setup Logger
logging.basicConfig(filename="security_events.log", level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

app = FastAPI()

# Middleware for Logging All Requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"Incoming Request - Method: {request.method}, Path: {request.url}")
    response = await call_next(request)
    return response

# Validation Function for SQL Injection Prevention
def validate_input(value: str):
    sql_injection_pattern = re.compile(r"(?:--|\b(SELECT|INSERT|DELETE|UPDATE|DROP|ALTER|CREATE|UNION|EXEC)\b)", re.IGNORECASE)
    if sql_injection_pattern.search(value):
        logger.warning(f"SQL Injection Attempt Detected: {value}")
        raise HTTPException(status_code=400, detail="Invalid input detected")
    return value

# Pydantic Model for Secure User Input
class SecureInput(BaseModel):
    username: str = Field(..., min_length=3, max_length=20, regex="^[a-zA-Z0-9_]+$")
    email: str
    comment: str

# API Route with Input Validation
@app.post("/submit/")
async def submit_form(data: SecureInput):
    validate_input(data.comment)  # Validate against SQL Injection
    logger.info(f"User {data.username} submitted a form with email {data.email}")
    return {"message": "Form submitted successfully!"}

# Logging Unauthorized Access Attempt
@app.get("/admin/")
async def admin_access(request: Request):
    client_ip = request.client.host
    logger.warning(f"Unauthorized Access Attempt from {client_ip}")
    raise HTTPException(status_code=403, detail="Access Denied")

