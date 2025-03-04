from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi.responses import JSONResponse

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.get("/login")
@limiter.limit("5/minute")  # Max 5 requests per minute
async def login_attempt():
    return {"message": "Login attempt recorded!"}
