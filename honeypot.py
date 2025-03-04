@app.get("/fake-db")
async def fake_db(request: Request):
    security_logger.warning(f"SQL Injection Probe Attempt from {request.client.host}")
    return {"error": "Invalid endpoint"}
