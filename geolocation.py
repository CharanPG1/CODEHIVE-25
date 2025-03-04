import requests

def get_ip_info(ip):
    response = requests.get(f"http://ip-api.com/json/{ip}")
    return response.json()

@app.get("/track-ip")
async def track_ip(request: Request):
    client_ip = request.client.host
    ip_info = get_ip_info(client_ip)
    return ip_info
