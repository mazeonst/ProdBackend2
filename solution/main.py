import os
from fastapi import FastAPI
import uvicorn

app = FastAPI()

@app.get("/api/ping")
def send():
    return {"status": "PROOOD"}

if __name__ == "__main__":
    host, port = "0.0.0.0", 8080
    addr = os.getenv("SERVER_ADDRESS")
    if addr and ":" in addr:
        splitted = addr.split(":")
        host = splitted[0]
        port = int(splitted[1])
    uvicorn.run(app, host=host, port=port)
