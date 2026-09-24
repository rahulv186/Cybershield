from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import prevention

app = FastAPI(
    title="CyberShield Unblock API",
    version="1.0.0"
)

# Allow frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class UnblockRequest(BaseModel):
    ip: str


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "CyberShield Unblock API"
    }


@app.post("/api/unblock")
def unblock_ip(request: UnblockRequest):
    ip = request.ip.strip()

    if not ip:
        raise HTTPException(
            status_code=400,
            detail="IP address is required"
        )

    print(f"[API] Unblock request received: {ip}")

    try:
        success = prevention.unblock_ip(ip)

        if not success:
            raise HTTPException(
                status_code=500,
                detail=f"Failed to remove firewall rule for {ip}"
            )

        return {
            "success": True,
            "message": f"IP {ip} unblocked successfully",
            "ip": ip
        }

    except HTTPException:
        raise

    except Exception as e:
        print(f"[API ERROR] {e}")

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

if __name__ == "__main__":
    import uvicorn

    print("🚀 CyberShield Unblock API")
    print("📡 http://0.0.0.0:5060")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=5060
    )