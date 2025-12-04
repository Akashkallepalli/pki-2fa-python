from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path

from .crypto_utils import load_private_key, decrypt_seed
from .totp_utils import generate_totp_code, verify_totp_code, seconds_remaining_in_period
from .config import SEED_FILE, DATA_DIR

app = FastAPI(title="PKI 2FA Microservice")


class DecryptSeedRequest(BaseModel):
    encrypted_seed: str


class Verify2FARequest(BaseModel):
    code: str | None = None


@app.on_event("startup")
def ensure_directories():
    """Create data directory on startup"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/health")
def health():
    """Health check endpoint"""
    return {"status": "ok"}


@app.post("/decrypt-seed")
def decrypt_seed_endpoint(body: DecryptSeedRequest):
    """
    Decrypt encrypted seed and store persistently
    
    Request: {"encrypted_seed": "BASE64_STRING..."}
    Response: {"status": "ok"} or {"error": "Decryption failed"}
    """
    # Load student private key
    try:
        private_key = load_private_key("student_private.pem")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Private key load failed: {e}")
    
    # Decrypt seed
    try:
        hex_seed = decrypt_seed(body.encrypted_seed, private_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed")
    
    # Save to persistent storage
    try:
        SEED_FILE.write_text(hex_seed + "\n", encoding="utf-8")
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to persist seed")
    
    return {"status": "ok"}


@app.get("/generate-2fa")
def generate_2fa():
    """
    Generate current TOTP code
    
    Response: {"code": "123456", "valid_for": 30}
    """
    # Check if seed exists
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    
    # Read seed from persistent storage
    try:
        hex_seed = SEED_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        raise HTTPException(status_code=500, detail="Error reading seed")
    
    # Generate TOTP code
    try:
        code = generate_totp_code(hex_seed)
        valid_for = seconds_remaining_in_period(30)
    except Exception:
        raise HTTPException(status_code=500, detail="Error generating TOTP")
    
    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
def verify_2fa(body: Verify2FARequest):
    """
    Verify TOTP code with ±1 period tolerance
    
    Request: {"code": "123456"}
    Response: {"valid": true} or {"valid": false}
    """
    # Validate code is provided
    if body.code is None or body.code.strip() == "":
        raise HTTPException(status_code=400, detail="Missing code")
    
    # Check if seed exists
    if not SEED_FILE.exists():
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")
    
    # Read seed
    try:
        hex_seed = SEED_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        raise HTTPException(status_code=500, detail="Error reading seed")
    
    # Verify TOTP code
    try:
        valid = verify_totp_code(hex_seed, body.code, valid_window=1)
    except Exception:
        raise HTTPException(status_code=500, detail="Error verifying TOTP")
    
    return {"valid": valid}
