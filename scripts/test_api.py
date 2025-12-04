#!/usr/bin/env python3
"""
Test script to request encrypted seed and test all API endpoints
"""
import requests
import json
from pathlib import Path

# ===== EDIT THESE VALUES =====
STUDENT_ID = "23MH1A1220"  # Replace with your actual student ID
GITHUB_REPO_URL = "https://github.com/Akashkallepalli/pki-2fa-python"  
API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"
# =============================

def load_public_key_text(path: str) -> str:
    """Load public key as text"""
    pem = Path(path).read_text(encoding="utf-8")
    return pem


def request_encrypted_seed():
    """Request encrypted seed from instructor API"""
    print("\n" + "="*60)
    print("STEP 1: Request Encrypted Seed from Instructor API")
    print("="*60)
    
    # Load student public key
    public_key_pem = load_public_key_text("student_public.pem")
    
    # Prepare payload
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": public_key_pem,
    }
    
    print(f"\n📝 Payload:")
    print(f"   Student ID: {STUDENT_ID}")
    print(f"   GitHub Repo: {GITHUB_REPO_URL}")
    print(f"   Public Key: {len(public_key_pem)} bytes")
    
    # Send POST request
    try:
        print(f"\n🔄 Calling: {API_URL}")
        resp = requests.post(API_URL, json=payload, timeout=30)
        resp.raise_for_status()
    except Exception as e:
        print(f"❌ API request failed: {e}")
        raise
    
    # Parse response
    data = resp.json()
    print(f"\n✅ Response status: {data.get('status')}")
    
    if data.get("status") != "success":
        print(f"❌ Error: {data}")
        raise RuntimeError(f"API error: {data}")
    
    # Save encrypted seed
    encrypted_seed = data["encrypted_seed"].strip()
    Path("encrypted_seed.txt").write_text(encrypted_seed, encoding="utf-8")
    
    print(f"✅ Encrypted seed saved to: encrypted_seed.txt")
    print(f"   Length: {len(encrypted_seed)} bytes")
    
    return encrypted_seed


def test_decrypt_seed(encrypted_seed: str):
    """Test /decrypt-seed endpoint"""
    print("\n" + "="*60)
    print("STEP 2: Test /decrypt-seed Endpoint")
    print("="*60)
    
    payload = {"encrypted_seed": encrypted_seed}
    
    try:
        print(f"\n🔄 POST http://localhost:8080/decrypt-seed")
        resp = requests.post(
            "http://localhost:8080/decrypt-seed",
            json=payload,
            timeout=5
        )
        data = resp.json()
        
        if resp.status_code == 200:
            print(f"✅ Status: {resp.status_code}")
            print(f"   Response: {data}")
        else:
            print(f"❌ Status: {resp.status_code}")
            print(f"   Response: {data}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")


def test_generate_2fa():
    """Test /generate-2fa endpoint"""
    print("\n" + "="*60)
    print("STEP 3: Test /generate-2fa Endpoint")
    print("="*60)
    
    try:
        print(f"\n🔄 GET http://localhost:8080/generate-2fa")
        resp = requests.get("http://localhost:8080/generate-2fa", timeout=5)
        data = resp.json()
        
        if resp.status_code == 200:
            print(f"✅ Status: {resp.status_code}")
            print(f"   Code: {data['code']}")
            print(f"   Valid for: {data['valid_for']} seconds")
            return data['code']
        else:
            print(f"❌ Status: {resp.status_code}")
            print(f"   Response: {data}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")


def test_verify_2fa(code: str):
    """Test /verify-2fa endpoint"""
    print("\n" + "="*60)
    print("STEP 4: Test /verify-2fa Endpoint")
    print("="*60)
    
    # Test with valid code
    print(f"\n✓ Testing with VALID code: {code}")
    try:
        resp = requests.post(
            "http://localhost:8080/verify-2fa",
            json={"code": code},
            timeout=5
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Response: {data}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
    
    # Test with invalid code
    print(f"\n✗ Testing with INVALID code: 000000")
    try:
        resp = requests.post(
            "http://localhost:8080/verify-2fa",
            json={"code": "000000"},
            timeout=5
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Response: {data}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")
    
    # Test with missing code
    print(f"\n✗ Testing with MISSING code")
    try:
        resp = requests.post(
            "http://localhost:8080/verify-2fa",
            json={},
            timeout=5
        )
        data = resp.json()
        print(f"  Status: {resp.status_code}")
        print(f"  Response: {data}")
    except Exception as e:
        print(f"  ❌ Request failed: {e}")


def main():
    """Run all tests"""
    print("\n\n")
    print("█" * 60)
    print("PKI 2FA Microservice - Complete API Test")
    print("█" * 60)
    
    # Step 1: Request encrypted seed
    try:
        encrypted_seed = request_encrypted_seed()
    except Exception as e:
        print(f"\n❌ Failed to get encrypted seed: {e}")
        print("\n⚠️  Check that:")
        print(f"   1. STUDENT_ID is correct (currently: {STUDENT_ID})")
        print(f"   2. GITHUB_REPO_URL is correct (currently: {GITHUB_REPO_URL})")
        print(f"   3. student_public.pem exists and is valid")
        print(f"   4. You have internet connection")
        return
    
    # Step 2: Test decrypt-seed
    test_decrypt_seed(encrypted_seed)
    
    # Step 3: Test generate-2fa
    code = test_generate_2fa()
    
    # Step 4: Test verify-2fa
    if code:
        test_verify_2fa(code)
    
    print("\n\n" + "="*60)
    print("✅ All tests completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
