from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import base64

app = FastAPI(title="Password Encryption API")

# ===== Models =====
class EncryptRequest(BaseModel):
    pass_: str

    class Config:
        fields = {
            "pass_": "pass"
        }

class EncryptResponse(BaseModel):
    encrypted_pass: str

# ===== Encryption Logic =====
def encrypt_password(password: str) -> str:
    key_id = 45
    public_key = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1SaZ6oA\/8DU6nitD1Ua3\nrGIG4adnOS0\/cKEkZRgHrZQXLtLquWZwxKPCiAxr85ONMTNoJZa8UjyI0pYLmOsr\nZxetPeuMvkDhtliuwCDwlMasG8PSAQlC\/mHl7MhzbwHtQI2D1f9oSPbFcnL9xJs1\nmBh3fCFrDCTurxq\/8LTNf0x4VGtlFxwV\/L6vDvLbWUMUhdPbEvWdowpAndpU+\/a3\nSNW1wS+J3a5XRv6q\/DiASWg50zcKbQ4tfPRat1u4GxM0aFpeFxJZCdcOFkFr6Xf4\nNpfT8Z44\/sRyJfqAt3PXxa0D6PpHFs0yKwV66at43sM4QP6oeIYz\/d4JlL4DvSWt\nKQIDAQAB\n-----END PUBLIC KEY-----\n'
    session_key = get_random_bytes(32)
    iv = get_random_bytes(12)
    timestamp = str(int(time.time()))
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_v1_5.new(recipient_key)
    rsa_encrypted = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
    cipher_aes.update(timestamp.encode())
    aes_encrypted, tag = cipher_aes.encrypt_and_digest(password.encode('utf8'))
    size_buffer = len(rsa_encrypted).to_bytes(2, byteorder='little')
    payload = base64.b64encode(b''.join([
        b'\x01',
        key_id.to_bytes(1, byteorder='big'),
        iv,
        size_buffer,
        rsa_encrypted,
        tag,
        aes_encrypted,
    ]))
    return f'#PWD_FB4A:2:{timestamp}:{payload.decode()}'

# ===== Health Check =====
@app.get("/")
def health():
    return {"status": "ok"}

# ===== Endpoint =====
@app.post("/encrypt", response_model=EncryptResponse)
def encrypt(req: EncryptRequest):
    try:
        encrypted_pass = encrypt_password(req.pass_)
        return {"encrypted_pass": encrypted_pass}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
