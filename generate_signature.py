import hmac
import hashlib

SECRET_KEY = "mysecretkey"
payload = '{"event":"user_created","message":"Nuevo usuario creado","user_id":123}'

# Generar la firma HMAC
signature = hmac.new(
    SECRET_KEY.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256
).hexdigest()

print("Firma HMAC:", signature)
