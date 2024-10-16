from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from jose import JWTError, jwt, jwe, jws
from faker import Faker
from pydantic import BaseModel, HttpUrl

app = FastAPI()

JOSE_SECRET_KEY = "asecret128bitkey"
JOSE_ENC_ALGO = "A128GCM"
JOSE_ALGO = 'dir'
JOSE_JWT_SECRET_KEY = "ajwtsecret"
JOSE_JWT_ALGO = "HS256"

fake = Faker()

fake_db = {
    "account": str(fake.aba()),
    "routing": str(fake.bban())
}

def generate_jwt(data: dict) -> str:
    return jwt.encode(data, JOSE_JWT_SECRET_KEY, algorithm=JOSE_JWT_ALGO)

def generate_jwe(data: str) -> str:
    return jwe.encrypt(data, JOSE_SECRET_KEY, algorithm=JOSE_ALGO, encryption=JOSE_ENC_ALGO)

def get_jwt_claims(data: str) -> str:
    return jwt.decode(data, JOSE_JWT_SECRET_KEY, algorithms=[JOSE_JWT_ALGO])

def get_jwe(data: str) -> str:
    return jwe.decrypt(data, JOSE_SECRET_KEY)

class Token(BaseModel):
    token: str

class SecureLink(BaseModel):
    url: str

class AccountData(BaseModel):
    account: str = None
    routing: str = None

@app.get("/", response_class=HTMLResponse)
async def root():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Secure Link Generator</title>
    </head>
    <body>
        <h1>Welcome to the Secure Link Generator</h1>
        <p><a href="/generate_secure_link">Generate Secure Link</a></p>
    </body>
    </html>
    """
    return html_content

@app.get("/generate", response_model=Token)
async def generate():
    signed = generate_jwt(fake_db)
    print(f'[>] Signed token: {signed} - len: {len(signed)}')
    token = Token(token=generate_jwe(signed))
    print(f'[>] Encrypted token: {token.token} - len: {len(token.token)}')
    return token

@app.get("/generate_secure_link", response_model=SecureLink)
async def generate_secure_link():
    signed = generate_jwt(fake_db)
    print(f'[>] Signed token: {signed} - len: {len(signed)}')
    token = Token(token=generate_jwe(signed))
    print(f'[>] Encrypted token: {token.token} - len: {len(token.token)}')
    secure_link = SecureLink(url=f"/view_account/?token={token.token}")
    return secure_link

@app.get("/view_account", response_model=AccountData)
async def view_account(token: str):
    token = get_jwe(token)
    print(f'[>] Decrypted token: {token} - len: {len(token)}')
    jwt_token = get_jwt_claims(token)
    print(f'[>] Verified claims: {jwt_token} - len: {len(jwt_token)}')
    return AccountData(**jwt_token)
