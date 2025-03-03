import os
import sqlite3
from datetime import datetime, timedelta

import geopy.distance
import jwt
import requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

# Configuração do banco de dados
conn = sqlite3.connect("tracking.db", check_same_thread=False)
c = conn.cursor()
c.execute(
    """CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT,
                latitude REAL,
                longitude REAL,
                timestamp TEXT
            )"""
)
c.execute(
    """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                hashed_password TEXT
            )"""
)
conn.commit()

# Configuração de autenticação
SECRET_KEY = os.getenv("SECRET_KEY", "mysecret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Coordenadas da escola (exemplo)
SAFE_ZONES = {
    "school": (51.123456, -1.123456),  # Substituir pelas coordenadas reais
    "home": (51.654321, -1.654321),
}
GEOFENCE_RADIUS = 500  # Raio de segurança em metros

# Token do Telegram
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


# Modelos
class LocationData(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    timestamp: str = datetime.utcnow().isoformat()


class Token(BaseModel):
    access_token: str
    token_type: str


class UserCreate(BaseModel):
    username: str
    password: str


# Funções de autenticação
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(username: str, password: str):
    c.execute("SELECT hashed_password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if user and verify_password(password, user[0]):
        return username
    return None


def get_current_user(token: str = Security(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(
                status_code=401, detail="Invalid authentication credentials"
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401, detail="Invalid authentication credentials"
        )


# Rotas de autenticação
@app.post("/token", response_model=Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user}, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/register")
def register_user(user: UserCreate):
    hashed_password = get_password_hash(user.password)
    try:
        c.execute(
            "INSERT INTO users (username, hashed_password) VALUES (?, ?)",
            (user.username, hashed_password),
        )
        conn.commit()
        return {"message": "User registered successfully"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")


# Função para verificar geofencing
def check_geofence(latitude, longitude):
    for zone, coords in SAFE_ZONES.items():
        distance = geopy.distance.geodesic((latitude, longitude), coords).meters
        if distance <= GEOFENCE_RADIUS:
            return zone  # Está dentro da área segura
    return None  # Fora de áreas seguras


# Função para enviar alerta via Telegram
def send_telegram_alert(message):
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
        requests.post(url, data=payload)


@app.post("/location/")
def receive_location(data: LocationData, current_user: str = Depends(get_current_user)):
    try:
        c.execute(
            "INSERT INTO locations (device_id, latitude, longitude, timestamp) VALUES (?, ?, ?, ?)",
            (data.device_id, data.latitude, data.longitude, data.timestamp),
        )
        conn.commit()

        # Verificar se está dentro de uma zona segura
        zone = check_geofence(data.latitude, data.longitude)
        if not zone:
            send_telegram_alert(f"⚠️ Alerta! {data.device_id} saiu de uma área segura!")

        return {"message": "Location stored successfully", "geofence_status": zone}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/locations/{device_id}")
def get_locations(device_id: str, current_user: str = Depends(get_current_user)):
    c.execute(
        "SELECT latitude, longitude, timestamp FROM locations WHERE device_id = ? ORDER BY timestamp DESC",
        (device_id,),
    )
    locations = c.fetchall()
    if not locations:
        raise HTTPException(status_code=404, detail="No locations found")
    return {"device_id": device_id, "locations": locations}
