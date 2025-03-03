import sqlite3
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

# Criando o banco de dados
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
conn.commit()


# Modelo para receber localização
class LocationData(BaseModel):
    device_id: str
    latitude: float
    longitude: float
    timestamp: str = datetime.utcnow().isoformat()


@app.post("/location/")
def receive_location(data: LocationData):
    try:
        c.execute(
            "INSERT INTO locations (device_id, latitude, longitude, timestamp) VALUES (?, ?, ?, ?)",
            (data.device_id, data.latitude, data.longitude, data.timestamp),
        )
        conn.commit()
        return {"message": "Location stored successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/locations/{device_id}")
def get_locations(device_id: str):
    c.execute(
        "SELECT latitude, longitude, timestamp FROM locations WHERE device_id = ? ORDER BY timestamp DESC",
        (device_id,),
    )
    locations = c.fetchall()
    if not locations:
        raise HTTPException(status_code=404, detail="No locations found")
    return {"device_id": device_id, "locations": locations}
