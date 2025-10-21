# ai/weather_adapter.py
import requests
import os
from dotenv import load_dotenv

load_dotenv()


def get_weather(city=None, lat=None, lon=None):
    """Récupère la météo soit par ville, soit par coordonnées GPS"""
    api_key = os.getenv("WEATHER_API_KEY")
    if not api_key:
        raise ValueError("⚠️ Aucune clé API météo trouvée dans le fichier .env")

    if lat and lon:
        url = f"http://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={lon}&appid={api_key}&units=metric&lang=fr"
    else:
        city = city or "Paris"
        url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}&units=metric&lang=fr"

    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        return {
            "temp": data["main"]["temp"],
            "condition": data["weather"][0]["description"],
        }
    return None
