# ai/data_processing.py
import pandas as pd


def prepare_workout_data(workouts):
    """Nettoie les données des entraînements avant analyse"""
    df = pd.DataFrame(workouts)
    if "date" in df.columns:
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
    if "duration" in df.columns:
        df["duration"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0)
    return df.dropna(subset=["type"])
