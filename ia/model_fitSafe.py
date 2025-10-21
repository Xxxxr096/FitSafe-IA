# ai/model_fitSafe.py
import numpy as np
import pandas as pd
from datetime import datetime, timedelta


class FitSafeAIModel:
    """
    Moteur d'analyse FitSafe AI :
    - Analyse les entraînements de l'utilisateur
    - Calcule un score de risque
    - Fournit des recommandations dynamiques
    """

    def __init__(self, user_data, workouts, weather_data=None):
        self.user_data = user_data
        self.workouts = pd.DataFrame(workouts) if workouts else pd.DataFrame()
        self.weather_data = weather_data

    def compute_risk_score(self):
        """Évalue la fatigue potentielle et le risque de blessure"""
        if self.workouts.empty:
            return 0

        self.workouts["date"] = pd.to_datetime(self.workouts["date"])
        recent = self.workouts[
            self.workouts["date"] > datetime.now() - timedelta(days=7)
        ]
        avg_duration = self.workouts["duration"].mean()
        freq = len(recent)
        intensity = avg_duration * (freq + 1)

        # Ajustement selon météo
        weather_factor = (
            1.1 if self.weather_data and self.weather_data.get("temp", 20) > 30 else 1.0
        )
        fatigue_factor = np.clip(
            intensity / (self.user_data.get("niveau", 2) * 100), 0, 1
        )

        risk_score = round(fatigue_factor * 100 * weather_factor, 2)
        return min(risk_score, 100)

    def suggest_program(self):
        """Propose un programme équilibré selon les séances récentes"""
        if self.workouts.empty:
            return "Commence avec un programme complet : Full Body x3 par semaine 💪"

        types = self.workouts["type"].value_counts()
        most_done = types.index[0]
        suggestions = {
            "Pectoraux / Triceps": "Ajoute une séance 'Dos / Biceps' pour équilibrer ton haut du corps.",
            "Dos / Biceps": "Travaille tes jambes pour un meilleur équilibre musculaire.",
            "Jambes": "Ajoute du gainage et de la mobilité pour éviter les blessures.",
            "Full Body": "Passe sur un split Push / Pull / Legs pour progresser plus vite.",
        }
        return suggestions.get(most_done, "Continue ton rythme, tu progresses bien 🔥")

    def predict_next_focus(self):
        """Prévoit la zone musculaire à prioriser"""
        if self.workouts.empty:
            return "🦵 Commence par une base 'Full Body' légère."
        recent_types = self.workouts["type"].tail(5).tolist()
        if recent_types.count("Jambes") < 2:
            return "🦵 Focus jambes cette semaine pour équilibrer ton programme."
        elif recent_types.count("Pectoraux / Triceps") > 2:
            return "💪 Allège le haut du corps et travaille ton dos."
        return "🔥 Continue ton cycle actuel, tu es bien équilibré."
