import numpy as np
import pandas as pd
from datetime import datetime, timedelta


class FitSafeAIModel:
    """
    Moteur d'analyse FitSafe AI (version scientifique)
    - Calcule la charge d'entraînement via RPE × durée
    - Pondère selon le groupe musculaire
    - Ajuste selon le niveau utilisateur et la météo
    - Retourne un score de risque (0–100)
    """

    def __init__(self, user_data, workouts, weather_data=None):
        self.user_data = user_data or {}
        self.workouts = pd.DataFrame(workouts) if workouts else pd.DataFrame()
        self.weather_data = weather_data or {}

    def compute_risk_score(self):
        """Calcule le score de risque basé sur la charge physiologique"""
        if self.workouts.empty:
            return 0

        # Nettoyage des dates
        self.workouts["date"] = pd.to_datetime(self.workouts["date"], errors="coerce")

        # Table RPE et pondération musculaire
        rpe_map = {
            "Jambes": (8.0, 1.3),
            "Dos": (7.5, 1.2),
            "Pectoraux": (7.0, 1.1),
            "Épaules": (7.0, 1.0),
            "Biceps": (6.5, 0.9),
            "Triceps": (6.5, 0.9),
            "Avant_Bras": (5.5, 0.7),
            "Abdominaux": (6.0, 0.8),
            "Cardio": (7.5, 1.1),
        }

        # Calcul de la charge par exercice
        total_load = 0
        for _, w in self.workouts.iterrows():
            exo_type = w.get("type", "Full Body")
            duration = float(w.get("duration", 0))

            if exo_type in rpe_map:
                rpe, factor = rpe_map[exo_type]
            else:
                rpe, factor = (6.5, 1.0)  # valeur neutre par défaut

            load = duration * rpe * factor
            total_load += load

        # Moyenne journalière sur 7 jours récents
        recent = self.workouts[
            self.workouts["date"] > datetime.now() - timedelta(days=7)
        ]
        if not recent.empty:
            recent_load = recent["duration"].sum() * 7  # volume semaine
        else:
            recent_load = total_load

        # Capacité max estimée selon le niveau utilisateur
        niveau = self.user_data.get("niveau", 2)
        base_capacity = {1: 400, 2: 700, 3: 1000}[niveau]

        # Calcul brut du risque
        raw_risk = total_load / base_capacity

        # Lissage via fonction sigmoïde (évite les pics)
        risk_score = 100 / (1 + np.exp(-3 * (raw_risk - 1)))

        # Ajustement météo
        temp = self.weather_data.get("temp", 20)
        if temp > 30:
            risk_score *= 1.1  # chaleur
        elif temp < 5:
            risk_score *= 1.05  # froid

        # Clip entre 0 et 100
        return round(np.clip(risk_score, 0, 100), 1)

    def suggest_program(self):
        """Propose un ajustement d'entraînement équilibré"""
        if self.workouts.empty:
            return "Commence avec un programme Full Body 3x/semaine pour établir une base 💪"

        counts = self.workouts["type"].value_counts()
        top = counts.index[0]

        if top in ["Pectoraux", "Triceps"]:
            return "Travaille ton dos ou tes jambes pour équilibrer le haut du corps."
        elif top in ["Dos", "Biceps"]:
            return "Ajoute une séance jambes pour renforcer ta base."
        elif top == "Jambes":
            return "Pense à intégrer gainage et mobilité pour prévenir les blessures."
        elif top == "Cardio":
            return "Varie avec du renforcement musculaire pour la stabilité."
        return "Programme équilibré 👍 continue comme ça !"

    def predict_next_focus(self):
        """Prévoit le prochain groupe musculaire à cibler"""
        if self.workouts.empty:
            return "💪 Commence avec un Full Body pour évaluer ton niveau."
        last_types = self.workouts["type"].tail(5).tolist()
        if last_types.count("Jambes") < 2:
            return (
                "🦵 Travaille les jambes cette semaine pour équilibrer ton programme."
            )
        if last_types.count("Pectoraux") > 2:
            return "💪 Diminue le haut du corps et renforce le dos."
        return "🔥 Continue ton rythme, ton équilibre est bon."
