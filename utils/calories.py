def calories_brulees(
    type_exercice: str,
    duree_min: float,
    poids_kg: float = 70,
    series: int = 3,
    reps: int = 10,
):
    """Calcule les calories brûlées en tenant compte du temps de repos estimé automatiquement."""

    MET_VALUES = {
        "Pectoraux": 6.0,
        "Dos": 6.0,
        "Jambes": 7.0,
        "Épaules": 5.5,
        "Avant_Bras": 4.0,
        "Biceps": 5.5,
        "Triceps": 5.5,
        "Abdominaux": 5.0,
        "Cardio": 9.0,
    }

    REPOS_MOYEN = {
        "Pectoraux": 1.0,
        "Dos": 1.0,
        "Jambes": 1.2,
        "Épaules": 0.8,
        "Avant_Bras": 0.5,
        "Biceps": 0.8,
        "Triceps": 0.8,
        "Abdominaux": 0.5,
        "Cardio": 0.2,
    }

    met = MET_VALUES.get(type_exercice, 5.0)
    repos_moyen = REPOS_MOYEN.get(type_exercice, 1.0)

    # Estimation effort + repos
    duree_effort_min = (series * reps * 2) / 60
    duree_theorique_min = duree_effort_min + (series - 1) * repos_moyen

    # Ajustement du ratio réel d'effort
    ratio_effort = min(1.0, duree_effort_min / duree_min) if duree_min else 1.0

    calories = met * poids_kg * ((duree_min * ratio_effort) / 60)
    return round(calories, 2)
