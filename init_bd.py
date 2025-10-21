from app import bd, app

with app.app_context():
    bd.create_all()
    print("✅ Base de données initialisée avec succès !")
