from app import app, bd, User


def make_admin(email):
    with app.app_context():  # ✅ Active le contexte Flask
        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"❌ Aucun utilisateur trouvé avec l'email : {email}")
            return

        user.is_admin = True
        bd.session.commit()
        print(
            f"✅ {user.nom} ({user.email}) est maintenant administrateur FitSafe IA !"
        )


if __name__ == "__main__":
    email = input("👉 Entre l'email de l'utilisateur à promouvoir : ").strip()
    make_admin(email)
