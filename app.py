from flask import Flask, render_template, request, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    UserMixin,
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)

from flask_bcrypt import Bcrypt
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import generate_csrf
from datetime import datetime
from datetime import date
from wtforms import StringField, TextAreaField
from wtforms.validators import DataRequired, Email, Length
from flask_wtf import FlaskForm
from email.mime.multipart import MIMEMultipart
from flask import render_template, request
from flask_login import login_required, current_user
from datetime import datetime
from collections import defaultdict

from ia.model_fitSafe import FitSafeAIModel
from ia.weather_adapter import get_weather
from utils.calories import (
    calories_brulees,
)


load_dotenv()
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
# app.config["SESSION_COOKIE_SECURE"] = True  # only works with HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.permanent_session_lifetime = timedelta(minutes=30)
app.config["SESSION_PERMANENT"] = False

bd = SQLAlchemy(app)
bycrypt = Bcrypt(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class ContactForm(FlaskForm):
    nom = StringField("Nom complet", validators=[DataRequired(), Length(min=2, max=80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    sujet = StringField("Sujet", validators=[DataRequired(), Length(min=3, max=100)])
    message = TextAreaField("Message", validators=[DataRequired(), Length(min=10)])


# DATA BASE
class User(bd.Model, UserMixin):
    id = bd.Column(bd.Integer, primary_key=True, autoincrement=True)
    nom = bd.Column(bd.String(100), nullable=False)
    email = bd.Column(bd.String(120), unique=True, nullable=False)
    password = bd.Column(bd.String(256), nullable=False)
    age = bd.Column(bd.Integer, nullable=True)
    taille = bd.Column(bd.Float, nullable=True)
    poids = bd.Column(bd.Float, nullable=True)
    niveau = bd.Column(bd.String(50), nullable=True)

    confirmed = bd.Column(bd.Boolean, default=False)

    latitude = bd.Column(bd.Float, nullable=True)
    longitude = bd.Column(bd.Float, nullable=True)

    is_admin = bd.Column(bd.Boolean, default=False)
    is_banned = bd.Column(bd.Boolean, default=False)
    date_created = bd.Column(bd.DateTime, default=datetime.utcnow)


class Session(bd.Model):
    id = bd.Column(bd.Integer, primary_key=True, autoincrement=True)
    name = bd.Column(bd.String(100), nullable=False)
    user_id = bd.Column(bd.Integer, bd.ForeignKey("user.id"), nullable=False)
    workouts = bd.relationship(
        "Workout", backref="session", lazy=True, cascade="all, delete-orphan"
    )


class Workout(bd.Model):
    id = bd.Column(bd.Integer, primary_key=True, autoincrement=True)
    user_id = bd.Column(bd.Integer, bd.ForeignKey("user.id"), nullable=False)
    session_id = bd.Column(bd.Integer, bd.ForeignKey("session.id"), nullable=True)

    type = bd.Column(bd.String(100), nullable=False)  # ex: "Pectoraux / Triceps"
    exercise = bd.Column(bd.String(100), nullable=False)  # ex: "Développé couché"
    series = bd.Column(bd.Integer, nullable=False, default=3)
    reps = bd.Column(bd.Integer, nullable=False, default=10)

    duration = bd.Column(bd.Integer, nullable=False)  # durée totale pour cet exercice
    date = bd.Column(bd.Date, nullable=False, default=datetime.utcnow)


# --- Demandes de programmes personnalisés ---
class ProgramRequest(bd.Model):
    id = bd.Column(bd.Integer, primary_key=True, autoincrement=True)
    user_id = bd.Column(bd.Integer, bd.ForeignKey("user.id"), nullable=False)
    objectif = bd.Column(bd.Text, nullable=False)
    status = bd.Column(bd.String(50), default="En attente")
    response_link = bd.Column(bd.String(255), nullable=True)
    response_date = bd.Column(bd.DateTime, nullable=True)
    created_at = bd.Column(bd.DateTime, default=datetime.utcnow)

    user = bd.relationship("User", backref="requests", lazy=True)


def generate_confirmation_token(email):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email, salt="confirm-email")


@app.route("/")
def home():
    return render_template("home.html")


@app.route("/ia")
def ia():
    return render_template("ia.html")


from flask import abort


def admin_required(func):
    from functools import wraps

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return func(*args, **kwargs)

    return decorated_view


@app.route("/admin_dashboard")
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    demandes = ProgramRequest.query.order_by(ProgramRequest.created_at.desc()).all()
    return render_template("admin_dashboard.html", users=users, demandes=demandes)


@app.route("/admin/ban_user/<int:user_id>")
@login_required
@admin_required
def ban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = True
    bd.session.commit()
    flash(f"L'utilisateur {user.nom} a été banni 🚫", "warning")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/unban_user/<int:user_id>")
@login_required
@admin_required
def unban_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_banned = False
    bd.session.commit()
    flash(f"L'utilisateur {user.nom} a été réactivé ✅", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    bd.session.delete(user)
    bd.session.commit()
    flash(f"L'utilisateur {user.nom} a été supprimé 🗑️", "danger")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/validate_request/<int:request_id>", methods=["POST"])
@login_required
@admin_required
def validate_request(request_id):
    program_link = request.form.get("program_link")
    demande = ProgramRequest.query.get_or_404(request_id)
    demande.status = "Validé"
    demande.response_link = program_link
    demande.response_date = datetime.utcnow()
    bd.session.commit()
    flash("Programme envoyé avec succès ✅", "success")
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🎯 Ton programme personnalisé FitSafe est prêt !"
    msg["From"] = os.getenv("MAIL_USERNAME")
    msg["To"] = demande.user.email

    text_part = f"""
    Bonjour {demande.user.nom},

    Ton programme personnalisé FitSafe est prêt !

    Tu peux le consulter dès maintenant via le lien suivant :
    {program_link} ou sur ton espace dans la rubrique Humain.

    Continue de t’entraîner avec régularité et prudence 💪

    L’équipe FitSafe
    """

    html_part = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #222;">
        <p>Bonjour <strong>{demande.user.nom}</strong>,</p>
        <p>Ton <strong>programme personnalisé FitSafe</strong> est maintenant disponible 🎯</p>
        <p style="text-align:center;">
        <a href="{program_link}" 
            style="background-color:#007BFF; color:white; padding:12px 20px; text-decoration:none; border-radius:6px;">
            Voir mon programme
        </a>
        </p>
        <p>Continue de t’entraîner avec rigueur et prudence 💪</p>
        <p style="color:#666;">– L’équipe FitSafe</p>
    </body>
    </html>
    """

    msg.attach(MIMEText(text_part, "plain"))
    msg.attach(MIMEText(html_part, "html"))

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/user/<int:user_id>")
@login_required
@admin_required
def admin_user_detail(user_id):
    user = User.query.get_or_404(user_id)
    sessions = Session.query.filter_by(user_id=user.id).all()
    workouts = Workout.query.filter_by(user_id=user.id).all()

    # ⚙️ Filtrer les workouts valides (durée non nulle)
    valid_workouts = [w for w in workouts if w.duration and w.duration > 0]

    # --- Calcul des calories
    total_calories = 0
    for w in valid_workouts:
        try:
            total_calories += calories_brulees(w.type, w.duration, user.poids or 70)
        except Exception:
            pass

    # --- IA et fitness
    user_data = {
        "age": user.age or 25,
        "poids": user.poids or 70,
        "taille": user.taille or 175,
        "niveau": {"Débutant": 1, "Intermédiaire": 2, "Avancé": 3}.get(user.niveau, 2),
    }

    try:
        weather = get_weather("Paris")
    except Exception:
        weather = None

    ai_model = FitSafeAIModel(user_data, [w.__dict__ for w in valid_workouts], weather)
    risk_score = ai_model.compute_risk_score()
    fitness_score = calculate_fitness_score(user, valid_workouts, risk_score)

    return render_template(
        "admin_user_detail.html",
        user=user,
        sessions=sessions,
        workouts=valid_workouts,
        total_calories=round(total_calories, 2),
        fitness_score=fitness_score,
        risk_score=risk_score,
    )


@app.route("/humain", methods=["GET", "POST"])
@login_required
def humain():
    if request.method == "POST":
        objectif = request.form.get("objectif")
        if not objectif or objectif.strip() == "":
            flash("Merci de préciser ton objectif.", "error")
            return redirect(url_for("humain"))

        demande = ProgramRequest(user_id=current_user.id, objectif=objectif)
        bd.session.add(demande)
        bd.session.commit()
        flash("Ta demande a été envoyée avec succès 💪", "success")
        return redirect(url_for("humain"))

    demandes = (
        ProgramRequest.query.filter_by(user_id=current_user.id)
        .order_by(ProgramRequest.created_at.desc())
        .all()
    )
    return render_template("humain.html", demandes=demandes)


# route conseils
@app.route("/advis")
def advis():
    return render_template("advis.html")


@app.route("/privacy", methods=["GET"])
def privacy():
    return render_template("privacy.html", datetime=datetime)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        nom = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validation du mail ici a ajouter ****
        # *************###

        # Validation mot de passe
        if password != confirm_password:
            flash("Le mot de passe ne correspond pas.")
            return redirect(url_for("register"))
        if User.query.filter_by(email=email).first():
            flash("Un compte existe déja avec cet email.")
            return redirect(url_for("register"))
        hashed_pw = bycrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(nom=nom, email=email, password=hashed_pw)
        bd.session.add(new_user)
        bd.session.commit()

        # Ajouter la confirmation par mail token
        token = generate_confirmation_token(email)
        confirm_url = url_for("confirm_email", token=token, _external=True)

        message = MIMEMultipart("alternative")
        message["Subject"] = "Confirme ton compte FitSafe ✅"
        message["From"] = os.getenv("MAIL_USERNAME")
        message["To"] = email

        text_part = f"""
        Bonjour {nom},

        Bienvenue sur FitSafe ! 💪

        Merci d’avoir créé ton compte. Pour activer ton profil, clique sur le lien ci-dessous :
        {confirm_url}

        Ce lien est valable pendant 1 heure.

        L’équipe FitSafe
        """

        html_part = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #222;">
            <p>Bonjour <strong>{nom}</strong>,</p>
            <p>Bienvenue sur <strong>FitSafe</strong> 💪</p>
            <p>Merci d’avoir créé ton compte. Pour activer ton profil, clique sur le bouton ci-dessous :</p>
            <p style="text-align: center;">
            <a href="{confirm_url}" 
                style="background-color: #007BFF; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px;">
                Confirmer mon compte
            </a>
            </p>
            <p>Ce lien est valable pendant <strong>1 heure</strong>.</p>
            <p style="color: #666;">– L’équipe FitSafe</p>
        </body>
        </html>
        """

        message.attach(MIMEText(text_part, "plain"))
        message.attach(MIMEText(html_part, "html"))

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.set_debuglevel(1)  # 👈 affiche les échanges SMTP
                smtp.ehlo()
                smtp.starttls()
                smtp.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                smtp.send_message(message)
                print("✅ Email envoyé avec succès !")
        except Exception as e:
            print("❌ Erreur SMTP :", e)
            flash(f"Erreur lors de l'envoi du mail : {e}", "error")

        flash(
            "Ton compte a bien été créé ! Un email de confirmation t’a été envoyé. Clique sur le lien pour activer ton compte.",
            "success",
        )
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)

    if not email:
        flash("Lien invalide ou expiré.", "error")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Utilisateur introuvable.", "error")
        return redirect(url_for("login"))

    if user.confirmed:
        flash("Ton compte est déjà confirmé.", "info")
    else:
        user.confirmed = True
        bd.session.commit()
        flash("Ton compte a été confirmé avec succès.", "success")

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and bycrypt.check_password_hash(user.password, password):
            if not user.confirmed:
                flash(
                    "Vous devez confirmez votre adress email avant de vous connecter.",
                    "warning",
                )
                return redirect(url_for("login"))
            if user.is_banned:
                flash(
                    "Vous etes banie par l'admin, veuillez laisser un message dans la rubrique Contact",
                    "warning",
                )
                return redirect(url_for("login"))
            login_user(user)
            if user.is_admin:
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        else:
            flash("Email ou mot de passe incorrect", "error")
    return render_template("login.html")


def confirm_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, salt="confirm-email", max_age=expiration)
    except:
        return None
    return email


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/add_workout", methods=["POST"])
@login_required
def add_workout():
    session_id = request.form.get("session_id", type=int)
    workout_type = request.form.get("type")
    exercise = request.form.get("exercise")
    series = request.form.get("series", type=int)
    reps = request.form.get("reps", type=int)
    duration = request.form.get("duration", type=int)
    date_str = request.form.get("date")

    if not (workout_type and exercise and duration):
        flash("Merci de remplir tous les champs obligatoires.", "error")
        return redirect(url_for("dashboard"))

    date = (
        datetime.strptime(date_str, "%Y-%m-%d").date()
        if date_str
        else datetime.utcnow().date()
    )

    new_workout = Workout(
        user_id=current_user.id,
        session_id=session_id,
        type=workout_type,
        exercise=exercise,
        series=series,
        reps=reps,
        duration=duration,
        date=date,
    )

    bd.session.add(new_workout)
    bd.session.commit()
    flash(f"Exercice '{exercise}' ajouté à ta séance ✅", "success")
    return redirect(url_for("dashboard"))


@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    sessions = Session.query.filter_by(user_id=current_user.id).all()

    selected_session_id = request.args.get("session_id", type=int)
    if selected_session_id:
        workouts = Workout.query.filter_by(
            user_id=current_user.id, session_id=selected_session_id
        ).all()
        current_session = Session.query.get(selected_session_id)
    else:
        workouts = Workout.query.filter_by(user_id=current_user.id).all()
        current_session = None

    user_poids = current_user.poids

    if not user_poids:
        email = current_user.email
        corps_html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #222;">
            <p>Bonjour <strong>{current_user.nom}</strong>,</p>
            <p>Bienvenue sur <strong>FitSafe</strong> 💪</p>
            <p>Pour que ton tableau de bord fonctionne correctement, merci de renseigner ton <strong>poids</strong>, ta <strong>taille</strong> et ton <strong>âge</strong> dans la rubrique <em>Profil</em>.</p>
            <p style="text-align: center;">
            <a href="{url_for('profil', _external=True)}" 
                style="background-color: #28A745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 6px;">
                Mettre à jour mon profil
            </a>
            </p>
            <p style="color: #666;">Merci pour ta confiance 💪<br>L’équipe FitSafe</p>
        </body>
        </html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "⚠️ Complète ton profil FitSafe"
        msg["From"] = os.getenv("MAIL_USERNAME")
        msg["To"] = email

        msg.attach(MIMEText(corps_html, "html"))

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as smtp:
                smtp.starttls()
                smtp.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                smtp.send_message(msg)
        except Exception as e:
            print("Erreur envoi email :", e)

        flash(
            "⚠️ Merci de compléter ton profil pour activer le calcul des calories.",
            "warning",
        )
        return redirect(url_for("profil"))

    # --- Calcul des calories pour chaque exercice ---
    total_calories = 0
    calories_par_exercice = {}

    for w in workouts:
        kcal = calories_brulees(w.type, w.duration, user_poids)
        calories_par_exercice[w.id] = kcal
        total_calories += kcal

    # --- Données IA et graphique ---
    user_data = {
        "age": current_user.age or 25,
        "poids": user_poids,
        "taille": current_user.taille or 175,
        "niveau": {"Débutant": 1, "Intermédiaire": 2, "Avancé": 3}.get(
            current_user.niveau, 2
        ),
    }

    try:
        weather = get_weather("Paris")
    except Exception:
        weather = None

    ai_model = FitSafeAIModel(user_data, [w.__dict__ for w in workouts], weather)
    risk_score = ai_model.compute_risk_score()
    risk_message = ai_model.suggest_program()
    focus_message = ai_model.predict_next_focus()

    data_map = defaultdict(int)
    for w in workouts:
        data_map[w.type] += w.duration
    chart_labels = list(data_map.keys())
    chart_data = list(data_map.values())

    if current_user.latitude and current_user.longitude:
        weather = get_weather(lat=current_user.latitude, lon=current_user.longitude)
    else:
        weather = get_weather("Paris")  # fallback

    risk_score = ai_model.compute_risk_score()
    risk_message = ai_model.suggest_program()
    focus_message = ai_model.predict_next_focus()
    fitness_score = calculate_fitness_score(current_user, workouts, risk_score)

    return render_template(
        "dashboard.html",
        user=current_user,
        sessions=sessions,
        selected_session=current_session,
        workouts=workouts,
        risk_score=risk_score,
        risk_message=risk_message,
        focus_message=focus_message,
        chart_labels=chart_labels,
        chart_data=chart_data,
        weather=weather,
        fitness_score=fitness_score,
        total_calories=round(total_calories, 2),
        calories_par_exercice=calories_par_exercice,
        datetime=datetime,
    )


def calculate_fitness_score(user, workouts, risk_score):
    """
    Calcule un score de forme entre 0 et 100 basé sur :
    - la charge d'entraînement (durée moyenne des séances)
    - la régularité (nombre total de séances)
    - le risque de blessure (inversé)
    """
    # Regroupe les séances par ID
    sessions = Session.query.filter_by(user_id=user.id).all()

    if not workouts:
        return 0  # pas d'entraînement => pas de score

    # Durée totale de tous les exercices
    total_duration = sum(w.duration for w in workouts)
    total_sessions = len(sessions)
    avg_duration = total_duration / max(total_sessions, 1)  # durée moyenne par séance

    # Facteurs pondérés
    training_load = min(avg_duration / 60 * 100, 100)  # 1h = 100%
    regularity = min(total_sessions / 5 * 100, 100)  # 5 séances/semaine = 100%
    risk_factor = 100 - (risk_score or 50)  # on inverse le risque

    # Calcul final pondéré
    fitness_score = (
        0.4 * training_load
        + 0.25 * regularity
        + 0.25 * risk_factor
        + 0.1 * 90  # récupération simulée moyenne à 90%
    )

    return round(fitness_score, 1)


@app.route("/delete_workout/<int:id>", methods=["POST"])
@login_required
def delete_workout(id):
    workout = Workout.query.get_or_404(id)

    # Sécurité : vérifier que le workout appartient bien à l'utilisateur connecté
    if workout.user_id != current_user.id:
        flash("Action non autorisée.", "error")
        return redirect(url_for("dashboard"))

    bd.session.delete(workout)
    bd.session.commit()
    flash("L'activité a bien été supprimée", "success")
    return redirect(url_for("dashboard"))


@app.route("/add_session", methods=["POST"])
@login_required
def add_session():
    name = request.form.get("name")
    if not name:
        flash("Le nom de la séance est obligatoire.", "error")
        return redirect(url_for("dashboard"))

    new_session = Session(name=name, user_id=current_user.id)
    bd.session.add(new_session)
    bd.session.commit()
    flash(f"Séance '{name}' ajoutée ✅", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_session/<int:id>", methods=["POST"])
def delete_session(id):
    session = Session.query.get_or_404(id)
    if session.user_id != current_user.id:
        flash("Action non autorisée.", "error")
        return redirect(url_for("dashboard"))
    bd.session.delete(session)
    bd.session.commit()
    flash("La séance a bien été supprimée", "success")
    return redirect(url_for("dashboard"))


@app.route("/profil")
@login_required
def profil():
    workouts = (
        Workout.query.filter_by(user_id=current_user.id)
        .order_by(Workout.date.desc())
        .all()
    )
    sessions = Session.query.filter_by(user_id=current_user.id).all()

    total_sessions = len(sessions)
    avg_duration = (
        round(sum(w.duration for w in workouts) / total_sessions, 1)
        if total_sessions > 0
        else 0
    )

    # Récupérer le risque de blessure depuis ton modèle IA (comme sur le dashboard)
    user_data = {
        "age": current_user.age or 25,
        "poids": current_user.poids or 70,
        "taille": current_user.taille or 175,
        "niveau": {"Débutant": 1, "Intermédiaire": 2, "Avancé": 3}.get(
            current_user.niveau, 2
        ),
    }

    try:
        # On prend la localisation utilisateur si elle existe
        if current_user.latitude and current_user.longitude:
            weather = get_weather(lat=current_user.latitude, lon=current_user.longitude)
        else:
            weather = get_weather("Paris")
    except Exception:
        weather = None

    # Calcul du score IA comme sur le dashboard
    ai_model = FitSafeAIModel(user_data, [w.__dict__ for w in workouts], weather)
    risk_score = ai_model.compute_risk_score()

    # 👉 On calcule le même fitness_score qu’au dashboard
    fitness_score = calculate_fitness_score(current_user, workouts, risk_score)

    return render_template(
        "profil.html",
        user=current_user,
        workouts=workouts,
        total_sessions=total_sessions,
        avg_duration=avg_duration,
        risk_score=risk_score,
        fitness_score=fitness_score,
    )


@app.route("/change_password", methods=["POST"])
@login_required
def change_password():
    old_password = request.form["old_password"]
    new_password = request.form["new_password"]
    confirm_password = request.form["confirm_password"]

    if not bycrypt.check_password_hash(current_user.password, old_password):
        flash("Mot de passs incorrect", "error")
        return redirect(url_for("profil"))
    if new_password != confirm_password:
        flash("Les nouveaux mots de passe ne correspondent pas ⚠️", "error")
        return redirect(url_for("login"))

    hashed_pw = bycrypt.generate_password_hash(new_password).decode("utf-8")
    current_user.password = hashed_pw
    bd.session.commit()

    flash("Mot de passe changer avec succées", "success")
    return redirect(url_for("profil"))


@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    try:
        current_user.nom = request.form.get("nom")
        current_user.age = request.form.get("age", type=int)
        current_user.taille = request.form.get("taille", type=float)
        current_user.poids = request.form.get("poids", type=float)
        current_user.niveau = request.form.get("niveau")

        bd.session.commit()
        flash("Profil mis à jour avec succès ✅", "success")
    except Exception as e:
        bd.session.rollback()
        flash(f"Erreur lors de la mise à jour : {e}", "error")

    return redirect(url_for("profil"))


# ---- route principale ----
@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = ContactForm()

    if form.validate_on_submit():
        nom = form.nom.data
        email = form.email.data
        sujet = form.sujet.data
        message = form.message.data

        # --- Construction de l'email ---
        msg = MIMEMultipart("alternative")
        msg["To"] = os.getenv("MAIL_USERNAME")
        msg["From"] = email
        msg["Subject"] = f"[FitSafe AI] Message de {nom}"

        text_part = f"""
        Nouveau message reçu depuis le formulaire de contact FitSafe AI :

        Nom : {nom}
        Email : {email}
        Sujet : {sujet}

        Message :
        {message}
        """

        html_part = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #222;">
            <h2>📩 Nouveau message reçu via FitSafe AI</h2>
            <p><strong>Nom :</strong> {nom}<br>
            <strong>Email :</strong> {email}<br>
            <strong>Sujet :</strong> {sujet}</p>
            <hr>
            <p style="white-space: pre-line;">{message}</p>
            <hr>
            <p style="color: #666;">– Notification automatique FitSafe</p>
        </body>
        </html>
        """

        msg.attach(MIMEText(text_part, "plain"))
        msg.attach(MIMEText(html_part, "html"))

        try:
            # Connexion sécurisée à Gmail SMTP
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(os.getenv("MAIL_USERNAME"), os.getenv("MAIL_PASSWORD"))
                server.send_message(msg)

            flash("✅ Ton message a été envoyé avec succès !", "success")
            return redirect(url_for("contact"))

        except Exception as e:
            print("Erreur d'envoi :", e)
            flash("❌ Une erreur est survenue lors de l'envoi du message.", "error")

    elif request.method == "POST":
        flash("⚠️ Merci de vérifier les champs du formulaire.", "error")

    return render_template("contact.html", form=form)


@app.route("/update_location", methods=["POST"])
@login_required
def update_location():
    data = request.get_json()
    lat = data.get("lat")
    lon = data.get("lon")

    if lat and lon:
        current_user.latitude = lat
        current_user.longitude = lon
        bd.session.commit()
        return {"status": "success"}, 200
    else:
        return {"status": "error", "message": "Coordonnées manquantes"}, 400


@app.route("/humain/delete_request/<int:request_id>", methods=["POST"])
@login_required
def delete_request(request_id):
    demande = ProgramRequest.query.get_or_404(request_id)

    # Sécurité : l'utilisateur ne peut supprimer que ses propres demandes
    if demande.user_id != current_user.id:
        flash("Action non autorisée.", "error")
        return redirect(url_for("humain"))

    bd.session.delete(demande)
    bd.session.commit()
    flash("Ta demande a bien été supprimée 🗑️", "success")
    return redirect(url_for("humain"))


# ---- CSRF pour tous les templates ----
@app.context_processor
def inject_csrf_token():
    from flask_wtf.csrf import generate_csrf

    return dict(csrf_token=generate_csrf)


if __name__ == "__main__":
    app.run(debug=True)
