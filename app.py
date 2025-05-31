# app.py - Main application file
import os
import json
import threading
import pytz
import re
import secrets
from datetime import datetime
from io import BytesIO
from typing import Dict, List, Optional, Union, Tuple
from functools import wraps
from hmac import compare_digest
from dotenv import load_dotenv
from secrets import token_hex

# Load environment variables before creating the Flask app
load_dotenv()

# Third-party imports
from flask import (
    Flask, render_template, request, flash, 
    redirect, url_for, session, Response, jsonify,
    get_flashed_messages
)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, CSRFError, generate_csrf
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import validates
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import text
from wtforms import (
    StringField, DateField, SelectField, 
    EmailField, TelField, PasswordField, 
    SubmitField, HiddenField
)
from wtforms.validators import (
    DataRequired, Email, Length, 
    Regexp, ValidationError
)
import pandas as pd
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import logging
from logging.handlers import RotatingFileHandler

# Local imports
from config import Config

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Custom JSON Encoder for datetime objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%d.%m.%Y %H:%M")
        return super().default(obj)

app.json_encoder = CustomJSONEncoder

# Initialize extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure logging
def setup_logging():
    """Configure application logging"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    file_handler = RotatingFileHandler(
        'logs/application.log',
        maxBytes=10240,
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

setup_logging()

# Generate a nonce
def generate_csp_nonce():
    return secrets.token_hex(16)

CSP_NONCE = secrets.token_hex(16)

# Security configuration
CSP = {
    'default-src': ["'self'"],
    'script-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',
        'https://cdnjs.cloudflare.com',
        "'unsafe-eval'",
        f"'nonce-{CSP_NONCE}'"
    ],
    'style-src': [
        "'self'",
        'https://stackpath.bootstrapcdn.com',
        'https://fonts.googleapis.com',
        'https://cdn.jsdelivr.net'
    ],
    'img-src': ["'self'", 'data:', 'blob:'],
    'form-action': ["'self'"],
    'frame-ancestors': "'none'",
    'object-src': "'none'",
    'base-uri': ["'self'"]
}

if os.environ.get("RENDER"):
    Talisman(
        app,
        content_security_policy=CSP,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        strict_transport_security_preload=True
    )
else:
    Talisman(
        app,
        content_security_policy=CSP,
        force_https=False,
        strict_transport_security=False
    )

# Database Models
class Registration(db.Model):
    """Database model for registration entries"""
    id = db.Column(db.Integer, primary_key=True)
    persons = db.Column(db.Text, nullable=False, default='[]')
    contact_firstname = db.Column(db.String(50), nullable=False)
    contact_lastname = db.Column(db.String(50), nullable=False)
    contact_birthdate = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    email = db.Column(db.String(100), nullable=False, index=True)
    cake_donation = db.Column(db.String(100), nullable=False, default='')
    help_organisation = db.Column(db.String(100), nullable=False, default='')
    confirmed = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(
        db.DateTime, 
        default=lambda: datetime.now(pytz.timezone("Europe/Berlin")),
        index=True
    )

    @validates('email')
    def validate_email(self, key, address):
        """Validate email address format"""
        if not re.match(r"[^@]+@[^@]+\.[^@]+", address):
            raise ValueError("Invalid email address")
        return address.lower()

    def to_dict(self) -> Dict:
        """Convert registration to dictionary"""
        return {
            'id': self.id,
            'persons': json.loads(self.persons),
            'contact_firstname': self.contact_firstname,
            'contact_lastname': self.contact_lastname,
            'contact_birthdate': self.contact_birthdate,
            'phone_number': self.phone_number,
            'email': self.email,
            'cake_donation': self.cake_donation,
            'help_organisation': self.help_organisation,
            'confirmed': self.confirmed,
            'created_at': self.created_at.strftime("%d.%m.%Y %H:%M")
        }

class RegistrationForm(FlaskForm):
    """Form for registration data validation"""
    contact_firstname = StringField(
        "Vorname Kontaktperson",
        validators=[
            DataRequired(message="Vorname ist erforderlich"),
            Length(min=2, max=50, message="Vorname muss zwischen 2 und 50 Zeichen lang sein"),
            Regexp(
                r'^[A-Za-zÄÖÜäöüß\s-]+$',
                message="Vorname darf nur Buchstaben, Leerzeichen und Bindestriche enthalten"
            )
        ]
    )
    contact_lastname = StringField(
        "Nachname Kontaktperson",
        validators=[
            DataRequired(message="Nachname ist erforderlich"),
            Length(min=2, max=50, message="Nachname muss zwischen 2 und 50 Zeichen lang sein"),
            Regexp(
                r'^[A-Za-zÄÖÜäöüß\s-]+$',
                message="Nachname darf nur Buchstaben, Leerzeichen und Bindestriche enthalten"
            )
        ]
    )
    phone_number = TelField(
        "Telefonnummer",
        validators=[
            DataRequired(message="Telefonnummer ist erforderlich"),
            Length(min=5, max=15, message="Telefonnummer muss zwischen 5 und 15 Zeichen lang sein"),
            Regexp(
                r'^\+?[0-9\s-]+$',
                message="Ungültiges Telefonnummerformat"
            )
        ]
    )
    email = EmailField(
        "E-Mail",
        validators=[
            DataRequired(message="E-Mail ist erforderlich"),
            Email(message="Ungültige E-Mail-Adresse"),
            Length(max=100, message="E-Mail darf maximal 100 Zeichen lang sein")
        ]
    )
    cake_donation = SelectField(
        "Kuchenspende",
        choices=[
            ('', 'Option auswählen'),
            ('Wir spenden einen Rührkuchen für den Freitag.', 'Wir spenden einen Rührkuchen für den Freitag.'),
            ('Wir spenden einen Kuchen für den Sonntag.', 'Wir spenden einen Kuchen für den Sonntag.')
        ],
        validators=[
            DataRequired(message="Kuchenspende-Option ist erforderlich")
        ]
    )
    
    help_organisation = SelectField(
        "Auf-/Abbau",
        choices=[
            ('', 'Option auswählen'),
            ('Wir helfen beim Aufbau am Donnerstag, 17. Juli ab 18:00 Uhr.', 'Wir helfen beim Aufbau am Donnerstag, 17. Juli ab 18:00 Uhr.'),
            ('Wir helfen beim Aufbau am Sonntag, 20. Juli ab 13:00 Uhr.', 'Wir helfen beim Aufbau am Sonntag, 20. Juli ab 13:00 Uhr.')
        ],
        validators=[
            DataRequired(message="Auf-/Abbau-Option ist erforderlich")
        ]
    )
    
class DeleteForm(FlaskForm):
    """Form for CSRF protection on delete operations"""
    submit = SubmitField('Löschen')

# Utility Functions
def admin_required(f):
    """Decorator to require admin login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("admin_logged_in"):
            flash("Bitte melden Sie sich als Administrator an.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

def safe_commit() -> bool:
    """Safely commit database changes"""
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        return False

def validate_child_age(birth_date_str):
    """Validiere dass Kinder zwischen 6-11 Jahre alt sind (1.-5. Klasse)"""
    age = calculate_age(birth_date_str)
    if age and (age < 6 or age > 11):
        return False, f"Kind ist {age} Jahre alt. Zeltlager ist für 1.-5. Klasse (6-11 Jahre)."
    return True, None

def validate_registration_data(data: Dict) -> Tuple[bool, Optional[str]]:
    """Validate registration request data"""
    if not isinstance(data, dict):
        return False, "Invalid request format"
    
    required_fields = ["contact_firstname", "contact_lastname", "contact_birthdate", "phone_number", "email", "cake_donation", "help_organisation"]
    missing_fields = [field for field in required_fields if not data.get(field)]
    if missing_fields:
        return False, f"Missing required fields: {', '.join(missing_fields)}"
    
    persons_data = data.get("persons", [])
    if not persons_data:
        return False, "Mindestens ein Kind muss hinzugefügt werden."

    for i, person in enumerate(persons_data, 1):
        if 'birthdate' in person:
            is_valid_age, age_error = validate_child_age(person['birthdate'])
            if not is_valid_age:
                return False, f"Kind {i}: {age_error}"

    return True, None

def format_persons_details(persons):
    """Format the list of persons with their details"""
    return "\n".join([
        f"{person['person_firstname']} {person['person_lastname']} (Geb.: {person['birthdate']})"
        for person in persons
    ])

def send_confirmation_email(app, entry_id):
    """Send confirmation email to registrant"""
    with app.app_context():
        try:
            entry = Registration.query.get(entry_id)
            if not entry:
                app.logger.error(f"Registration entry {entry_id} not found")
                return

            msg = MIMEMultipart()
            msg["From"] = app.config['SMTP_USER']
            msg["To"] = entry.email
            msg["Subject"] = "Bestätigung Ihrer Anmeldung zum Zeltlager"

            # Load email template
            template_path = os.path.join(app.root_path, 'templates', 'emails', 'confirmation.txt')
            try:
                with open(template_path, 'r', encoding='utf-8') as f:
                    template = f.read()
                
                # Format template with registration data
                email_body = template.format(
                    **entry.to_dict(), 
                    persons_details=format_persons_details(json.loads(entry.persons))
                )
            except FileNotFoundError:
                # Fallback email template
                email_body = f"""
Liebe/r {entry.contact_firstname} {entry.contact_lastname},

vielen Dank für Ihre Anmeldung zum Zeltlager 2025!

Ihre Anmeldedaten:
- Kontaktperson: {entry.contact_firstname} {entry.contact_lastname}
- E-Mail: {entry.email}
- Telefon: {entry.phone_number}
- Kuchenspende: {entry.cake_donation}
- Auf-/Abbau: {entry.help_organisation}

Angemeldete Kinder:
{format_persons_details(json.loads(entry.persons))}

Mit freundlichen Grüßen
Ihr Zeltlager-Team
                """
            
            msg.attach(MIMEText(email_body, "plain"))

            with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
                server.starttls()
                server.login(app.config['SMTP_USER'], app.config['SMTP_PASS'])
                server.send_message(msg)

            app.logger.info(f"Confirmation email sent to {entry.email}")

        except Exception as e:
            app.logger.error(f"Failed to send confirmation email for entry {entry_id}: {str(e)}")

def sanitize_input(value):
    """Sanitize user input to prevent XSS and other injection attacks"""
    if not isinstance(value, str):
        return value
        
    # Remove any HTML tags
    value = re.sub(r'<[^>]*>', '', value)
    
    # Convert special characters to HTML entities
    value = value.replace('&', '&amp;')\
                 .replace('<', '&lt;')\
                 .replace('>', '&gt;')\
                 .replace('"', '&quot;')\
                 .replace("'", '&#x27;')
                 
    # Remove any null bytes
    value = value.replace('\x00', '')
    
    # Normalize whitespace
    value = ' '.join(value.split())
    
    return value

def calculate_age(birth_date_str, reference_date=None):
    """Calculate age on a specific date based on birth date"""
    try:
        if reference_date is None:
            reference_date = datetime.now()
            
        birth_date = datetime.strptime(birth_date_str, '%Y-%m-%d')
        age = reference_date.year - birth_date.year
        
        # Adjust age if birthday hasn't occurred yet in the reference year
        if (reference_date.month, reference_date.day) < (birth_date.month, birth_date.day):
            age -= 1
        return age
    except (ValueError, TypeError):
        return None

# Routes
@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    """Handle registration form"""
    if request.method == "POST":
        # Prüfen ob es ein AJAX-Request ist (JSON-Daten)
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            try:
                data = request.get_json(force=True)
                app.logger.info("Received registration data")

                # Validate data (OHNE WTForms, da wir JSON bekommen)
                is_valid, error_message = validate_registration_data(data)
                if not is_valid:
                    return jsonify({
                        "success": False,
                        "error": error_message
                    }), 400

                # Sanitize and store data
                sanitized_data = {
                    "persons": data["persons"],
                    "contact_firstname": sanitize_input(data["contact_firstname"]),
                    "contact_lastname": sanitize_input(data["contact_lastname"]),
                    "contact_birthdate": sanitize_input(data["contact_birthdate"]),
                    "phone_number": sanitize_input(data["phone_number"]),
                    "email": sanitize_input(data["email"].lower()),
                    "cake_donation": sanitize_input(data["cake_donation"]),
                    "help_organisation": sanitize_input(data["help_organisation"])
                }

                # Store in session
                session["registration_data"] = sanitized_data
                app.logger.info(f"Registration data stored in session for {sanitized_data['email']}")

                # Convert persons list to JSON string before creating database entry
                sanitized_data['persons'] = json.dumps(sanitized_data['persons'])

                # Create database entry
                registration = Registration(**sanitized_data)
                db.session.add(registration)
                if not safe_commit():
                    return jsonify({
                        "success": False,
                        "error": "Datenbankfehler. Bitte versuchen Sie es erneut."
                    }), 500

                return jsonify({
                    "success": True,
                    "redirect": url_for("confirmation")
                })

            except Exception as e:
                app.logger.error(f"Registration error: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut."
                }), 500
        
        else:
            # Fallback für normale Form-Submissions (nicht AJAX)
            form = RegistrationForm()
            if not form.validate():
                for field, errors in form.errors.items():
                    for error in errors:
                        flash(f"{field}: {error}", "danger")
                return render_template("form.html", form=form)

    # GET Request - zeige Formular
    return render_template("form.html", form=RegistrationForm())

@app.route("/confirmation")
def confirmation():
    """Display confirmation page"""
    data = session.get("registration_data")
    if not data:
        flash("Keine Anmeldedaten gefunden. Bitte füllen Sie das Formular erneut aus.", "error")
        return redirect(url_for("register"))
    
    # Ensure persons data is a list
    if isinstance(data.get('persons'), str):
        data['persons'] = json.loads(data['persons'])
    
    return render_template(
        "confirmation.html", 
        data=data,
        payment_info={
            'paypal_link': app.config.get('PAYPAL_LINK', ''),
            'bank_name': app.config.get('BANK_NAME', ''),
            'recipient': app.config.get('RECIPIENT_NAME', ''),
            'iban': app.config.get('BANK_IBAN', ''),
            'bic': app.config.get('BANK_BIC', '')
        }
    )

@app.route("/admin-login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def admin_login():
    """Handle admin login"""
    if request.method == "POST":
        password = request.form.get('password')
        expected_password = app.config['ADMIN_PASSWORD']
        
        if not password:
            flash("Bitte geben Sie ein Passwort ein.", "danger")
            app.logger.warning("Login attempt with no password")
        elif not expected_password:
            flash("Systemkonfigurationsfehler. Bitte kontaktieren Sie den Administrator.", "danger")
            app.logger.error("No admin password configured")
        else:
            is_match = compare_digest(password, expected_password)
            
            if is_match:
                session["admin_logged_in"] = True
                session.permanent = True
                app.logger.info("Admin login successful")
                return redirect(url_for("admin"))
            else:
                app.logger.warning("Failed admin login attempt")
                flash("Falsches Passwort. Bitte erneut versuchen.", "danger")
    
    flash_messages = [
        {"category": category, "text": message}
        for category, message in get_flashed_messages(with_categories=True)
    ]
    
    return render_template("admin_login.html", 
        flashMessages=flash_messages,
        csrf_token=generate_csrf(),
        csp_nonce=CSP_NONCE
    )

@app.route("/admin")
@admin_required
def admin():
    """Admin dashboard"""
    try:
        registrations = Registration.query\
            .order_by(Registration.created_at.desc())\
            .all()
        
        registrations_data = []
        timezone = pytz.timezone("Europe/Berlin")
        total_children = 0
        
        for reg in registrations:
            try:
                persons_data = json.loads(reg.persons)
                
                # Zähle alle angemeldeten Kinder
                total_children += len(persons_data)
                
                reg_dict = {
                    'id': reg.id,
                    'contact_firstname': reg.contact_firstname,
                    'contact_lastname': reg.contact_lastname,
                    'contact_birthdate': getattr(reg, 'contact_birthdate', None),
                    'phone_number': reg.phone_number,
                    'email': reg.email,
                    'cake_donation': reg.cake_donation,
                    'help_organisation': reg.help_organisation,
                    'confirmed': reg.confirmed,
                    'persons': persons_data,
                    'created_at': reg.created_at.astimezone(timezone).strftime("%d.%m.%Y %H:%M")
                }
                registrations_data.append(reg_dict)
                
            except Exception as person_error:
                app.logger.error(f"Error processing registration {reg.id}: {str(person_error)}")
                app.logger.error(f"Problematic persons data: {reg.persons}")

        stats = {
            'total_registrations': len(registrations),
            'confirmed_registrations': sum(1 for r in registrations if r.confirmed),
            'total_children': total_children
        }

        app.logger.info(f"Admin dashboard stats: {stats}")

        return render_template(
            "admin.html",
            registrations=registrations_data,
            stats=stats,
            csrf_token=generate_csrf(),
            csp_nonce=CSP_NONCE
        )
        
    except Exception as e:
        app.logger.error(f"Error accessing admin dashboard: {str(e)}")
        flash("Fehler beim Laden der Daten.", "danger")
        return redirect(url_for("admin_login"))

@app.route("/confirm-mail/<int:entry_id>", methods=["POST"])
@admin_required
def confirm_mail(entry_id: int):
    """Send confirmation email"""
    try:
        entry = db.session.get(Registration, entry_id)
        if not entry:
            flash("Eintrag nicht gefunden.", "danger")
            return redirect(url_for("admin"))

        if entry.confirmed:
            flash("Bestätigungsmail wurde bereits versendet.", "warning")
            return redirect(url_for("admin"))

        entry.confirmed = True
        if not safe_commit():
            flash("Fehler beim Speichern der Bestätigung.", "danger")
            return redirect(url_for("admin"))

        # Send email in background thread
        threading.Thread(
            target=send_confirmation_email,
            args=(app, entry_id),
            daemon=True
        ).start()

        flash("Bestätigungsmail wurde erfolgreich versandt.", "success")

    except Exception as e:
        app.logger.error(f"Error confirming registration {entry_id}: {str(e)}")
        flash("Fehler beim Senden der Bestätigungsmail.", "danger")

    return redirect(url_for("admin"))

@app.route("/delete-entry/<int:entry_id>", methods=["POST"])
@admin_required
def delete_entry(entry_id: int):
    """Delete single registration entry"""
    try:
        entry = db.session.get(Registration, entry_id)
        if not entry:
            flash("Der Eintrag konnte nicht gefunden werden.", "danger")
            return redirect(url_for("admin"))

        db.session.delete(entry)
        if not safe_commit():
            flash("Fehler beim Löschen des Eintrags.", "danger")
            return redirect(url_for("admin"))

        app.logger.info(f"Deleted registration entry {entry_id}")
        flash("Der ausgewählte Eintrag wurde erfolgreich gelöscht.", "success")

    except Exception as e:
        app.logger.error(f"Error deleting entry {entry_id}: {str(e)}")
        flash("Fehler beim Löschen des ausgewählten Eintrags.", "danger")

    return redirect(url_for("admin"))

@app.route("/delete-all-entries", methods=["POST"])
@admin_required
def delete_all_entries():
    """Delete all registration entries"""
    try:
        count = Registration.query.count()
        Registration.query.delete()
        if not safe_commit():
            flash("Beim Löschen aller Einträge ist ein Fehler aufgetreten.", "danger")
            return redirect(url_for("admin"))

        app.logger.info(f"Deleted all {count} registration entries")
        flash(f"Alle {count} Einträge wurden erfolgreich gelöscht.", "success")

    except Exception as e:
        app.logger.error(f"Error deleting all entries: {str(e)}")
        flash("Beim Löschen aller Einträge ist ein Fehler aufgetreten.", "danger")

    return redirect(url_for("admin"))

@app.route("/export-excel")
@admin_required
def export_excel():
    """Export registrations to Excel with separate sheets for participants and companions"""
    try:
        registrations = Registration.query\
            .order_by(Registration.created_at.desc())\
            .all()
        
        if not registrations:
            flash("Keine Daten zum Exportieren vorhanden.", "warning")
            return redirect(url_for("admin"))
        
        # Zwei separate Datensätze anlegen
        participants_data = []  # Für angemeldete Personen
        companions_data = []    # Für Begleitpersonen
        
        # Referenzdatum für Altersberechnung
        reference_date = datetime.now()
        date_str = reference_date.strftime("%d.%m.%Y")
        
        for reg in registrations:
            # Daten für Begleitperson/Kontaktperson
            companion_age = calculate_age(reg.contact_birthdate, reference_date) if reg.contact_birthdate else None
            age_group = "Erwachsener (ab 18)" if companion_age and companion_age >= 18 else "Kind/Jugendl. (bis 17)"
            
            companions_data.append({
                "Vorname": reg.contact_firstname,
                "Nachname": reg.contact_lastname,
                "Geburtsdatum": reg.contact_birthdate,
                f"Alter am {date_str}": companion_age if companion_age is not None else "Unbekannt",
                "Altersgruppe": age_group,
                "Telefon": reg.phone_number,
                "E-Mail": reg.email,
                "Kuchenspende": reg.cake_donation,
                "Auf-/Abbau": reg.help_organisation,
                "Anmeldung bestätigt": "Ja" if reg.confirmed else "Nein",
                "Anmeldezeitpunkt": reg.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y %H:%M")
            })
            
            # Daten für angemeldete Personen (Kinder)
            try:
                persons = json.loads(reg.persons)
                for person in persons:
                    person_age = calculate_age(person.get('birthdate'), reference_date)
                    age_group = "Erwachsener (ab 18)" if person_age and person_age >= 18 else "Kind/Jugendl. (bis 17)"
                    
                    participants_data.append({
                        "Vorname": person.get('person_firstname', ''),
                        "Nachname": person.get('person_lastname', ''),
                        "Geburtsdatum": person.get('birthdate', ''),
                        f"Alter am {date_str}": person_age if person_age is not None else "Unbekannt",
                        "Altersgruppe": age_group,
                        "Vereinsmitgliedschaft": person.get('club_membership', ''),
                        "Kontaktperson": f"{reg.contact_firstname} {reg.contact_lastname}",
                        "Anmeldung bestätigt": "Ja" if reg.confirmed else "Nein",
                        "Anmeldezeitpunkt": reg.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y %H:%M")
                    })
            except (json.JSONDecodeError, TypeError) as e:
                app.logger.error(f"Error parsing persons data for registration {reg.id}: {e}")

        # Statistiken berechnen
        total_adults = sum(1 for p in participants_data if p["Altersgruppe"] == "Erwachsener (ab 18)")
        total_adults += sum(1 for c in companions_data if c["Altersgruppe"] == "Erwachsener (ab 18)")
        
        total_children = sum(1 for p in participants_data if p["Altersgruppe"] == "Kind/Jugendl. (bis 17)")
        total_children += sum(1 for c in companions_data if c["Altersgruppe"] == "Kind/Jugendl. (bis 17)")
        
        # DataFrames erstellen
        participants_df = pd.DataFrame(participants_data) if participants_data else pd.DataFrame()
        companions_df = pd.DataFrame(companions_data) if companions_data else pd.DataFrame()
        
        # Statistik-DataFrame erstellen
        stats_data = [
            ["Gesamt Anmeldungen", len(companions_data)],
            ["Bestätigte Anmeldungen", sum(1 for c in companions_data if c["Anmeldung bestätigt"] == "Ja")],
            ["Anzahl angemeldete Kinder", len(participants_data)],
            ["Anzahl Erwachsene", total_adults],
            ["Anzahl Kinder/Jugendliche", total_children]
        ]
        stats_df = pd.DataFrame(stats_data, columns=["Statistik", "Anzahl"])

        # Excel-Datei erstellen
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Sheet für angemeldete Kinder
            participants_df.to_excel(writer, index=False, sheet_name='Angemeldete Kinder')
            participants_sheet = writer.sheets['Angemeldete Kinder']
            
            # Spaltenbreiten anpassen
            for idx, col in enumerate(participants_df.columns):
                max_length = max(
                    participants_df[col].astype(str).apply(len).max() if not participants_df.empty else 10,
                    len(col)
                ) + 2
                participants_sheet.column_dimensions[chr(65 + idx)].width = min(max_length, 30)
            
            # Sheet für Begleitpersonen
            companions_df.to_excel(writer, index=False, sheet_name='Kontaktpersonen')
            companions_sheet = writer.sheets['Kontaktpersonen']
            
            # Spaltenbreiten anpassen
            for idx, col in enumerate(companions_df.columns):
                max_length = max(
                    companions_df[col].astype(str).apply(len).max() if not companions_df.empty else 10,
                    len(col)
                ) + 2
                companions_sheet.column_dimensions[chr(65 + idx)].width = min(max_length, 30)
            
            # Statistik-Sheet
            stats_df.to_excel(writer, index=False, sheet_name='Statistik')
            stats_sheet = writer.sheets['Statistik']
            
            # Spaltenbreiten für Statistik anpassen
            for idx, col in enumerate(stats_df.columns):
                stats_sheet.column_dimensions[chr(65 + idx)].width = 25

        output.seek(0)
        
        # Dateiname mit Zeitstempel erstellen
        timestamp = datetime.now(pytz.timezone("Europe/Berlin"))\
            .strftime("%d-%m-%Y_%H-%M-%S")
        
        # Response mit Excel-Datei senden
        response = Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f"attachment; filename=Anmeldungen_Stand-{timestamp}.xlsx",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
        
        app.logger.info("Excel export generated successfully")
        return response

    except Exception as e:
        app.logger.error(f"Error generating Excel export: {str(e)}")
        flash("Fehler beim Erstellen der Excel-Datei.", "danger")
        return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    """Handle admin logout"""
    session.clear()
    flash("Erfolgreich ausgeloggt.", "success")
    return redirect(url_for("admin_login"))

@app.route("/datenschutz")
def privacy():
    """Display privacy policy"""
    return render_template("privacy.html")

# Error Handlers
@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    app.logger.error(f"404 Error: {request.url}")
    return render_template("error.html", 
        error_code=404,
        error_message="Seite nicht gefunden"
    ), 404

@app.errorhandler(500)
def internal_server_error(e):
    """Handle 500 errors"""
    app.logger.error(f"500 Error: {request.url}")
    return render_template("error.html",
        error_code=500,
        error_message="Interner Serverfehler"
    ), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Handle CSRF errors"""
    app.logger.error(f"CSRF Error: {request.url}")
    if request.is_json:
        return jsonify({
            "success": False,
            "error": "CSRF-Token ist ungültig oder fehlt. Bitte laden Sie die Seite neu."
        }), 400
    flash("CSRF-Token ist ungültig oder fehlt. Bitte versuchen Sie es erneut.", "danger")
    return redirect(url_for("register"))

@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors"""
    app.logger.warning(f"Rate limit exceeded: {request.url}")
    return jsonify({
        "success": False,
        "error": "Zu viele Anfragen. Bitte warten Sie einen Moment."
    }), 429

# Security Headers
@app.after_request
def set_security_headers(response):
    """Set security headers for all responses"""
    response.headers.update({
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'Referrer-Policy': 'no-referrer-when-downgrade',
        'X-XSS-Protection': '1; mode=block',
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
    })
    return response

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    
    if os.environ.get("RENDER"):
        from gunicorn.app.wsgiapp import run
        run()
    else:
        app.run(
            debug=False,
            host="127.0.0.1",
            port=port,
        )
