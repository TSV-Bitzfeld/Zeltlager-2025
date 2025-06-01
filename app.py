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
from email.mime.application import MIMEApplication

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
            ('Wir helfen beim Abbau am Sonntag, 20. Juli ab 13:00 Uhr.', 'Wir helfen beim Abbau am Sonntag, 20. Juli ab 13:00 Uhr.')
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
    """Validiere dass Kinder zwischen 6-12 Jahre alt sind (1.-5. Klasse)"""
    age = calculate_age(birth_date_str)
    if age and (age < 6 or age > 12):
        return False, f"Kind ist {age} Jahre alt. Zeltlager ist für 1.-5. Klasse (6-12 Jahre)."
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
            entry = db.session.get(Registration, entry_id)
            if not entry:
                app.logger.error(f"Registration entry {entry_id} not found")
                return False

            # ✅ KORREKTE E-Mail-Struktur: 'mixed' für Anhänge
            msg = MIMEMultipart('mixed')
            msg["From"] = app.config['SMTP_USER']
            msg["To"] = entry.email
            msg["Subject"] = "Ihre Anmeldung zum Zeltlager 2025"

            # Personen-Daten laden
            try:
                persons_data = json.loads(entry.persons)
            except (json.JSONDecodeError, TypeError):
                persons_data = []

            # E-Mail-Template erstellen
            email_body_text = create_confirmation_email_text(entry, persons_data)
            email_body_html = create_confirmation_email_html(entry, persons_data)

            # ✅ Erstelle eine 'alternative' Gruppe für Text + HTML
            body_container = MIMEMultipart('alternative')
            
            # Text- und HTML-Versionen zur alternativen Gruppe hinzufügen
            part1 = MIMEText(email_body_text, 'plain', 'utf-8')
            part2 = MIMEText(email_body_html, 'html', 'utf-8')
            
            body_container.attach(part1)
            body_container.attach(part2)
            
            # ✅ Die alternative Gruppe zur Haupt-Nachricht hinzufügen
            msg.attach(body_container)

            # ✅ PDF als Anhang hinzufügen
            pdf_path = os.path.join(app.static_folder, 'forms', 'gesundheitsbogen-und-einverstaendniserklaerung.pdf')
            
            if os.path.exists(pdf_path):
                with open(pdf_path, 'rb') as pdf_file:
                    pdf_attachment = MIMEApplication(pdf_file.read(), _subtype='pdf')
                    pdf_attachment.add_header(
                        'Content-Disposition', 
                        'attachment', 
                        filename='Gesundheitsbogen_Einverstaendniserklaerung_Zeltlager2025.pdf'
                    )
                    msg.attach(pdf_attachment)
                    app.logger.info("PDF attachment added successfully")
            else:
                app.logger.warning(f"PDF file not found at: {pdf_path}")

            # E-Mail versenden
            with smtplib.SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as server:
                server.starttls()
                server.login(app.config['SMTP_USER'], app.config['SMTP_PASS'])
                server.send_message(msg)

            app.logger.info(f"Confirmation email sent successfully to {entry.email}")
            return True

        except Exception as e:
            app.logger.error(f"Failed to send confirmation email for entry {entry_id}: {str(e)}")
            return False

def create_confirmation_email_html(entry, persons_data):
    """Create HTML version of confirmation email"""
    
    def format_date(date_string):
        """Convert YYYY-MM-DD to DD.MM.YYYY format"""
        if not date_string:
            return ""
        try:
            # Handle both YYYY-MM-DD and DD.MM.YYYY formats
            if "-" in date_string:
                parts = date_string.split("-")
                if len(parts) == 3:
                    return f"{parts[2]}.{parts[1]}.{parts[0]}"
            return date_string  # Return as-is if already in correct format or unknown
        except:
            return date_string
    
    def format_cake_donation(cake_text):
        """Shorten cake donation text"""
        if not cake_text:
            return ""
        if "freitag" in cake_text.lower():
            return "Rührkuchen für Freitag"
        elif "sonntag" in cake_text.lower():
            return "Kuchen für Sonntag"
        return cake_text
    
    def format_help_organisation(help_text):
        """Shorten help organisation text"""
        if not help_text:
            return ""
        if "aufbau" in help_text.lower():
            return "Aufbau"
        elif "abbau" in help_text.lower():
            return "Abbau"
        return help_text
    
    # Kinder-Details formatieren
    children_html = ""
    for i, person in enumerate(persons_data, 1):
        formatted_birthdate = format_date(person.get('birthdate', ''))
        children_html += f"""
        <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 8px; font-weight: bold;">Kind {i}:</td>
            <td style="padding: 8px;">{person.get('person_firstname', '')} {person.get('person_lastname', '')}</td>
        </tr>
        <tr>
            <td style="padding: 8px; padding-left: 20px; color: #666;">Geburtsdatum:</td>
            <td style="padding: 8px; color: #666;">{formatted_birthdate}</td>
        </tr>
        <tr>
            <td style="padding: 8px; padding-left: 20px; color: #666;">Verein:</td>
            <td style="padding: 8px; color: #666;">{person.get('club_membership', '')}</td>
        </tr>
        """
    
    child_count = len(persons_data)
    total_amount = child_count * 50
    
    # Format contact birthdate
    formatted_contact_birthdate = format_date(entry.contact_birthdate)
    
    # Format cake donation and help organisation
    formatted_cake_donation = format_cake_donation(entry.cake_donation)
    formatted_help_organisation = format_help_organisation(entry.help_organisation)
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bestätigung Zeltlager 2025</title>
    </head>
    <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
     
        <p style="font-size: 16px;">Liebe/r {entry.contact_firstname} {entry.contact_lastname},</p>
        
        <p>vielen Dank für Ihre Anmeldung zum <strong>Zeltlager 2025</strong>! Wir haben Ihre Anmeldung erfolgreich erhalten.</p>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h2 style="color: #2c3e50; margin-top: 0;">📋 Ihre Anmeldedaten im Überblick</h2>
            
            <h3 style="color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px;">👤 Kontaktperson</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 5px; font-weight: bold;">Name:</td><td style="padding: 5px;">{entry.contact_firstname} {entry.contact_lastname}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">Geburtsdatum:</td><td style="padding: 5px;">{formatted_contact_birthdate}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">E-Mail:</td><td style="padding: 5px;">{entry.email}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">Telefon:</td><td style="padding: 5px;">{entry.phone_number}</td></tr>
            </table>

            <h3 style="color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 25px;">👶 Angemeldete Kinder ({child_count} {'Kind' if child_count == 1 else 'Kinder'})</h3>
            <table style="width: 100%; border-collapse: collapse;">
                {children_html}
            </table>

            <h3 style="color: #34495e; border-bottom: 2px solid #3498db; padding-bottom: 5px; margin-top: 25px;">🍰 Weitere Angaben</h3>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 5px; font-weight: bold;">Kuchenspende:</td><td style="padding: 5px;">{formatted_cake_donation}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">Auf-/Abbau:</td><td style="padding: 5px;">{formatted_help_organisation}</td></tr>
            </table>
        </div>

        <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 20px; margin: 20px 0;">
            <h2 style="color: #856404; margin-top: 0;">💰 Zahlungsinformationen</h2>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 5px; font-weight: bold; color: #856404;">Betrag:</td><td style="padding: 5px; color: #856404; font-weight: bold;">{total_amount},00 €</td></tr>
                <tr><td style="padding: 5px; color: #856404;"></td><td style="padding: 5px; color: #856404; font-size: 14px;">({child_count} {'Kind' if child_count == 1 else 'Kinder'} x 50,00 €)</td></tr>
                <tr><td style="padding: 5px; font-weight: bold; color: #856404;">Zahlungsfrist:</td><td style="padding: 5px; color: #856404; font-weight: bold;">30. Juni 2025</td></tr>
            </table>
            
            <h3 style="color: #856404; background: #fff3cd; margin-top: 20px; margin-bottom: 10px;">Bankdaten:</h3>
            <table style="width: 100%; border-collapse: collapse; color: #856404; background: #fff3cd; border-radius: 5px; padding: 10px;">
                <tr><td style="padding: 5px; font-weight: bold;">Empfänger:</td><td style="padding: 5px;">{app.config.get('RECIPIENT_NAME', 'TSV Bitzfeld 1922 e.V.')}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">IBAN:</td><td style="padding: 5px;">{app.config.get('BANK_IBAN', 'DE89 6225 0030 0005 0447 68')}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">BIC:</td><td style="padding: 5px;">{app.config.get('BANK_BIC', 'SOLADES1HLB')}</td></tr>
                <tr><td style="padding: 5px; font-weight: bold;">VZ:</td><td style="padding: 5px;">Zeltlager-{entry.contact_firstname} {entry.contact_lastname}</td></tr>
            </table>
        </div>

        <div style="background: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 20px; margin: 20px 0;">
            <h2 style="color: #155724; margin-top: 0;">📝 Wichtige nächste Schritte</h2>
            <ol style="color: #155724; margin: 10px 0;">
                <li style="margin: 10px 0;"><strong>Zahlung überweisen</strong> bis 30. Juni 2025</li>
                <li style="margin: 10px 0;"><strong>📎 Formulare ausdrucken und ausfüllen</strong><br>
                    <em style="color: #155724; font-size: 14px;">Die Formulare (Gesundheitsbogen & Einverständniserklärung) finden Sie im Anhang dieser E-Mail!</em><br>
                    <small style="color: #666;">⚠️ Wichtig: Bitte für {'jedes Kind ein separates Formular' if child_count > 1 else 'das Kind ein Formular'} ausfüllen!</small>
                </li>
                <li style="margin: 10px 0;"><strong>Formulare mitbringen</strong> zum Zeltlager-Start am <strong>Freitag, 18. Juli 2025 um 16:00 Uhr</strong></li>
            </ol>
        </div>

        <div style="background: #e3f2fd; border: 1px solid #bbdefb; border-radius: 8px; padding: 20px; margin: 20px 0;">
            <h2 style="color: #1565c0; margin-top: 0;">🎒 Packliste für das Zeltlager</h2>
            
            <h3 style="color: #1565c0; margin-top: 20px; margin-bottom: 10px;">✅ Ausrüstung</h3>
            <ul style="color: #1565c0; margin: 10px 0; padding-left: 20px;">
                <li>Schlafsack</li>
                <li>Isomatte / Luftmatratze</li>
                <li>Wolldecke</li>
                <li>Waschzeug</li>
                <li>Handtücher</li>
                <li>Badesachen (für evtl. Wasserspiele)</li>
                <li>Taschenlampe</li>
                <li>Kleiner Rucksack, Vesperbox, Trinkflasche</li>
                <li>Kleider und Schuhwerk je nach Wetterlage</li>
                <li>Autositz</li>
            </ul>

            <h3 style="color: #1565c0; margin-top: 20px; margin-bottom: 10px;">❌ Nicht erwünscht</h3>
            <ul style="color: #1565c0; margin: 10px 0; padding-left: 20px;">
                <li>Süßigkeiten aller Art (Ameisen im Zelt)</li>
                <li>Elektronische Spielgeräte</li>
            </ul>

            <h3 style="color: #1565c0; margin-top: 20px; margin-bottom: 10px;">👨‍👩‍👧‍👦 Für die Eltern am Sonntag</h3>
            <ul style="color: #1565c0; margin: 10px 0; padding-left: 20px;">
                <li>Bitte eigenes Geschirr mitbringen</li>
                <li>Turnschuhe für das Fußballspiel</li>
            </ul>
        </div>

        <div style="background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 15px; margin: 20px 0;">
            <h3 style="color: #495057; margin-top: 0;">❓ Fragen oder Probleme</h3>
            <p style="margin: 5px 0;">📧 <a href="mailto:anmeldung.tsvbitzfeld1922@gmail.com" style="color: #007bff;">anmeldung.tsvbitzfeld1922@gmail.com</a></p>
            <p style="margin: 5px 0;">📞 Lena Weihbrecht: <a href="tel:+4917389093788" style="color: #007bff;">0173/8909378</a></p>
        </div>

        <div style="text-align: center; margin: 30px 0;">
            <p style="font-size: 16px; color: #333;">Wir freuen uns riesig auf drei tolle Tage mit {'Ihrem Kind' if child_count == 1 else 'Ihren Kindern'} beim Zeltlager 2025! 🏕️🚜</p>
        </div>

        <div style="border-top: 2px solid #dee2e6; padding-top: 20px; text-align: center; color: #6c757d; font-size: 14px;">
            <p style="margin: 5px 0;"><strong>Mit freundlichen Grüßen</strong></p>
            <p style="margin: 5px 0;">Ihr Zeltlager-Team</p>
            <p style="margin: 5px 0;">TSV Bitzfeld 1922 e.V. & TSV Schwabbach 1947 e.V.</p>
            <hr style="margin: 15px 0; border: none; border-top: 1px solid #dee2e6;">
            <p style="margin: 5px 0; font-size: 12px;">Diese E-Mail wurde automatisch generiert.</p>
            <p style="margin: 5px 0; font-size: 12px;">Anmeldezeitpunkt: {entry.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y um %H:%M Uhr")}</p>
        </div>

    </body>
    </html>
    """

def create_confirmation_email_text(entry, persons_data):
    """Create text version of confirmation email"""
    
    def format_date(date_string):
        """Convert YYYY-MM-DD to DD.MM.YYYY format"""
        if not date_string:
            return ""
        try:
            if "-" in date_string:
                parts = date_string.split("-")
                if len(parts) == 3:
                    return f"{parts[2]}.{parts[1]}.{parts[0]}"
            return date_string
        except:
            return date_string
    
    def format_cake_donation(cake_text):
        """Shorten cake donation text"""
        if not cake_text:
            return ""
        if "freitag" in cake_text.lower():
            return "Rührkuchen für Freitag"
        elif "sonntag" in cake_text.lower():
            return "Kuchen für Sonntag"
        return cake_text
    
    def format_help_organisation(help_text):
        """Shorten help organisation text"""
        if not help_text:
            return ""
        if "aufbau" in help_text.lower():
            return "Aufbau"
        elif "abbau" in help_text.lower():
            return "Abbau"
        return help_text
    
    # Kinder-Details formatieren
    children_details = []
    for i, person in enumerate(persons_data, 1):
        formatted_birthdate = format_date(person.get('birthdate', ''))
        children_details.append(
            f"  Kind {i}: {person.get('person_firstname', '')} {person.get('person_lastname', '')}\n"
            f"          Geburtsdatum: {formatted_birthdate}\n"
            f"          Verein: {person.get('club_membership', '')}"
        )
    
    children_text = "\n".join(children_details)
    child_count = len(persons_data)
    
    # Zahlungsbetrag berechnen
    total_amount = child_count * 50
    
    # Format contact birthdate
    formatted_contact_birthdate = format_date(entry.contact_birthdate)
    
    # Format cake donation and help organisation
    formatted_cake_donation = format_cake_donation(entry.cake_donation)
    formatted_help_organisation = format_help_organisation(entry.help_organisation)
    
    return f"""Liebe/r {entry.contact_firstname} {entry.contact_lastname},

vielen Dank für Ihre Anmeldung zum Zeltlager 2025 "Farm Fieber"!

═══════════════════════════════════════════════════
📋 IHRE ANMELDEDATEN IM ÜBERBLICK
═══════════════════════════════════════════════════

👤 KONTAKTPERSON:
   {entry.contact_firstname} {entry.contact_lastname}
   Geburtsdatum: {formatted_contact_birthdate}
   E-Mail: {entry.email}
   Telefon: {entry.phone_number}

👶 ANGEMELDETE KINDER ({child_count} {'Kind' if child_count == 1 else 'Kinder'}):
{children_text}

🍰 KUCHENSPENDE:
   {formatted_cake_donation}

🔨 AUF-/ABBAU:
   {formatted_help_organisation}

💰 ZAHLUNGSINFORMATIONEN:
   Betrag: {total_amount},00 € ({child_count} {'Kind' if child_count == 1 else 'Kinder'} x 50,00 €)
   Zahlungsfrist: 30. Juni 2025
   
   Bankdaten:
   Empfänger: {app.config.get('RECIPIENT_NAME', 'TSV Bitzfeld 1922 e.V.')}
   IBAN: {app.config.get('BANK_IBAN', 'DE89 6225 0030 0005 0447 68')}
   BIC: {app.config.get('BANK_BIC', 'SOLADES1HLB')}
   Verwendungszweck: Zeltlager-{entry.contact_firstname} {entry.contact_lastname}

═══════════════════════════════════════════════════
📝 WICHTIGE NÄCHSTE SCHRITTE
═══════════════════════════════════════════════════

1️⃣ ZAHLUNG bis 30. Juni 2025 überweisen

2️⃣ FORMULARE ausdrucken und ausfüllen:
   📎 Die Formulare (Gesundheitsbogen & Einverständniserklärung) finden Sie im Anhang!
   
   ⚠️ Wichtig: Bitte für {'jedes Kind ein separates Formular' if child_count > 1 else 'das Kind ein Formular'} ausfüllen!

3️⃣ FORMULARE mitbringen zum Zeltlager-Start:
   📅 Freitag, 18. Juli 2025 um 16:00 Uhr
   📍 Sportplatz in Schwabbach

═══════════════════════════════════════════════════
🎒 PACKLISTE FÜR DAS ZELTLAGER
═══════════════════════════════════════════════════

✅ AUSRÜSTUNG:
• Schlafsack
• Isomatte / Luftmatratze
• Wolldecke
• Waschzeug
• Handtücher
• Badesachen (für evtl. Wasserspiele)
• Taschenlampe
• Kleiner Rucksack, Vesperbox, Trinkflasche
• Kleider und Schuhwerk je nach Wetterlage
• Autositz

❌ NICHT ERWÜNSCHT:
• Süßigkeiten aller Art (Ameisen im Zelt)
• Elektronische Spielgeräte

👨‍👩‍👧‍👦 FÜR DIE ELTERN AM SONNTAG:
• Bitte eigenes Geschirr mitbringen
• Turnschuhe für das Fußballspiel

═══════════════════════════════════════════════════
❓ FRAGEN ODER PROBLEME?
═══════════════════════════════════════════════════

Kontaktieren Sie uns gerne:
📧 anmeldung.tsvbitzfeld1922@gmail.com
📞 Lena Weihbrecht: 0173/8909378

═══════════════════════════════════════════════════

Wir freuen uns riesig auf drei tolle Tage mit {'Ihrem Kind' if child_count == 1 else 'Ihren Kindern'} beim Zeltlager 2025! 🏕️🚜

Mit freundlichen Grüßen
Ihr Zeltlager-Team
TSV Bitzfeld 1922 e.V. & TSV Schwabbach 1947 e.V.

═══════════════════════════════════════════════════
Diese E-Mail wurde automatisch generiert.
Anmeldezeitpunkt: {entry.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y um %H:%M Uhr")}
"""

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
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
            try:
                data = request.get_json(force=True)
                app.logger.info("Received registration data")

                # CSRF-Token aus den Daten extrahieren und validieren
                csrf_token = data.get('csrf_token')
                if not csrf_token:
                    app.logger.error("No CSRF token in request")
                    return jsonify({
                        "success": False,
                        "error": "CSRF-Token fehlt. Bitte laden Sie die Seite neu."
                    }), 400

                # CSRF-Token validieren
                try:
                    from flask_wtf.csrf import validate_csrf
                    validate_csrf(csrf_token)
                except Exception as csrf_error:
                    app.logger.error(f"CSRF validation failed: {str(csrf_error)}")
                    return jsonify({
                        "success": False,
                        "error": "CSRF-Token ist ungültig. Bitte laden Sie die Seite neu."
                    }), 400

                # Validate data (OHNE WTForms, da wir JSON bekommen)
                is_valid, error_message = validate_registration_data(data)
                if not is_valid:
                    app.logger.error(f"Validation failed: {error_message}")
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
                db_data = sanitized_data.copy()
                db_data['persons'] = json.dumps(sanitized_data['persons'])

                # Create database entry
                registration = Registration(**db_data)
                db.session.add(registration)
                if not safe_commit():
                    app.logger.error("Database commit failed")
                    return jsonify({
                        "success": False,
                        "error": "Datenbankfehler. Bitte versuchen Sie es erneut."
                    }), 500

                # E-Mail sofort senden (synchron, nicht in Thread wegen Session-Problemen)
                email_sent = send_confirmation_email(app, registration.id)
                if not email_sent:
                    app.logger.warning(f"Failed to send confirmation email for registration {registration.id}")
                    # Trotzdem erfolgreich, aber mit Warnung
                    return jsonify({
                        "success": True,
                        "redirect": url_for("confirmation"),
                        "warning": "Anmeldung erfolgreich, aber E-Mail konnte nicht versendet werden."
                    })

                app.logger.info(f"Registration {registration.id} completed successfully with email confirmation")
                return jsonify({
                    "success": True,
                    "redirect": url_for("confirmation")
                })

            except json.JSONDecodeError as e:
                app.logger.error(f"Invalid JSON in request: {str(e)}")
                return jsonify({
                    "success": False,
                    "error": "Ungültige Datenformat. Bitte versuchen Sie es erneut."
                }), 400
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
        
        # Neue Statistik-Zähler
        cake_friday_count = 0
        cake_sunday_count = 0
        help_thursday_count = 0
        help_sunday_count = 0
        
        for reg in registrations:
            try:
                persons_data = json.loads(reg.persons)
                
                # Zähle alle angemeldeten Kinder
                total_children += len(persons_data)
                
                # Zähle Kuchenspenden
                cake_text = reg.cake_donation.lower()
                if 'freitag' in cake_text:
                    cake_friday_count += 1
                elif 'sonntag' in cake_text:
                    cake_sunday_count += 1
                
                # Zähle Helfer
                help_text = reg.help_organisation.lower()
                if 'aufbau' in help_text:
                    help_thursday_count += 1
                elif 'abbau' in help_text:
                    help_sunday_count += 1
                
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

        # Neue Statistiken
        stats = {
            'total_registrations': len(registrations),
            'total_children': total_children,
            'cake_friday_count': cake_friday_count,
            'cake_sunday_count': cake_sunday_count,
            'help_thursday_count': help_thursday_count,
            'help_sunday_count': help_sunday_count
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

@app.route("/edit-entry/<int:entry_id>", methods=["GET", "POST"])
@admin_required
def edit_entry(entry_id: int):
    """Edit registration entry"""
    try:
        registration = db.session.get(Registration, entry_id)
        if not registration:
            flash("Eintrag nicht gefunden.", "danger")
            return redirect(url_for("admin"))

        if request.method == "GET":
            # Lade Daten für Bearbeitungsformular
            try:
                persons_data = json.loads(registration.persons)
            except (json.JSONDecodeError, TypeError):
                persons_data = []
            
            edit_data = {
                'id': registration.id,
                'contact_firstname': registration.contact_firstname,
                'contact_lastname': registration.contact_lastname,
                'contact_birthdate': registration.contact_birthdate,
                'phone_number': registration.phone_number,
                'email': registration.email,
                'cake_donation': registration.cake_donation,
                'help_organisation': registration.help_organisation,
                'persons': persons_data
            }
            
            return render_template(
                "edit_form.html", 
                data=edit_data,
                csrf_token=generate_csrf(),
                csp_nonce=CSP_NONCE
            )

        elif request.method == "POST":
            # Verarbeite Formular-Daten (JSON oder normale Form)
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # AJAX-Request mit JSON-Daten
                try:
                    data = request.get_json(force=True)
                    
                    # Validiere Daten
                    is_valid, error_message = validate_registration_data(data)
                    if not is_valid:
                        return jsonify({
                            "success": False,
                            "error": error_message
                        }), 400

                    # Sanitize Daten
                    sanitized_data = {
                        "contact_firstname": sanitize_input(data["contact_firstname"]),
                        "contact_lastname": sanitize_input(data["contact_lastname"]),
                        "contact_birthdate": sanitize_input(data["contact_birthdate"]),
                        "phone_number": sanitize_input(data["phone_number"]),
                        "email": sanitize_input(data["email"].lower()),
                        "cake_donation": sanitize_input(data["cake_donation"]),
                        "help_organisation": sanitize_input(data["help_organisation"]),
                        "persons": json.dumps(data["persons"])
                    }

                    # Update Registration
                    for key, value in sanitized_data.items():
                        setattr(registration, key, value)

                    if not safe_commit():
                        return jsonify({
                            "success": False,
                            "error": "Datenbankfehler. Bitte versuchen Sie es erneut."
                        }), 500

                    app.logger.info(f"Registration {entry_id} updated successfully")
                    
                    return jsonify({
                        "success": True,
                        "message": "Eintrag erfolgreich bearbeitet!",
                        "redirect": url_for("admin")
                    })

                except Exception as e:
                    app.logger.error(f"Error updating registration {entry_id}: {str(e)}")
                    return jsonify({
                        "success": False,
                        "error": "Ein Fehler ist aufgetreten. Bitte versuchen Sie es erneut."
                    }), 500
            
            else:
                # Fallback für normale Form-Submissions
                flash("Formular-Upload wird nicht unterstützt. Bitte verwenden Sie das JavaScript-Interface.", "danger")
                return redirect(url_for("edit_entry", entry_id=entry_id))

    except Exception as e:
        app.logger.error(f"Error in edit_entry for ID {entry_id}: {str(e)}")
        flash("Fehler beim Bearbeiten des Eintrags.", "danger")
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
        participants_data = []  # Für angemeldete Personen (Kinder)
        companions_data = []    # Für Kontaktpersonen
        
        # Referenzdatum für Altersberechnung
        reference_date = datetime.now()
        date_str = reference_date.strftime("%d.%m.%Y")
        
        # Statistik-Zähler
        cake_friday_count = 0
        cake_sunday_count = 0
        help_thursday_count = 0
        help_sunday_count = 0
        
        for reg in registrations:
            # Daten für Kontaktperson
            contact_age = calculate_age(reg.contact_birthdate, reference_date) if reg.contact_birthdate else None
            contact_age_group = "Erwachsener (ab 18)" if contact_age and contact_age >= 18 else "Kind/Jugendl. (bis 17)"
            
            # Statistiken zählen
            cake_text = reg.cake_donation.lower()
            if 'freitag' in cake_text:
                cake_friday_count += 1
            elif 'sonntag' in cake_text:
                cake_sunday_count += 1
            
            help_text = reg.help_organisation.lower()
            if 'donnerstag' in help_text and 'aufbau' in help_text:
                help_thursday_count += 1
            elif 'sonntag' in help_text and 'abbau' in help_text:
                help_sunday_count += 1
            
            companions_data.append({
                "Anmeldungs-ID": reg.id,
                "Vorname": reg.contact_firstname,
                "Nachname": reg.contact_lastname,
                "Geburtsdatum": reg.contact_birthdate if reg.contact_birthdate else "Nicht angegeben",
                f"Alter am {date_str}": contact_age if contact_age is not None else "Unbekannt",
                "Altersgruppe": contact_age_group,
                "Telefon": reg.phone_number,
                "E-Mail": reg.email,
                "Kuchenspende": reg.cake_donation,
                "Auf-/Abbau": reg.help_organisation,
                "Anzahl angemeldete Kinder": len(json.loads(reg.persons)) if reg.persons else 0,
                "Anmeldung bestätigt": "Ja" if reg.confirmed else "Nein",
                "Anmeldezeitpunkt": reg.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y %H:%M")
            })
            
            # Daten für angemeldete Kinder
            try:
                persons = json.loads(reg.persons)
                for person in persons:
                    person_age = calculate_age(person.get('birthdate'), reference_date)
                    person_age_group = "Kind/Jugendl. (bis 17)" if person_age and person_age < 18 else "Erwachsener (ab 18)"
                    
                    participants_data.append({
                        "Anmeldungs-ID": reg.id,
                        "Vorname": person.get('person_firstname', ''),
                        "Nachname": person.get('person_lastname', ''),
                        "Geburtsdatum": person.get('birthdate', ''),
                        f"Alter am {date_str}": person_age if person_age is not None else "Unbekannt",
                        "Altersgruppe": person_age_group,
                        "Vereinsmitgliedschaft": person.get('club_membership', ''),
                        "Kontaktperson": f"{reg.contact_firstname} {reg.contact_lastname}",
                        "Kontakt E-Mail": reg.email,
                        "Kontakt Telefon": reg.phone_number,
                        "Anmeldung bestätigt": "Ja" if reg.confirmed else "Nein",
                        "Anmeldezeitpunkt": reg.created_at.astimezone(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y %H:%M")
                    })
            except (json.JSONDecodeError, TypeError) as e:
                app.logger.error(f"Error parsing persons data for registration {reg.id}: {e}")

        # Statistiken berechnen
        total_adults_participants = sum(1 for p in participants_data if p["Altersgruppe"] == "Erwachsener (ab 18)")
        total_adults_contacts = sum(1 for c in companions_data if c["Altersgruppe"] == "Erwachsener (ab 18)")
        total_adults = total_adults_participants + total_adults_contacts
        
        total_children_participants = sum(1 for p in participants_data if p["Altersgruppe"] == "Kind/Jugendl. (bis 17)")
        total_children_contacts = sum(1 for c in companions_data if c["Altersgruppe"] == "Kind/Jugendl. (bis 17)")
        total_children = total_children_participants + total_children_contacts
        
        confirmed_registrations = sum(1 for c in companions_data if c["Anmeldung bestätigt"] == "Ja")
        
        # DataFrames erstellen
        participants_df = pd.DataFrame(participants_data) if participants_data else pd.DataFrame()
        companions_df = pd.DataFrame(companions_data) if companions_data else pd.DataFrame()
        
        # Erweiterte Statistik-DataFrame erstellen
        stats_data = [
            ["Gesamt Anmeldungen", len(companions_data)],
            ["Bestätigte Anmeldungen", confirmed_registrations],
            ["Nicht bestätigte Anmeldungen", len(companions_data) - confirmed_registrations],
            ["", ""],  # Leerzeile
            ["Anzahl angemeldete Kinder (Teilnehmer)", len(participants_data)],
            ["Anzahl Kontaktpersonen", len(companions_data)],
            ["", ""],  # Leerzeile
            ["Gesamt Erwachsene (ab 18)", total_adults],
            ["Gesamt Kinder/Jugendliche (bis 17)", total_children],
            ["", ""],  # Leerzeile
            ["Kuchenspenden Freitag", cake_friday_count],
            ["Kuchenspenden Sonntag", cake_sunday_count],
            ["", ""],  # Leerzeile
            ["Helfer Aufbau Donnerstag", help_thursday_count],
            ["Helfer Abbau Sonntag", help_sunday_count],
            ["", ""],  # Leerzeile
            ["Export erstellt am", datetime.now(pytz.timezone("Europe/Berlin")).strftime("%d.%m.%Y %H:%M")]
        ]
        stats_df = pd.DataFrame(stats_data, columns=["Statistik", "Anzahl"])

        # Excel-Datei erstellen
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Sheet für Statistiken (zuerst)
            stats_df.to_excel(writer, index=False, sheet_name='Statistik')
            stats_sheet = writer.sheets['Statistik']
            
            # Spaltenbreiten für Statistik anpassen
            stats_sheet.column_dimensions['A'].width = 35
            stats_sheet.column_dimensions['B'].width = 20
            
            # Sheet für angemeldete Kinder
            if not participants_df.empty:
                participants_df.to_excel(writer, index=False, sheet_name='Angemeldete Kinder')
                participants_sheet = writer.sheets['Angemeldete Kinder']
                
                # Spaltenbreiten anpassen
                for idx, col in enumerate(participants_df.columns):
                    max_length = max(
                        participants_df[col].astype(str).apply(len).max(),
                        len(col)
                    ) + 2
                    col_letter = chr(65 + idx) if idx < 26 else chr(65 + idx // 26 - 1) + chr(65 + idx % 26)
                    participants_sheet.column_dimensions[col_letter].width = min(max_length, 30)
            
            # Sheet für Kontaktpersonen
            if not companions_df.empty:
                companions_df.to_excel(writer, index=False, sheet_name='Kontaktpersonen')
                companions_sheet = writer.sheets['Kontaktpersonen']
                
                # Spaltenbreiten anpassen
                for idx, col in enumerate(companions_df.columns):
                    max_length = max(
                        companions_df[col].astype(str).apply(len).max(),
                        len(col)
                    ) + 2
                    col_letter = chr(65 + idx) if idx < 26 else chr(65 + idx // 26 - 1) + chr(65 + idx % 26)
                    companions_sheet.column_dimensions[col_letter].width = min(max_length, 30)

        output.seek(0)
        
        # Dateiname mit Zeitstempel erstellen
        timestamp = datetime.now(pytz.timezone("Europe/Berlin"))\
            .strftime("%d-%m-%Y_%H-%M")
        
        # Response mit Excel-Datei senden
        response = Response(
            output.getvalue(),
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={
                "Content-Disposition": f"attachment; filename=Zeltlager_Anmeldungen_{timestamp}.xlsx",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0"
            }
        )
        
        app.logger.info(f"Excel export generated successfully with {len(participants_data)} children and {len(companions_data)} contacts")
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
    app.logger.error(f"CSRF Error: {request.url} - {str(e)}")
    
    # Für AJAX-Requests JSON zurückgeben
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
        return jsonify({
            "success": False,
            "error": "CSRF-Token ist ungültig oder fehlt. Bitte laden Sie die Seite neu."
        }), 400
    
    # Für normale Requests Flash-Message und Redirect
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