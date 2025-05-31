# config.py - Separate configuration file
import os
from datetime import timedelta

class Config:
    """Application configuration"""
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///registrations.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback_secret_key')
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 10800  # 3 hours
    
    # Session
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_TYPE = 'filesystem'
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    
    # Email
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SMTP_USER = os.getenv('SMTP_USER')
    SMTP_PASS = os.getenv('SMTP_PASS')
    
    # Admin
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

    # Bank Details
    BANK_NAME = os.getenv('BANK_NAME', 'Bank Name')
    RECIPIENT_NAME = os.getenv('RECIPIENT_NAME', 'Recipient Name')
    BANK_IBAN = os.getenv('BANK_IBAN', 'IBAN Number')
    BANK_BIC = os.getenv('BANK_BIC', 'BIC Code')
    
    # Rate limiting
    RATELIMIT_DEFAULT = "200 per day"
    RATELIMIT_STORAGE_URL = "memory://"
