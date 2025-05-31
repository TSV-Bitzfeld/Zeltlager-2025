# debug_fix.py - Debuggt und repariert die Datenbank-Probleme
import os
import sys
import traceback
import sqlite3

def test_imports():
    """Testet, ob alle Imports funktionieren"""
    print("🔍 Teste Imports...")
    try:
        from flask import Flask
        print("  ✅ Flask")
        
        from flask_sqlalchemy import SQLAlchemy
        print("  ✅ SQLAlchemy")
        
        from config import Config
        print("  ✅ Config")
        
        return True
    except Exception as e:
        print(f"  ❌ Import-Fehler: {e}")
        return False

def create_minimal_database():
    """Erstellt die Datenbank manuell mit SQL"""
    print("\n🔧 Erstelle Datenbank manuell...")
    
    try:
        # Datenbank direkt mit SQLite erstellen
        conn = sqlite3.connect('registrations.db')
        cursor = conn.cursor()
        
        # Tabelle erstellen
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS registration (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            persons TEXT NOT NULL DEFAULT '[]',
            contact_firstname VARCHAR(50) NOT NULL,
            contact_lastname VARCHAR(50) NOT NULL,
            contact_birthdate VARCHAR(10) NOT NULL,
            phone_number VARCHAR(15) NOT NULL,
            email VARCHAR(100) NOT NULL,
            cake_donation VARCHAR(100) NOT NULL DEFAULT '',
            help_organisation VARCHAR(100) NOT NULL DEFAULT '',
            confirmed BOOLEAN DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        cursor.execute(create_table_sql)
        
        # Index für Email erstellen
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON registration(email);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_created_at ON registration(created_at);")
        
        conn.commit()
        
        # Struktur überprüfen
        cursor.execute("PRAGMA table_info(registration)")
        columns = cursor.fetchall()
        
        print("  ✅ Tabelle 'registration' erstellt!")
        print("  📊 Spalten:")
        for col in columns:
            print(f"    - {col[1]} ({col[2]})")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"  ❌ SQL-Fehler: {e}")
        return False

def test_flask_app():
    """Testet, ob die Flask-App funktioniert"""
    print("\n🧪 Teste Flask-App...")
    
    try:
        # Minimale Flask-App Konfiguration
        from flask import Flask
        from flask_sqlalchemy import SQLAlchemy
        
        app = Flask(__name__)
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///registrations.db'
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        app.config['SECRET_KEY'] = 'test_secret'
        
        db = SQLAlchemy(app)
        
        with app.app_context():
            # Prüfen, ob Verbindung funktioniert
            result = db.engine.execute("SELECT COUNT(*) FROM registration")
            count = result.scalar()
            print(f"  ✅ Datenbankverbindung OK - {count} Einträge gefunden")
            
        return True
        
    except Exception as e:
        print(f"  ❌ Flask-App Fehler: {e}")
        traceback.print_exc()
        return False

def main():
    print("🚀 Diagnose und Reparatur gestartet...")
    print("=" * 60)
    
    # Schritt 1: Imports testen
    if not test_imports():
        print("\n❌ Import-Probleme gefunden. Installieren Sie fehlende Pakete:")
        print("pip install flask flask-sqlalchemy flask-migrate")
        return
    
    # Schritt 2: Vorhandene Datenbank prüfen
    if os.path.exists('registrations.db'):
        print("\n📁 Datenbank existiert bereits - lösche sie für Neustart...")
        os.remove('registrations.db')
    
    # Schritt 3: Datenbank manuell erstellen
    if not create_minimal_database():
        print("\n❌ Manuelle Datenbank-Erstellung fehlgeschlagen")
        return
    
    # Schritt 4: Flask-App testen
    if not test_flask_app():
        print("\n❌ Flask-App Test fehlgeschlagen")
        return
    
    # Schritt 5: Finale Überprüfung
    print("\n🎯 Finale Überprüfung...")
    if os.path.exists('registrations.db'):
        file_size = os.path.getsize('registrations.db')
        print(f"  ✅ Datenbank erstellt ({file_size} Bytes)")
        
        # Testdaten einfügen
        try:
            conn = sqlite3.connect('registrations.db')
            cursor = conn.cursor()
            
            test_data = """
            INSERT INTO registration 
            (persons, contact_firstname, contact_lastname, contact_birthdate, 
             phone_number, email, cake_donation, help_organisation) 
            VALUES 
            ('[{"person_firstname":"Test","person_lastname":"Kind","birthdate":"2015-01-01","club_membership":"TSV Bitzfeld 1922 e.V."}]',
             'Test', 'Parent', '1990-01-01', '0123456789', 'test@example.com',
             'Wir spenden einen Rührkuchen für den Freitag.',
             'Wir helfen beim Aufbau am Donnertag, 17. Juli ab 18:00 Uhr.')
            """
            
            cursor.execute(test_data)
            conn.commit()
            conn.close()
            
            print("  ✅ Testdaten eingefügt")
            
        except Exception as e:
            print(f"  ⚠️  Testdaten-Fehler (nicht kritisch): {e}")
    
    print("=" * 60)
    print("✅ Reparatur abgeschlossen!")
    print("\n🚀 Versuchen Sie jetzt: python app.py")

if __name__ == "__main__":
    main()