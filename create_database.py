# create_database.py - Erstellt die Datenbank mit allen Tabellen und Spalten
import os
import sys
sys.path.append('.')

from app import app, db
from config import Config

def create_database():
    """Erstellt die Datenbank mit allen benötigten Tabellen"""
    
    print("🚀 Datenbank-Erstellung gestartet...")
    print("=" * 50)
    
    try:
        # Flask App Context erstellen
        with app.app_context():
            # Alle Tabellen erstellen
            print("📋 Erstelle alle Tabellen...")
            db.create_all()
            
            # Prüfen, ob die Datenbank erstellt wurde
            db_path = 'registrations.db'
            if os.path.exists(db_path):
                print(f"✅ Datenbank '{db_path}' erfolgreich erstellt!")
                
                # Tabellenstruktur prüfen
                import sqlite3
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                cursor.execute("PRAGMA table_info(registration)")
                columns = cursor.fetchall()
                
                print("\n📊 Erstelle Tabellen-Struktur:")
                print("Tabelle: registration")
                for col in columns:
                    print(f"  - {col[1]} ({col[2]})")
                
                conn.close()
                
                print("\n🎯 Datenbank ist bereit für die Anwendung!")
                return True
            else:
                print("❌ Datenbank wurde nicht erstellt")
                return False
                
    except Exception as e:
        print(f"❌ Fehler beim Erstellen der Datenbank: {e}")
        print("\nMögliche Ursachen:")
        print("- Fehler in der app.py oder config.py")
        print("- Fehlende Abhängigkeiten")
        print("- Berechtigungsprobleme")
        return False

if __name__ == "__main__":
    if create_database():
        print("=" * 50)
        print("✅ Fertig! Sie können jetzt 'python app.py' ausführen.")
        print("\n💡 Tipp: Ihre Anwendung sollte jetzt ohne Probleme starten!")
    else:
        print("=" * 50)
        print("❌ Datenbank-Erstellung fehlgeschlagen.")
        print("Überprüfen Sie die Fehlermeldungen oben.")