# db_fix.py - Führen Sie diese Datei aus, um die Datenbank zu reparieren
import sqlite3
import os

def fix_database():
    """Fügt die fehlenden Spalten zur Datenbank hinzu"""
    
    # Pfad zur Datenbank
    db_path = 'registrations.db'
    
    if not os.path.exists(db_path):
        print(f"❌ Datenbank '{db_path}' nicht gefunden!")
        print("Stellen Sie sicher, dass Sie im richtigen Projektordner sind.")
        return False
    
    try:
        # Verbindung zur Datenbank herstellen
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Prüfen, ob die Spalten bereits existieren
        cursor.execute("PRAGMA table_info(registration)")
        columns = [row[1] for row in cursor.fetchall()]
        
        print("🔍 Vorhandene Spalten:")
        for col in columns:
            print(f"  - {col}")
        
        # Spalten hinzufügen, falls sie nicht existieren
        changes_made = False
        
        if 'cake_donation' not in columns:
            print("➕ Füge 'cake_donation' Spalte hinzu...")
            cursor.execute("ALTER TABLE registration ADD COLUMN cake_donation VARCHAR(100) NOT NULL DEFAULT ''")
            changes_made = True
        else:
            print("✅ 'cake_donation' Spalte bereits vorhanden")
            
        if 'help_organisation' not in columns:
            print("➕ Füge 'help_organisation' Spalte hinzu...")
            cursor.execute("ALTER TABLE registration ADD COLUMN help_organisation VARCHAR(100) NOT NULL DEFAULT ''")
            changes_made = True
        else:
            print("✅ 'help_organisation' Spalte bereits vorhanden")
        
        # Änderungen speichern
        if changes_made:
            conn.commit()
            print("✅ Datenbank erfolgreich aktualisiert!")
        else:
            print("ℹ️  Keine Änderungen erforderlich - alle Spalten bereits vorhanden")
        
        # Finale Überprüfung
        cursor.execute("PRAGMA table_info(registration)")
        final_columns = [row[1] for row in cursor.fetchall()]
        
        print("\n🎯 Finale Spalten-Übersicht:")
        for col in final_columns:
            print(f"  - {col}")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Fehler beim Aktualisieren der Datenbank: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Datenbank-Reparatur gestartet...")
    print("=" * 50)
    
    if fix_database():
        print("=" * 50)
        print("✅ Fertig! Sie können jetzt 'python app.py' ausführen.")
    else:
        print("=" * 50)
        print("❌ Reparatur fehlgeschlagen. Prüfen Sie die Fehlermeldungen oben.")