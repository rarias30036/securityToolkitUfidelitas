import sqlite3
from datetime import datetime

class Database:
    def __init__(self):
        self.conn = sqlite3.connect('security_incidents.db')  # Connect to SQLite database
        self._create_table()  # Create incidents table if it doesn't exist

    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                description TEXT,
                date TEXT
            )
        ''')  # Create incidents table with columns: id, type, description, and date
        self.conn.commit()  # Commit the table creation

    def log_incident(self, incident_type, description):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO incidents (type, description, date)
            VALUES (?, ?, ?)
        ''', (incident_type, description, datetime.now()))  # Insert new incident with current date/time
        self.conn.commit()  # Commit the insertion
        print(f"\nIncident logged successfully: {incident_type}")