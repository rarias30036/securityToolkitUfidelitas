import sqlite3
from datetime import datetime

class Database:
    def __init__(self):
        # Connect to the SQLite database or create incidents table if it doesn't exist
        self.conn = sqlite3.connect('security_incidents.db')
        self._create_table()

    def _create_table(self):
        # Create a cursor object to execute SQL commands
        cursor = self.conn.cursor()
        # SQL query to create the incidents table with columns: id, type, description, and date
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                description TEXT,
                date TEXT
            )
        ''')
        # Commit the table creation to the database
        self.conn.commit()

    def log_incident(self, incident_type, description):
        cursor = self.conn.cursor()
        # SQL query to insert a new incident into the incidents table
        cursor.execute('''
            INSERT INTO incidents (type, description, date)
            VALUES (?, ?, ?)
        ''', (incident_type, description, datetime.now()))  # Use the current date and time
        # Commit the insertion to the database
        self.conn.commit()
        print(f"\nIncident logged successfully: {incident_type}")