import csv
import sqlite3

# Connect to the SQLite database
conn = sqlite3.connect('cve_database.db')
cursor = conn.cursor()

# Open the CSV file and insert data into the database
with open('CVE_DATABASE.csv', 'r') as file:
    csv_data = csv.reader(file)
    next(csv_data)  # Skip the header row if present

    for row in csv_data:
        cursor.execute('''
            INSERT INTO cve_database (cve_id, severity ,cvss , affected_packages , description , cwe_id)
            VALUES (?, ?, ?, ?, ?, ?);
        ''', row)

# Commit the changes and close the connection
conn.commit()
conn.close()