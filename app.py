from flask import Flask, g, jsonify, request
import sqlite3

app = Flask(__name__)
app.config['DATABASE'] = 'cve_database.db'
app.json.sort_keys = False

class Data:
    def __init__(self, data):
        self.cve_id = data[0]
        self.severity = data[1]
        self.cvss = data[2]
        self.affected_packages = data[3]
        self.description = data[4]
        self.cwe_id = data[5]

def get_db():
    #"""Get a database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row  # Enable dict-like row access
    return db

@app.teardown_appcontext
def close_connection(exception):
    #"""Close the database connection on app teardown."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

@app.route('/cve/all', methods=['GET'])
def get_all_cves():
    #"""Retrieve all CVE records."""
    try:
        db = get_db()
        cursor = db.execute('SELECT * FROM cve_database')
        rows = cursor.fetchall()

        cve_list = []
        for row in rows:
            item = Data(row)
            item_dict = {
                'cve_id': item.cve_id,
                'severity': item.severity,
                'cvss': item.cvss,
                'affected_packages': item.affected_packages,
                'description': item.description,
                'cwe_id': item.cwe_id
            }
            cve_list.append(item_dict)

        return jsonify(cve_list), 200
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/<cve_id>', methods=['GET'])
def get_cve_details(cve_id):
    #"""Retrieve details of a specific CVE by its ID."""
    try:
        db = get_db()
        cursor = db.execute('SELECT * FROM cve_database WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({'error': 'CVE not found'}), 404

        item = Data(row)
        item_dict = {
            'cve_id': item.cve_id,
            'severity': item.severity,
            'cvss': item.cvss,
            'affected_packages': item.affected_packages,
            'description': item.description,
            'cwe_id': item.cwe_id
        }

        return jsonify(item_dict), 200
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/addCVE', methods=['POST'])
def add_cve():
    #"""Add a new CVE record."""
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid input'}), 400

    required_fields = ['cve_id', 'severity', 'cvss', 'affected_packages', 'description', 'cwe_id']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing fields in input data'}), 400

    try:
        db = get_db()
        cursor = db.execute('SELECT * FROM cve_database WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()
        if row:
            return jsonify({'error': 'CVE ID already exists'}), 409
        db.execute('INSERT INTO cve_database (cve_id, severity, cvss, affected_packages, description, cwe_id) VALUES (?, ?, ?, ?, ?, ?)',
                   (data['cve_id'], data['severity'], data['cvss'], data['affected_packages'], data['description'], data['cwe_id']))
        db.commit()

        new_cve = {field: data[field] for field in required_fields}
        return jsonify({'message': 'CVE added successfully', 'cve_data': new_cve}), 201
    except sqlite3.IntegrityError as e:
        return jsonify({'error': 'CVE ID already exists'}), 409
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/<cve_id>', methods=['DELETE'])
def delete_cve(cve_id):
    #"""Delete a CVE record by its ID."""
    try:
        db = get_db()
        cursor = db.execute('SELECT * FROM cve_database WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({'error': 'CVE not found'}), 404

        db.execute('DELETE FROM cve_database WHERE cve_id = ?', (cve_id,))
        db.commit()
        return jsonify({'message': 'CVE deleted successfully', 'cve_id': cve_id}), 200
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

@app.route('/cve/<cve_id>', methods=['PUT'])
def update_cve(cve_id):
    #"""Update an existing CVE record by its ID."""
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid input'}), 400

    fields_to_update = ['severity', 'cvss', 'affected_packages', 'description', 'cwe_id']
    updates = {field: data[field] for field in fields_to_update if field in data}

    if not updates:
        return jsonify({'error': 'No valid fields to update'}), 400

    try:
        db = get_db()
        cursor = db.execute('SELECT * FROM cve_database WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()

        if row is None:
            return jsonify({'error': 'CVE not found'}), 404

        set_clause = ', '.join(f"{field} = ?" for field in updates)
        values = list(updates.values()) + [cve_id]

        db.execute(f'UPDATE cve_database SET {set_clause} WHERE cve_id = ?', values)
        db.commit()

        updated_cve = {field: updates.get(field, row[field]) for field in ['cve_id', *fields_to_update]}
        return jsonify({'message': 'CVE updated successfully', 'cve_data': updated_cve}), 200
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
