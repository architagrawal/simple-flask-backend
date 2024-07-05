# CVE Management Web Application

This is a Flask web application that interacts with a SQLite database to manage CVE (Common Vulnerabilities and Exposures) records and performs CRUD operations.

## Setup Instructions

### Prerequisites

Ensure you have the following installed:

- Python 3.10 or higher
- pip (Python package installer)

### Installation

1. Download the code and setup the schema in sqlite database.

```
CREATE TABLE cve_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    cvss REAL CHECK(cvss >= 0 AND cvss <= 10),
    affected_packages TEXT,
    description TEXT,
    cwe_id TEXT
);

```

2. Update pip and install the required libraries:

   ```sh
   pip install -r requirements.txt
   ```

3. Set up the SQLite database:

   ```sh
   python import_csv.py
   ```

4. Run the Flask application:

   ```sh
   python app.py
   ```

## API Endpoints

### 1. Add a New CVE Record

- **Endpoint:** `/cve/addCVE`
- **Method:** POST
- **Expected Input:** JSON object with the following fields:

  - `cve_id`: string (required)
  - `description`: string (required)
  - `published_date`: string (optional, format: YYYY-MM-DD)
  - `severity`: string (optional, e.g., "Low", "Medium", "High")
  - `cvss`: string (optional)
  - `affected_packages` : string (optional)
  - `cwe_id` : string(optional)

- **Example Input:**

  ```json
  {
    "cve_id": "CVE-2023-1234",
    "description": "Description of the vulnerability.",
    "published_date": "2023-07-01",
    "severity": "High",
    "cvss": "3.3",
    "affected_packages": "pack-1",
    "cwe_id": "CWE-276"
  }
  ```

- **Expected Output:** JSON object with the added CVE record and a success message.

- **Example Output:**

  ```json
  {
    "message": "CVE record added successfully.",
    "cve": {
      "id": 1,
      "cve_id": "CVE-2023-1234",
      "description": "Description of the vulnerability.",
      "published_date": "2023-07-01",
      "severity": "High"
    }
  }
  ```

### 2. Retrieve All CVE Records

- **Endpoint:** `/cve/all`
- **Method:** GET
- **Expected Input:** None

- **Expected Output:** JSON array of all CVE records.

- **Example Output:**

  ```json
  [
    {
      "id": 1,
      "cve_id": "CVE-2023-1234",
      "description": "Description of the vulnerability.",
      "published_date": "2023-07-01",
      "severity": "High",
      "cvss": "3.3",
      "affected_packages": "pack-1",
      "cwe_id": "CWE-276"
    },
    {
      "id": 2,
      "cve_id": "CVE-2023-5678",
      "description": "Another vulnerability description.",
      "published_date": "2023-07-02",
      "severity": "Medium",
      "cvss": "3.3",
      "affected_packages": "pack-1",
      "cwe_id": "CWE-276"
    }
  ]
  ```

### 3. Retrieve a Specific CVE Record

- **Endpoint:** `cve/<id>`
- **Method:** GET
- **Expected Input:** URL parameter with the CVE record ID.

- **Expected Output:** JSON object with the requested CVE record.

- **Example Output:**

  ```json
  {
    "id": 1,
    "cve_id": "CVE-2023-1234",
    "description": "Description of the vulnerability.",
    "published_date": "2023-07-01",
    "severity": "High",
    "cvss": "3.3",
    "affected_packages": "pack-1",
    "cwe_id": "CWE-276"
  }
  ```

### 4. Update a CVE Record

- **Endpoint:** `cve/<id>`
- **Method:** PUT
- **Expected Input:** JSON object with the fields to update:

  - `cve_id`: string (optional)
  - `description`: string (optional)
  - `published_date`: string (optional, format: YYYY-MM-DD)
  - `severity`: string (optional, e.g., "Low", "Medium", "High")
  - `cvss`: string (optional)
  - `affected_packages` : string (optional)
  - `cwe_id` : string(optional)

- **Example Input:**

  ```json
  {
    "description": "Updated description of the vulnerability.",
    "severity": "Low"
  }
  ```

- **Expected Output:** JSON object with the updated CVE record and a success message.

- **Example Output:**

  ```json
  {
    "message": "CVE record updated successfully.",
    "cve": {
      "id": 1,
      "cve_id": "CVE-2023-1234",
      "description": "Updated description of the vulnerability.",
      "published_date": "2023-07-01",
      "severity": "Low",
      "cvss": "3.3",
      "affected_packages": "pack-1",
      "cwe_id": "CWE-276"
    }
  }
  ```

### 5. Delete a CVE Record

- **Endpoint:** `/cve/<id>`
- **Method:** DELETE
- **Expected Input:** URL parameter with the CVE record ID.

- **Expected Output:** JSON object with a success message.

- **Example Output:**

  ```json
  {
    "message": "CVE record deleted successfully."
  }
  ```
