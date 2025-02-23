# Arbiter Agent Demo

A demonstration of an automated arbiter agent that evaluates and processes security findings from multiple audit agents. 

## Quick Start

### Prerequisites

- Python 3.8+

### Setup

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# For Windows use: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
# Copy example config and modify as needed
cp .env.example .env

# Start server
python run.py
```

### Environment Variables

```bash
# API Keys
ANTHROPIC_API_KEY=     # API key for Claude evaluation

# Thresholds
OVERLAP_THRESHOLD=0.2  # Threshold for finding overlap detection
SIMILARITY_THRESHOLD=80  # Threshold for finding similarity
EVALUATION_THRESHOLD=60  # Threshold for finding evaluation (0-100)

# Logging (optional)
LOG_LEVEL=INFO        # DEBUG, INFO, WARNING, ERROR, CRITICAL
ENVIRONMENT=          # production or development
```

## API Reference

### Endpoints

#### `POST /api/process_findings`
Submit security findings for analysis, deduplication, and evaluation.

**Request Body:**
```json
{
  "project_id": "string",
  "reported_by_agent": "string",
  "findings": [
    {
      "finding_id": "string",
      "title": "string",
      "description": "string",
      "severity": "string",
      "recommendation": "string",
      "code_references": ["string"],
      "exploit_poc": "string"
    }
  ]
}
```

**Response:**
```json
{
  "unique": 1,
  "duplicated": 0,
  "disputed": 0
}
```

#### `GET /api/statistics`
Get evaluation statistics for findings.

**Query Parameters:**
- `project_id` (optional): Filter statistics by project ID

**Response:**
```json
{
  "project_id": "string",
  "agent_id": "string",
  "unique_count": 0,
  "duplicated_count": 0,
  "disputed_count": 0
}
```

### Examples

#### Submit Findings

Using inline JSON (simple example):
```bash
curl -X POST http://localhost:8080/api/process_findings \
-H "Content-Type: application/json" \
-d '{
  "project_id": "test-project",
  "reported_by_agent": "scanner-1",
  "findings": [{
    "finding_id": "VULN-001",
    "title": "Cross-site Scripting (XSS)",
    "description": "Found XSS vulnerability in user input field",
    "severity": "Medium",
    "recommendation": "Implement input validation and output encoding",
    "code_references": ["src/user/profile.js:42"],
    "exploit_poc": "<script>alert(1)</script>"
  }]
}'
```

Using test data file (recommended for testing):
```bash
# Submit findings from test data file (contains complete examples)
curl -X POST http://localhost:8080/api/process_findings \
-H "Content-Type: application/json" \
-d @test/data/findings.json
```

#### Get Statistics

```bash
# Get all statistics
curl "http://localhost:8080/api/statistics"

# Get statistics for specific project
curl "http://localhost:8080/api/statistics?project_id=test-project"
```

## Project Structure

```
app/                    # Backend service
├── main.py            # Entry point
├── api.py             # API endpoints
├── models.py          # Data models
├── database.py        # Database layer
├── database_factory.py # Database table creation
├── deduplication.py   # Finding deduplication
├── evaluation.py      # Quality assessment
├── logger.py          # Logging configuration
└── config.yaml        # Application configuration

data/                  # Data storage
└── findings.db        # SQLite database

logs/                  # Application logs
└── app.log           # Application log file

test/                  # Test files
└── data/             # Test data
    └── findings.json  # Sample findings

run.py                # Backend startup script
requirements.txt      # Python dependencies
.env                  # Environment variables
.gitignore           # Git ignore rules
```

## Notes

- Backend runs on http://localhost:8080
- Uses SQLite database stored in `data/findings.db`
- Logs are stored in `logs/app.log`
- Each project gets its own table named `findings_{project_id}`
- For production deployment, consider:
  - Setting up proper logging
  - Configuring appropriate security measures
  - Setting up monitoring and backup
