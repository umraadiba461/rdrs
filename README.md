# RDRS - Ransomware Detection and Response System
Defensive, educational project. Simulation mode ON by default. Never run real malware.

## Setup
    python -m venv .venv
    source .venv/bin/activate      # Windows: .venv\Scripts\activate
    pip install -r requirements.txt
    python -m app.main --watch ./data/sandbox
    pytest --cov=app
