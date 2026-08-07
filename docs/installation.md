# Installation & Setup Documentation

## Prerequisites
- Python 3.11+ with `PyYAML` installed (`pip install PyYAML --break-system-packages`)
- Node.js 18+ (for schema validation tools)
- Docker & Docker Compose (for sandboxed execution environments)
- Git

## Step-by-Step Installation
1. Clone or navigate to the repository workspace:
   ```bash
   cd /home/user/noble-cascade
   ```
2. Inspect the skill manifest recording all installed components and provenance:
   ```bash
   cat agent-skills/manifest.yaml
   ```
3. Run the stack validation test suite to confirm all governance, security, and reporting skills load and execute correctly:
   ```bash
   python3 agent-skills/tests/validate-stack.py
   ```
