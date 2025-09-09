# URL Audit Kit (40 Checks + Local LLM via Ollama)

Evaluates a URL against 40 trust parameters and augments content signals using a local Ollama model.

## Install & Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # fill what you have
python cli.py https://example.com --json report.json
```
