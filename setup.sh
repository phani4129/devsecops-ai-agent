#!/usr/bin/env bash
# setup.sh
# One-time setup script for running the DevSecOps AI Agent on your laptop.
# Works on macOS and Linux. On Windows, run the equivalent commands manually
# inside Git Bash or WSL (see README.md for the Windows-specific steps).

set -e

echo "==> Creating Python virtual environment..."
python3 -m venv .venv

echo "==> Activating virtual environment..."
source .venv/bin/activate

echo "==> Installing dependencies (this may take a few minutes, ~1-2GB download)..."
pip install --upgrade pip
pip install -r requirements.txt

echo "==> Creating .env from template (you must add your free Groq API key)..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "    Created .env — open it and paste your Groq API key from https://console.groq.com/keys"
else
    echo "    .env already exists, skipping."
fi

echo "==> Building the local RAG knowledge base (downloads a small embedding model once, ~90MB)..."
python knowledge_base/build_knowledge_base.py

echo ""
echo "Setup complete."
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your free Groq API key (https://console.groq.com/keys)"
echo "  2. Run:  source .venv/bin/activate"
echo "  3. Run:  streamlit run app.py"
echo ""
