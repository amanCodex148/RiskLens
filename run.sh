#!/usr/bin/env bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

echo "=========================================================="
echo " Starting RiskLens Platform"
echo " Continuous Cyber Risk Quantification & Investment Optimizer"
echo "=========================================================="

SKIP_TESTS=false

for arg in "$@"; do
    case $arg in
        --docker|-d)
            echo "Launching RiskLens inside Docker container..."
            if command -v docker &> /dev/null && docker compose version &> /dev/null; then
                exec docker compose up --build
            elif command -v docker-compose &> /dev/null; then
                exec docker-compose up --build
            else
                echo "Error: Docker / Docker Compose is not installed on this system."
                exit 1
            fi
            ;;
        --skip-tests|-s|--fast)
            SKIP_TESTS=true
            ;;
        --test|-t)
            if [ -d ".venv" ]; then
                source .venv/bin/activate
            fi
            export PYTHONPATH="$DIR:$PYTHONPATH"
            echo "Running full automated test suite..."
            exec python3 -m unittest discover -s tests -p "test_*.py" -v
            ;;
        *)
            ;;
    esac
done

if [ ! -d ".venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source .venv/bin/activate
fi

export PYTHONPATH="$DIR:$PYTHONPATH"

if [ "$SKIP_TESTS" = false ]; then
    echo "Running test suite to verify mathematical models..."
    python3 -m unittest discover -s tests -p "test_*.py" -v
else
    echo "Skipping test suite (--skip-tests active)..."
fi

echo ""
echo "Starting RiskLens server on http://localhost:8000"
echo "Press Ctrl+C to stop."
echo "=========================================================="
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000
