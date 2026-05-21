#!/usr/bin/env bash
# =============================================================================
# setup.sh — Automated setup script for the NTFS Timestamp Forgery Detector
# Designed for Kali Linux (Debian-based)
# Usage: bash setup.sh
# =============================================================================

set -e

echo "============================================================"
echo "  Automated Digital Forensic Tool — Setup Script"
echo "  NTFS Timestamp Forgery Detector | Group 15, UDOM"
echo "============================================================"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "[*] Detected OS: $NAME"
else
    echo "[!] Cannot detect OS. Proceeding anyway..."
fi

# Install system dependencies (requires sudo)
echo ""
echo "[*] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
    libssl-dev libffi-dev build-essential \
    libpango-1.0-0 libpangoft2-1.0-0 libgdk-pixbuf2.0-0 \
    libcairo2 libgirepository1.0-dev gir1.2-pango-1.0 \
    poppler-utils 2>/dev/null || echo "[!] Some apt packages may have failed — continuing."

# Create virtual environment
echo ""
echo "[*] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip -q

# Install Python dependencies
echo ""
echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# Create required directories
echo ""
echo "[*] Creating required directories..."
mkdir -p media/uploads logs staticfiles

# Apply database migrations
echo ""
echo "[*] Applying database migrations..."
python manage.py makemigrations
python manage.py migrate

# Create superuser (optional — skip if already exists)
echo ""
echo "[*] Creating default admin user (admin/admin123)..."
python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@forensic.local', 'admin123')
    print('Admin user created.')
else:
    print('Admin user already exists.')
"

# Collect static files
echo ""
echo "[*] Collecting static files..."
python manage.py collectstatic --noinput -v 0

echo ""
echo "============================================================"
echo "  Setup complete!"
echo ""
echo "  To start the server:"
echo "    source venv/bin/activate"
echo "    python manage.py runserver"
echo ""
echo "  Then open: http://127.0.0.1:8000"
echo "  Admin:     http://127.0.0.1:8000/admin"
echo "  Login:     admin / admin123"
echo "============================================================"
