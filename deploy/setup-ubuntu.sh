#!/bin/bash
# ============================================
# SECFORIT Day0 - Ubuntu 24.04 Setup Script
#
# For: i9-12900K + RTX 3060 (12GB) + 64GB RAM
#
# This script installs and configures:
#   1. NVIDIA Container Toolkit (GPU passthrough)
#   2. Docker & Docker Compose
#   3. Ollama with llama3.1:8b
#   4. Nginx reverse proxy
#   5. SSL via Let's Encrypt
#   6. SECFORIT app via Docker Compose
#
# Usage:
#   chmod +x setup-ubuntu.sh
#   sudo ./setup-ubuntu.sh
# ============================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[SECFORIT]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
err() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
[[ $EUID -ne 0 ]] && err "Run as root: sudo ./setup-ubuntu.sh"

DOMAIN="${1:-}"
EMAIL="${2:-}"

if [[ -z "$DOMAIN" ]]; then
    echo ""
    echo "Usage: sudo ./setup-ubuntu.sh <domain> <email>"
    echo "  domain: your domain name (e.g., secforit.ro)"
    echo "  email:  email for Let's Encrypt SSL (e.g., razvan@secforit.ro)"
    echo ""
    echo "For local-only setup (no SSL):"
    echo "  sudo ./setup-ubuntu.sh local"
    echo ""
    exit 1
fi

log "Starting SECFORIT Day0 setup on Ubuntu 24.04..."
log "Host: $(hostname) | CPU: $(nproc) cores | RAM: $(free -h | awk '/Mem/{print $2}')"

# ============================================
# Step 1: System Updates
# ============================================
log "Step 1/7: Updating system packages..."
apt-get update -qq
apt-get upgrade -y -qq

# ============================================
# Step 2: NVIDIA Drivers & Container Toolkit
# ============================================
log "Step 2/7: Setting up NVIDIA GPU support..."

# Check if NVIDIA driver is installed
if ! command -v nvidia-smi &>/dev/null; then
    log "Installing NVIDIA drivers..."
    apt-get install -y -qq nvidia-driver-535
    warn "NVIDIA driver installed. A REBOOT may be required. Run this script again after reboot."
else
    log "NVIDIA driver found: $(nvidia-smi --query-gpu=driver_version --format=csv,noheader)"
fi

# Install NVIDIA Container Toolkit
if ! command -v nvidia-ctk &>/dev/null; then
    log "Installing NVIDIA Container Toolkit..."
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
    curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
        sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
        tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
    apt-get update -qq
    apt-get install -y -qq nvidia-container-toolkit
    nvidia-ctk runtime configure --runtime=docker
fi

# ============================================
# Step 3: Docker
# ============================================
log "Step 3/7: Setting up Docker..."

if ! command -v docker &>/dev/null; then
    log "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
else
    log "Docker found: $(docker --version)"
fi

# Restart Docker to pick up NVIDIA runtime
systemctl restart docker

# ============================================
# Step 4: Nginx
# ============================================
log "Step 4/7: Setting up Nginx..."

apt-get install -y -qq nginx certbot python3-certbot-nginx

# ============================================
# Step 5: Pull Ollama + Model via Docker
# ============================================
log "Step 5/7: Setting up Ollama with llama3.1:8b..."

# Start Ollama container first
docker pull ollama/ollama:latest
docker run -d --gpus all \
    --name ollama-setup \
    -p 127.0.0.1:11434:11434 \
    -v ollama_data:/root/.ollama \
    -e NVIDIA_VISIBLE_DEVICES=all \
    ollama/ollama:latest

# Wait for Ollama to be ready
log "Waiting for Ollama to start..."
for i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        break
    fi
    sleep 2
done

# Pull the model
log "Pulling llama3.1:8b (this will take a few minutes)..."
docker exec ollama-setup ollama pull llama3.1:8b

# Stop the temporary container (docker-compose will manage it)
docker stop ollama-setup
docker rm ollama-setup

log "Model llama3.1:8b ready!"

# ============================================
# Step 6: Nginx Configuration
# ============================================
log "Step 6/7: Configuring Nginx..."

if [[ "$DOMAIN" == "local" ]]; then
    # Local-only config (no SSL)
    cat > /etc/nginx/sites-available/secforit <<'NGINX_LOCAL'
upstream nextjs_backend {
    server 127.0.0.1:3000;
    keepalive 32;
}

server {
    listen 80;
    server_name localhost;

    client_max_body_size 10M;

    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/xml;

    location /api/ {
        proxy_pass http://nextjs_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 180s;
    }

    location /_next/static/ {
        proxy_pass http://nextjs_backend;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass http://nextjs_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;
    }
}
NGINX_LOCAL

else
    # Production config with SSL
    # Copy the full nginx config and replace domain
    cp "$(dirname "$0")/nginx.conf" /etc/nginx/sites-available/secforit
    sed -i "s/your-domain.com/$DOMAIN/g" /etc/nginx/sites-available/secforit

    # Get SSL certificate
    if [[ -n "$EMAIL" ]]; then
        log "Obtaining SSL certificate for $DOMAIN..."
        # Temporary nginx config for certbot
        cat > /etc/nginx/sites-available/secforit-temp <<TEMP
server {
    listen 80;
    server_name $DOMAIN;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 200 'ok'; }
}
TEMP
        ln -sf /etc/nginx/sites-available/secforit-temp /etc/nginx/sites-enabled/secforit
        rm -f /etc/nginx/sites-enabled/default
        nginx -t && systemctl reload nginx

        mkdir -p /var/www/certbot
        certbot certonly --webroot -w /var/www/certbot -d "$DOMAIN" --email "$EMAIL" --agree-tos --non-interactive

        rm -f /etc/nginx/sites-available/secforit-temp
    else
        warn "No email provided - skipping SSL. Run: certbot --nginx -d $DOMAIN"
    fi
fi

ln -sf /etc/nginx/sites-available/secforit /etc/nginx/sites-enabled/secforit
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ============================================
# Step 7: Create .env and start services
# ============================================
log "Step 7/7: Starting services..."

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [[ ! -f "$APP_DIR/.env" ]]; then
    cat > "$APP_DIR/.env" <<ENV
# SECFORIT Day0 Environment Variables
# Generated by setup-ubuntu.sh on $(date)

# Required: Groq API key for AI summaries
GROQ_API_KEY=your_groq_api_key_here

# Optional: NVD API key for higher rate limits
NVD_API_KEY=

# Base URL
NEXT_PUBLIC_BASE_URL=https://${DOMAIN}

# Ollama (managed by Docker Compose - don't change)
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3.1:8b
ENV

    warn "Created $APP_DIR/.env - EDIT THIS FILE and add your GROQ_API_KEY before starting!"
    warn "Then run: cd $APP_DIR/deploy && docker compose up -d"
else
    log ".env file already exists, not overwriting"
    cd "$APP_DIR/deploy"
    docker compose up -d
fi

echo ""
log "============================================"
log "SECFORIT Day0 Setup Complete!"
log "============================================"
echo ""
echo "  System: Ubuntu 24.04 | i9-12900K | RTX 3060 | 64GB RAM"
echo "  GPU:    $(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null || echo 'N/A')"
echo "  Model:  llama3.1:8b (Ollama)"
echo "  Nginx:  configured at /etc/nginx/sites-available/secforit"
echo ""
if [[ "$DOMAIN" == "local" ]]; then
    echo "  URL:    http://localhost"
else
    echo "  URL:    https://$DOMAIN"
fi
echo ""
echo "  Next steps:"
echo "    1. Edit $APP_DIR/.env and add GROQ_API_KEY"
echo "    2. cd $APP_DIR/deploy && docker compose up -d"
echo "    3. Visit the Security Bulletins page to test Ollama"
echo ""
