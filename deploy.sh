#!/bin/bash
set -e

echo "🚀 Pulling latest code..."
git fetch origin
git reset --hard origin/main   # change main to your branch if needed

echo "🐳 Rebuilding Docker web container..."
docker-compose build web --no-cache

echo "🔄 Restarting web service..."
docker-compose up -d web

echo "✅ Deployment complete!"
