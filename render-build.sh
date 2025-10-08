#!/usr/bin/env bash
echo "🚀 Building Technovaganza CTF..."
pip install -r requirements.txt
python -c "from app import initialize_database; initialize_database()"
echo "✅ Build completed successfully!"