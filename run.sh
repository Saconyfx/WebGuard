#!/usr/bin/env bash
# WebGuard — one-line start (Linux / macOS)
set -e

if ! command -v docker &> /dev/null; then
  echo "❌ Docker not found. Install from https://docs.docker.com/get-docker/"
  exit 1
fi

echo "🛡  Starting WebGuard..."
docker compose up --build
