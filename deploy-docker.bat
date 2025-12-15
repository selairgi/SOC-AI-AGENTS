@echo off
echo ========================================
echo SOC AI Agents - Docker Deployment
echo ========================================
echo.
echo This script will:
echo 1. Stop existing containers
echo 2. Rebuild all Docker images with latest code
echo 3. Start all services
echo.
pause

cd /d "%~dp0"

echo.
echo [1/4] Stopping existing containers...
docker-compose down

echo.
echo [2/4] Removing old images...
docker-compose down --rmi local

echo.
echo [3/4] Building new images with latest code...
docker-compose build --no-cache

echo.
echo [4/4] Starting all services...
docker-compose up -d

echo.
echo ========================================
echo Deployment Complete!
echo ========================================
echo.
echo Services Status:
docker-compose ps

echo.
echo Web UI available at: http://localhost:5000
echo.
echo To view logs: docker-compose logs -f web
echo To stop: docker-compose down
echo.
pause
