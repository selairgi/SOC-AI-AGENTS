@echo off
echo ====================================
echo  Rebuilding SOC AI Agents (No Cache)
echo ====================================
echo.
echo Stopping all containers...
docker compose down
echo.
echo Building images without cache...
docker compose build --no-cache
echo.
echo Starting all containers...
docker compose up -d
echo.
echo Waiting for containers to start...
timeout /t 10 /nobreak >nul
echo.
echo Testing OpenAI connectivity...
echo.
docker compose exec web curl -I https://api.openai.com
echo.
echo ====================================
echo Done! Check logs with:
echo   docker compose logs -f web
echo   docker compose logs -f core
echo ====================================
echo.
pause
