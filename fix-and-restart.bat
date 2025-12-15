@echo off
echo ====================================
echo  Fixing SOC Core Container
echo ====================================
echo.
echo Stopping containers...
docker compose down
echo.
echo Restarting all containers...
docker compose up -d
echo.
echo Done! Check logs with: docker compose logs -f core
echo.
pause
