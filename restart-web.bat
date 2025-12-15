@echo off
echo Restarting SOC Web Container...
docker compose restart web
echo.
echo Done! The web interface should be updated at http://localhost:5000
echo.
pause
