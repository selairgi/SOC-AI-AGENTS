@echo off
echo ====================================
echo  Fixing Docker Network + Restart
echo ====================================
echo.
echo Ce script va:
echo   1. Arreter tous les conteneurs
echo   2. Supprimer le reseau existant
echo   3. Recreer tout avec IPv6 + DNS fixes
echo   4. Tester la connectivite
echo.
pause
echo.

echo [1/5] Arret de tous les conteneurs...
docker compose down
echo.

echo [2/5] Suppression de l'ancien reseau (si existe)...
docker network rm socaiagentscursor_soc-network 2>nul || echo Reseau deja supprime
echo.

echo [3/5] Reconstruction complete sans cache...
docker compose build --no-cache
echo.

echo [4/5] Demarrage de tous les conteneurs avec nouveau reseau...
docker compose up -d
echo.

echo [5/5] Attente du demarrage (15 secondes)...
timeout /t 15 /nobreak >nul
echo.

echo ====================================
echo  Tests de Connectivite
echo ====================================
echo.

echo Test 1: Ping Google DNS (IPv4)
docker compose exec web ping -c 2 8.8.8.8
echo.

echo Test 2: Resolution DNS
docker compose exec web sh -c "getent hosts api.openai.com || nslookup api.openai.com || echo 'DNS tools not available'"
echo.

echo Test 3: Curl OpenAI API
docker compose exec web curl -I --max-time 10 https://api.openai.com
echo.

echo ====================================
echo  Etat des Services
echo ====================================
docker compose ps
echo.

echo ====================================
echo Termine!
echo.
echo Si les tests passent, executez:
echo   test-openai-docker.bat
echo.
echo Sinon, verifiez:
echo   docker compose logs web
echo ====================================
pause
