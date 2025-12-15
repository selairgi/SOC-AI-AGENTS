@echo off
echo ====================================
echo  Resetting Rate Limits
echo ====================================
echo.
echo Choix:
echo   1. Redemarrer le conteneur web (recommande)
echo   2. Vider Redis cache
echo   3. Les deux
echo.
set /p choice="Choisissez (1, 2 ou 3): "
echo.

if "%choice%"=="1" goto restart_web
if "%choice%"=="2" goto clear_redis
if "%choice%"=="3" goto both
echo Choix invalide!
pause
exit /b 1

:restart_web
echo [1/2] Redemarrage du conteneur web...
docker compose restart web
echo [2/2] Attente du demarrage...
timeout /t 5 /nobreak >nul
echo.
echo ====================================
echo ✅ Rate limit reinitialise!
echo ====================================
goto end

:clear_redis
echo [1/1] Suppression de toutes les cles de rate limit dans Redis...
docker compose exec redis redis-cli --scan --pattern "LIMITER*" | docker compose exec -T redis xargs redis-cli DEL
echo.
echo ====================================
echo ✅ Cache Redis nettoye!
echo ====================================
goto end

:both
echo [1/3] Suppression du cache Redis...
docker compose exec redis redis-cli --scan --pattern "LIMITER*" | docker compose exec -T redis xargs redis-cli DEL
echo [2/3] Redemarrage du conteneur web...
docker compose restart web
echo [3/3] Attente du demarrage...
timeout /t 5 /nobreak >nul
echo.
echo ====================================
echo ✅ Rate limit completement reinitialise!
echo ====================================
goto end

:end
echo.
echo Verification de l'etat:
docker compose ps web
echo.
echo Vous pouvez maintenant refaire vos requetes!
echo.
pause
