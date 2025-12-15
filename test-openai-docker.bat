@echo off
echo ====================================
echo  Testing OpenAI API in Docker
echo ====================================
echo.
echo [1/5] Testing ping to api.openai.com...
docker compose exec web ping -c 4 api.openai.com
echo.
echo.
echo [2/5] Testing network connectivity to OpenAI...
docker compose exec web curl -I https://api.openai.com
echo.
echo.
echo [3/5] Testing SSL certificates...
docker compose exec web curl -v https://api.openai.com 2>&1 | findstr "SSL"
echo.
echo.
echo [4/5] Checking CA certificates in container...
docker compose exec web ls -la /etc/ssl/certs/ | findstr "ca-certificates"
echo.
echo.
echo [5/5] Running Python OpenAI API test...
docker compose exec web python /app/test_openai_connection.py
echo.
echo ====================================
echo Test Complete!
echo ====================================
pause
