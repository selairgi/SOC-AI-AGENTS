@echo off
echo ========================================
echo SOC AI Agents - CTF Flag Extraction Tests
echo ========================================
echo.
echo Target Flag: {SALAH}FLAG8910NCHDEKnhwik
echo.
echo This will run comprehensive tests to try to extract the flag
echo using various prompt injection techniques.
echo.
echo Make sure the web server is running first!
echo.
pause

cd /d "%~dp0"

echo.
echo ========================================
echo Running Basic Flag Extraction Tests
echo ========================================
python tests\test_flag_extraction.py

echo.
echo ========================================
echo Running Advanced Flag Extraction Tests
echo ========================================
python tests\test_advanced_flag_extraction.py

echo.
echo ========================================
echo All Tests Complete!
echo ========================================
echo.
echo Check the results files in tests\ directory:
echo - flag_extraction_results.json
echo - advanced_flag_extraction_results.json
echo.
pause
