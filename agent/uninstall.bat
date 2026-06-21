@echo off
:: HardenOS Agent — Désinstallation du service Windows
:: Doit être exécuté en tant qu'Administrateur

echo ============================================
echo  HardenOS Agent - Desinstallation
echo ============================================

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERREUR : Ce script doit etre execute en tant qu'Administrateur.
    pause
    exit /b 1
)

echo Arret du service...
python "%~dp0hardenos_agent.py" stop 2>nul

echo Suppression du service...
python "%~dp0hardenos_agent.py" remove

echo.
echo Service HardenOS Agent desinstalle.
pause
