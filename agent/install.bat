@echo off
:: HardenOS Agent — Installation du service Windows
:: Doit être exécuté en tant qu'Administrateur

echo ============================================
echo  HardenOS Agent - Installation
echo ============================================

:: Vérification des droits admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERREUR : Ce script doit etre execute en tant qu'Administrateur.
    pause
    exit /b 1
)

:: Vérification de agent.conf
if not exist "%~dp0agent.conf" (
    echo ERREUR : Fichier agent.conf introuvable.
    echo Copiez agent.conf.example vers agent.conf et remplissez les valeurs.
    pause
    exit /b 1
)

:: Vérification du YAML
if not exist "%~dp0windows_server2022.yaml" (
    echo ERREUR : Fichier windows_server2022.yaml introuvable.
    echo Copiez le fichier de regles CIS dans le dossier de l'agent.
    pause
    exit /b 1
)

:: Installation des dépendances Python
echo.
echo [1/3] Installation des dependances Python...
pip install -r "%~dp0requirements.txt" --quiet
if %errorLevel% neq 0 (
    echo ERREUR : pip install a echoue. Verifiez que Python est installe.
    pause
    exit /b 1
)

:: Installation du service
echo [2/3] Installation du service Windows...
python "%~dp0hardenos_agent.py" install
if %errorLevel% neq 0 (
    echo ERREUR : Installation du service echouee.
    pause
    exit /b 1
)

:: Démarrage du service
echo [3/3] Demarrage du service...
python "%~dp0hardenos_agent.py" start
if %errorLevel% neq 0 (
    echo AVERTISSEMENT : Le service n'a pas pu demarrer automatiquement.
    echo Demarrez-le manuellement : sc start HardenOSAgent
)

echo.
echo ============================================
echo  Installation terminee !
echo  Service : HardenOS Security Agent
echo  Commandes utiles :
echo    sc start HardenOSAgent
echo    sc stop  HardenOSAgent
echo    sc query HardenOSAgent
echo ============================================
pause
