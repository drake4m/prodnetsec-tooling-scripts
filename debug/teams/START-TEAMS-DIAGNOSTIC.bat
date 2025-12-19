@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

cls
echo.
echo ================================================================
echo          DIAGNOSTIC TEAMS - ULTRATHINK SUPPORT
echo ================================================================
echo.
echo  Outil de diagnostic pour problemes Teams (lenteurs/coupures)
echo  Version 4.0.0
echo.
echo  INSTRUCTIONS:
echo  ------------
echo  1. Appuyer sur une touche pour lancer le diagnostic
echo  2. Pendant un appel Teams: appuyer sur ESPACE pour capturer
echo  3. Appuyer sur ESC pour terminer et obtenir le rapport
echo.
echo ================================================================
echo.
pause

cls
echo.
echo ================================================================
echo  DIAGNOSTIC EN COURS...
echo ================================================================
echo.

set "TIMESTAMP=%DATE:~-4%%DATE:~3,2%%DATE:~0,2%-%TIME:~0,2%%TIME:~3,2%"
set "TIMESTAMP=!TIMESTAMP: =0!"
set "OUTPUT_FILE=%~dp0TEAMS-DIAG-!TIMESTAMP!.csv"

powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '%~dp0teams-debug.ps1' -Mode baseline -Export '!OUTPUT_FILE!'"

echo.
echo ================================================================
echo  DIAGNOSTIC TERMINE
echo ================================================================
echo.
echo  Fichiers generes:
echo  - !OUTPUT_FILE!
echo  - Rapport affiche ci-dessus
echo.
echo  IMPORTANT: Copier le rapport affiche et l'envoyer par email
echo.
echo ================================================================
echo.
echo Appuyer sur une touche pour fermer...
pause >nul
exit