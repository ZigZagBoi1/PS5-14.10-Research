@echo off
cd /d "%~dp0\..\.."
python tools\pup14\analyze_output.py --auto
echo.
echo Review the analysis result above.
pause
