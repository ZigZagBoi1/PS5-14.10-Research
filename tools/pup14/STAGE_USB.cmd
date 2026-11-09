@echo off
cd /d "%~dp0\..\.."
python tools\pup14\prepare_usb.py --auto
echo.
echo Review the result above. No PS5 operation has been performed.
pause
