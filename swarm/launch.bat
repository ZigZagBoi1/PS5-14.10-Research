@echo off
title PS5 Kernel Exploit Swarm (100 Agents)
echo ============================================================
echo   PS5 14.10 KERNEL EXPLOIT SWARM — 100 AGENTS
echo   Target: 10.0.0.96:9026
echo   Mode: FULL FORCE — hands-free 24/7
echo ============================================================
echo.
echo Starting swarm...
echo To monitor: open another terminal and run: python swarm\dashboard.py
echo To stop: Ctrl+C
echo.

cd /d "%~dp0\.."
python swarm\swarm.py --agents 100

echo.
echo Swarm stopped. Press any key to exit.
pause >nul
