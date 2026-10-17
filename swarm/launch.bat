@echo off
title PS5 Kernel Exploit Swarm (100 Agents)
echo ============================================================
echo   PS5 14.10 KERNEL EXPLOIT SWARM — 100 AGENTS
echo   Target: 10.0.0.96:9026
echo   Mode: FULL FORCE — hands-free 24/7
echo ============================================================
echo.

cd /d "%~dp0\.."

REM Check for API key
if not defined OPENROUTER_API_KEY if not defined ANTHROPIC_API_KEY (
    echo   NO API KEY SET. You need a free OpenRouter key:
    echo.
    echo   1. Go to https://openrouter.ai/keys
    echo   2. Sign up ^(free, no credit card^)
    echo   3. Create a key, then run:
    echo.
    echo      set OPENROUTER_API_KEY=sk-or-your-key-here
    echo      swarm\launch.bat
    echo.
    pause
    exit /b 1
)

echo Starting swarm...
echo To monitor: open another terminal and run: python swarm\dashboard.py
echo To stop: Ctrl+C
echo.

python swarm\swarm.py --agents 100

echo.
echo Swarm stopped. Press any key to exit.
pause >nul
