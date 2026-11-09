@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>&1
if errorlevel 1 (
  echo Node.js 22 or later is required. Install Node.js and reopen this launcher.
  pause
  exit /b 1
)
echo Starting HackMatrix. Keep this window open while using it.
node launch.mjs
echo The dashboard server stopped.
pause
