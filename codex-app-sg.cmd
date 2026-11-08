@echo off
setlocal
python -X utf8 "%~dp0tools\codex_env.py" app %*
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" pause
exit /b %RC%
