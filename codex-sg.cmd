@echo off
setlocal
rem Runs in the CURRENT directory; args pass through. Optional first arg: --no-guard
python -X utf8 "%~dp0tools\codex_env.py" run %*
exit /b %ERRORLEVEL%
