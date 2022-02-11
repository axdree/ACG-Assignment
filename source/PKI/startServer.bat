@echo off
IF EXIST %SYSTEMROOT%\py.exe (
    python --version | findstr /r "3\.[8-9] 3\.10" > NUL 2>&1
    IF %ERRORLEVEL% NEQ 0 GOTO noversion 

    GOTO runscript
)

:runscript
CD ./.venv/Scripts
CALL activate
python.exe %~dp0/CertificateIssuer.py
GOTO end

:noversion
ECHO ERROR: Your Python is too old to run the script! (Python 3.8+)
PAUSE

:nopython
ECHO ERROR: Python has either not been installed or not added to your PATH.
PAUSE

:end
PAUSE