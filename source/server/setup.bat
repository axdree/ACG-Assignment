@echo off
IF EXIST %SYSTEMROOT%\py.exe (
    python --version | findstr /r "3\.[8-9] 3\.10" > NUL 2>&1
    IF %ERRORLEVEL% NEQ 0 GOTO noversion 

    virtualenv --version | findstr /r "15\.1" > NUL 2>&1
    GOTO runscript
)

python --version > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 GOTO nopython

GOTO runscript

:runscript
CMD %SYSTEMROOT%\py.exe /k python -m venv acg-server-venv/
CMD acg-server-venv/bin/activate
CMD 

:noversion
ECHO ERROR: Your Python is too old to run the script! (Python 3.8+)
PAUSE

:nopython
ECHO ERROR: Python has either not been installed or not added to your PATH.
PAUSE
