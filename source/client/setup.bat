@echo off
IF EXIST %SYSTEMROOT%\py.exe (
    python --version | findstr /r "3\.[8-9] 3\.10" > NUL 2>&1
    IF %ERRORLEVEL% NEQ 0 GOTO noversion 

    GOTO runscript
)

python --version | findstr /r "3\.[8-9] 3\.10" > NUL 2>&1
IF %ERRORLEVEL% NEQ 0 GOTO nopython

echo Setting Up Virtual Environment...
python -m venv .venv
CD ./.venv/Scripts
timeout 5
CALL activate
CD /d "%~dp0"
pip install -r requirements.txt
echo Setup and Update Complete, successful if no errors were faced during update.
GOTO END

:runscript
echo Setting Up Virtual Environment...
%SYSTEMROOT%\py.exe -m venv .venv
CD ./.venv/Scripts
timeout 5
CALL activate
CD /d "%~dp0"
pip install -r requirements.txt
echo Setup and Update Complete, successful if no errors were faced during update.
GOTO END

:noversion
ECHO ERROR: Your Python is too old to run the script! (Python 3.8+)
GOTO END

:nopython
ECHO ERROR: Python has either not been installed or not added to your PATH.
GOTO END

:end
PAUSE