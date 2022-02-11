#!/bin/bash

python -V |grep /r "3\.[8-9] 3\.10" > /dev/null 2>&1 || {
    echo >&2 "Python 3.8+ doesn't seem to be installed.  Do you have a weird installation?"
    echo >&2 "If you have python 3.5, use it to run run.py instead of this script."
    exit 1; }

activate(){
    . .venv/Scripts/activate
}

cd "$(dirname "$BASH_SOURCE")"
python -m venv .venv
activate()
pip install -r requirements.txt

