#!/bin/bash

cd "$(dirname "$BASH_SOURCE")"
python3 -m venv .venv
source "$(dirname "$BASH_SOURCE")"/.venv/bin/activate
pip install -r requirements.txt