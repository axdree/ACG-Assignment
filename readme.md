1. [Instructions - Automated Setup and Run with batch files. (Windows)](#instructions---automated-setup-and-run-with-batch-files-windows)
2. [Instructions - Manual Setup and install.](#instructions---manual-setup-and-install)

# Instructions - Automated Setup and Run with batch files. (Windows)
## To Setup
-  Run `setup.bat` in each folder

## To Run
- Run `start<NAME>.bat` in each folder in this order:
    1. PKI
    2. Server
    3. Client

# Instructions - Automated Setup and Run with bash files. (Linux)
## To Setup
-  Run `setup.sh` in each folder

## To Run
- Run `start<NAME>.sh` in each folder in this order:
    1. PKI
    2. Server
    3. Client

# Instructions - Manual Setup and install.
## To Setup
- Open a Command Prompt / Terminal and CD into the directory of each script
- Run `python -m venv .venv`
On Windows:
- Run `.venv/Scripts/activate.bat`
On Linux:
- Run `source .venv/bin/activate`
- In the virutal environment, run `python -m pip install -r requirements.txt`
- Start the script with `python <SCRIPTNAME>`
