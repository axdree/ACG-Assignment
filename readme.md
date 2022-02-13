# [ACG Assignment- Andre, Bin Qian, JiWoo](https://github.com/lightcoxa/ACG-Assignment)

Contents:
1. [Instructions - Automated Setup and Run with batch files. (Windows)](#instructions---automated-setup-and-run-with-batch-files-windows)
2. [Instructions - Automated Setup and Run with bash files. (Linux)](#instructions---automated-setup-and-run-with-bash-files-linux)
3. [Instructions - Manual Setup and install.](#instructions---manual-setup-and-install)

Please Ensure you have [Python 3.10+!](https://www.python.org/downloads/release/python-3102/)

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
1. Open a Command Prompt / Terminal and CD into the directory of each script
2. Run `python -m venv .venv`
On Windows:
3. Run `.venv/Scripts/activate.bat`
On Linux:
3. Run `source .venv/bin/activate`
4. In the virutal environment, run `python -m pip install -r requirements.txt`
5. Start the script with `python <SCRIPTNAME>`
