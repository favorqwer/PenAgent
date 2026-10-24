@echo off
rem Lab profile 2: kali 100.116.135.31 -> target 100.86.108.4
"%~dp0.venv\Scripts\python.exe" "%~dp0cli.py" agent --kali 100.116.135.31 -t 100.86.108.4 %*
