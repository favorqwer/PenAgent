@echo off
rem Lab profile 1: kali 100.74.213.15 -> target 100.84.151.2
"%~dp0.venv\Scripts\python.exe" "%~dp0cli.py" agent --kali 100.74.213.15 -t 100.84.151.2 %*
