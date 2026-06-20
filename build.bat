@echo off
setlocal

pyinstaller --onefile --windowed --name "MotorCriptograficoMASGLOBAL" --collect-all customtkinter app.py

endlocal
