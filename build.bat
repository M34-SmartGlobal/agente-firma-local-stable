@echo off
setlocal

pyinstaller --onefile --windowed --name "MotorCriptograficoMASGLOBAL" --collect-all customtkinter --hidden-import=pkcs11 app.py

endlocal
