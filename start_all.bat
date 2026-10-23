@echo off
echo ===========================================
echo Starting ERION CYBERGUARD Services...
echo ===========================================

echo Starting Admin Dashboard (Port 5000)...
start cmd /k "python app.py"

echo Starting Image Detection (Port 5001)...
start cmd /k "cd CyberGuard-Image-Detection && .venv\Scripts\python.exe app.py"

echo Starting Video Detection (Port 5050)...
start cmd /k "cd cybervideo && python app.py"

echo Starting Mailguard (Port 8000)...
start cmd /k "cd mailguard && run.bat"

echo.
echo All services have been launched in separate windows!
echo Close the individual command prompt windows to stop the servers later.
pause
