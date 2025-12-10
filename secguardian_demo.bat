	@echo off
setlocal ENABLEDELAYEDEXPANSION

rem ==========================================================
rem  SecGuardian Demo Runner
rem  File: secguardian_demo.bat
rem  Author: Mobin Yousefi (github.com/mobinyousefi-cs)
rem  Usage: Double-click or run in cmd from project root
rem ==========================================================

rem Detect project root (directory of this .bat)
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo.
echo ==========================================================
echo   SecGuardian - Demo Control Script
echo   Project Root: %CD%
echo ==========================================================
echo.

rem ----------------------------------------------------------
rem Detect Python (prefer py launcher on Windows)
rem ----------------------------------------------------------
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    set "PYTHON_CMD=py -3"
) else (
    set "PYTHON_CMD=python"
)

echo Using Python command: %PYTHON_CMD%
echo.

rem ----------------------------------------------------------
rem Virtualenv handling (.venv in project root)
rem ----------------------------------------------------------
set "VENV_DIR=.venv"
set "VENV_ACTIVATE=%VENV_DIR%\Scripts\activate.bat"

:CHECK_VENV
if exist "%VENV_ACTIVATE%" (
    echo [INFO] Virtual environment found: %VENV_DIR%
) else (
    echo [INFO] No virtual environment found. Creating one...
    %PYTHON_CMD% -m venv "%VENV_DIR%"
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to create virtual environment.
        echo Press any key to exit...
        pause >nul
        exit /b 1
    )
    echo [OK] Virtual environment created.
)

call "%VENV_ACTIVATE%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to activate virtual environment.
    echo Press any key to exit...
    pause >nul
    exit /b 1
)

echo [OK] Virtualenv activated.
echo Python in venv:
where python
echo.

rem ----------------------------------------------------------
rem Main menu loop
rem ----------------------------------------------------------
:MENU
echo ==========================================================
echo   SecGuardian Demo - Main Menu
echo ==========================================================
echo   [1] Install / Update dependencies (requirements.txt)
echo   [2] Run unit tests (pytest)
echo   [3] Start SecGuardian monitor (main.py)
echo   [4] Open HTML dashboard (if exists)
echo   [Q] Quit
echo.
set /p choice=Select an option [1-4,Q]: 

if /I "%choice%"=="1" goto INSTALL_DEPS
if /I "%choice%"=="2" goto RUN_TESTS
if /I "%choice%"=="3" goto RUN_MONITOR
if /I "%choice%"=="4" goto OPEN_DASHBOARD
if /I "%choice%"=="Q" goto QUIT

echo.
echo [WARN] Invalid choice. Please select 1-4 or Q.
echo.
goto MENU

rem ----------------------------------------------------------
rem Option 1: Install dependencies
rem ----------------------------------------------------------
:INSTALL_DEPS
echo.
echo ==========================================================
echo   Installing / Updating Python dependencies
echo ==========================================================
if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found in %CD%
    echo.
    goto MENU
)

python -m pip install --upgrade pip
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Failed to upgrade pip. Continuing...
)

pip install --no-cache-dir -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install dependencies.
    echo.
) else (
    echo [OK] Dependencies installed/updated successfully.
    echo.
)

goto MENU

rem ----------------------------------------------------------
rem Option 2: Run tests
rem ----------------------------------------------------------
:RUN_TESTS
echo.
echo ==========================================================
echo   Running unit tests with pytest
echo ==========================================================
where pytest >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] pytest not found. Installing pytest...
    pip install pytest
    if %ERRORLEVEL% NEQ 0 (
        echo [ERROR] Failed to install pytest.
        echo.
        goto MENU
    )
)

pytest -q
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [WARN] Some tests failed or errors occurred.
) else (
    echo.
    echo [OK] All tests passed.
)

echo.
goto MENU

rem ----------------------------------------------------------
rem Option 3: Run monitor
rem ----------------------------------------------------------
:RUN_MONITOR
echo.
echo ==========================================================
echo   Starting SecGuardian Monitor
echo ==========================================================
if not exist "main.py" (
    echo [ERROR] main.py not found in %CD%
    echo.
    goto MENU
)

if not exist "rules" (
    echo [WARN] rules directory not found. Creating and adding sample_rules.yar is recommended.
) else (
    if not exist "rules\sample_rules.yar" (
        echo [WARN] sample_rules.yar not found in rules\. Please add your YARA rules.
    )
)

if not exist "logs" (
    mkdir "logs"
)

echo.
echo [INFO] Press CTRL+C to stop monitoring.
echo.

python main.py --rules ".\rules\sample_rules.yar" --log-dir ".\logs"
echo.
goto MENU

rem ----------------------------------------------------------
rem Option 4: Open HTML dashboard
rem ----------------------------------------------------------
:OPEN_DASHBOARD
echo.
echo ==========================================================
echo   Opening HTML Dashboard
echo ==========================================================
set "DASHBOARD_PATH=logs\dashboard.html"

if not exist "logs" (
    echo [WARN] logs directory does not exist yet.
    echo Run the monitor at least once to generate dashboard.html
    echo.
    goto MENU
)

if not exist "%DASHBOARD_PATH%" (
    echo [WARN] %DASHBOARD_PATH% not found.
    echo Run the monitor until at least one event is generated.
    echo.
    goto MENU
)

echo [INFO] Opening %DASHBOARD_PATH% in default browser...
start "" "%DASHBOARD_PATH%"
echo.
goto MENU

rem ----------------------------------------------------------
rem Quit
rem ----------------------------------------------------------
:QUIT
echo.
echo Shutting down SecGuardian Demo script.
echo.
endlocal
exit /b 0
