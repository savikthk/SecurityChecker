@echo off
rem Build SecurityChecker: Visual Studio (MSVC) + Qt 6 + CMake/Ninja from the Qt kit
setlocal

set "QT_DIR=C:\Qt\6.11.1\msvc2022_64"
set "QT_TOOLS=C:\Qt\Tools"
set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

if not exist "%VCVARS%" (
    echo Visual Studio not found: %VCVARS%
    exit /b 1
)
call "%VCVARS%" >nul
set "PATH=%QT_TOOLS%\CMake_64\bin;%QT_TOOLS%\Ninja;%QT_DIR%\bin;%PATH%"

cd /d "%~dp0"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="%QT_DIR%"
if errorlevel 1 exit /b 1
cmake --build build
if errorlevel 1 exit /b 1

echo.
echo Done: %~dp0build\SecurityChecker.exe