@echo off
echo.
echo  ============================================
echo   TCP Port Scanner - Build Script
echo  ============================================
echo.

:: Check if g++ is available
where g++ >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [ERROR] g++ not found! Please install MinGW-w64 or TDM-GCC.
    echo  Download: https://www.mingw-w64.org/downloads/
    echo.
    pause
    exit /b 1
)

echo  [*] Compiler found:
g++ --version | head -1

echo.
echo  [*] Compiling port_scanner.cpp ...
echo.

g++ -o port_scanner.exe port_scanner.cpp ^
    -lws2_32 ^
    -std=c++17 ^
    -O2 ^
    -Wall ^
    -static-libgcc ^
    -static-libstdc++

if %ERRORLEVEL% EQU 0 (
    echo.
    echo  [SUCCESS] Build completed: port_scanner.exe
    echo.
    echo  Usage examples:
    echo    port_scanner.exe 127.0.0.1
    echo    port_scanner.exe 192.168.1.1 -p 1-1024
    echo    port_scanner.exe scanme.nmap.org -p 80,443,22 -t 50
    echo    port_scanner.exe 10.0.0.1 -p 1-65535 -t 500 -o result.txt
    echo.
) else (
    echo.
    echo  [FAILED] Build failed! Check errors above.
    echo.
)

pause
