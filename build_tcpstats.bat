@echo off
echo Building TcpStats.exe...
echo.

where csc.exe >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    csc.exe /out:TcpStats.exe /optimize+ TcpStats.cs
    goto done
)

if exist "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" (
    C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:TcpStats.exe /optimize+ TcpStats.cs
    goto done
)

echo ERROR: Could not find csc.exe
echo Run from Visual Studio Developer Command Prompt or install .NET Framework SDK
exit /b 1

:done
if %ERRORLEVEL% EQU 0 (
    echo.
    echo Build successful!
    echo.
    echo Usage: TcpStats.exe [options]
    echo   --all       Show all connection states
    echo   -v          Verbose output
    echo   -p PID      Filter by process ID
    echo   --port NUM  Filter by port number
    echo.
    echo IMPORTANT: Run as Administrator for full statistics
) else (
    echo Build failed!
)
