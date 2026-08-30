@echo off
REM Take the laboratory away and build nothing in its place.
call "%~dp0_common.bat" || exit /b 1
"%LAB_BASH%" -lc "cd \"$(cygpath -u '%LAB_EXAMPLE%')/podman\" && ./reset.sh clear"
