@echo off
REM Destroy whatever laboratory is up and build the named one. No name lists them.
REM     win\reset-topology.bat simple-with-gateway
call "%~dp0_common.bat" || exit /b 1
"%LAB_BASH%" -lc "cd \"$(cygpath -u '%LAB_EXAMPLE%')/podman\" && ./reset.sh %*"
