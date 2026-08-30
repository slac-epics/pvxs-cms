@echo off
REM Run a command somewhere in the laboratory, as someone:
REM     win\run-in.bat lab as guest without a certificate pvxget test:aiExample
call "%~dp0_common.bat" || exit /b 1
"%LAB_BASH%" -lc "cd \"$(cygpath -u '%LAB_EXAMPLE%')/podman\" && . ./helpers.sh >/dev/null && run_in %*"
