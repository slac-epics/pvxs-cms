@echo off
REM A bash with the helpers loaded: run_in, reset_topology, lab_ids, build_images.
call "%~dp0_common.bat" || exit /b 1
"%LAB_BASH%" -lc "cd \"$(cygpath -u '%LAB_EXAMPLE%')/podman\" && exec bash --rcfile <(echo '. ./helpers.sh') -i"
