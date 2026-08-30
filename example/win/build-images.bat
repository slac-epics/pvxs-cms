@echo off
REM Build the laboratory images with podman. JOBS limits compiler processes:
REM     set JOBS=2 ^& win\build-images.bat
call "%~dp0_common.bat" || exit /b 1
"%LAB_BASH%" -lc "cd \"$(cygpath -u '%LAB_EXAMPLE%')\" && CONTAINER_ENGINE=podman JOBS=\"${JOBS:-}\" ./bootstrap.sh %*"
