@echo off
REM One-time setup: create and start the podman machine, and check the pieces.
call "%~dp0_common.bat" || exit /b 1

podman machine inspect >nul 2>nul || (
    echo == creating the podman machine
    podman machine init --cpus 4 --memory 8192 --disk-size 60 || exit /b 1
)
podman info >nul 2>nul || (
    echo == starting the podman machine
    podman machine start || exit /b 1
)
"%LAB_BASH%" -lc "command -v podman-compose" >nul 2>nul || (
    echo podman-compose is required. With Python installed:  pip install podman-compose
    exit /b 1
)
echo The machine is running. Next:
echo     win\build-images.bat
echo     win\reset-topology.bat simple
