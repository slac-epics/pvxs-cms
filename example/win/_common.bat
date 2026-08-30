@echo off
REM Shared plumbing for the laboratory wrappers. Not run directly.
REM
REM UNTESTED ON REAL WINDOWS: written against the documented behaviour of native
REM Windows podman and Git for Windows. Remove this notice once a live run passes.
REM
REM The laboratories are driven by the same bash scripts on every platform. These
REM wrappers only find a bash, stop MSYS from rewriting container paths, and hand over.

REM The repository root is two levels above this file: ...\pvxs-cms\example\win\
set "LAB_EXAMPLE=%~dp0.."

REM Native podman first; nothing here works without it.
where podman >nul 2>nul || (
    echo podman is not installed. Install Podman for Windows from podman.io,
    echo then run win\setup.bat once.
    exit /b 1
)

REM A bash to run the scripts with. Git for Windows ships one; podman's own
REM machine is the fallback shell of last resort.
set "LAB_BASH="
for %%B in ("%ProgramFiles%\Git\bin\bash.exe" "%ProgramFiles(x86)%\Git\bin\bash.exe" "%LocalAppData%\Programs\Git\bin\bash.exe") do (
    if exist %%B set "LAB_BASH=%%~B"
)
if not defined LAB_BASH (
    where bash >nul 2>nul && for /f "delims=" %%B in ('where bash') do set "LAB_BASH=%%B"
)
if not defined LAB_BASH (
    echo No bash found. Install Git for Windows from git-scm.com; its bash runs
    echo the laboratory scripts unchanged.
    exit /b 1
)

REM MSYS rewrites arguments that look like paths, which corrupts container mount
REM specifications such as ./config:/etc/config. Container paths are not Windows
REM paths; leave every argument exactly as typed.
set "MSYS2_ARG_CONV_EXCL=*"
set "MSYS_NO_PATHCONV=1"
exit /b 0
