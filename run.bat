@echo off
REM Build if needed, then run JADX Studio.
REM   run.bat                  -> GUI
REM   run.bat --gui app.apk    -> GUI with a file
REM   run.bat -o out app.apk   -> CLI
setlocal
cd /d "%~dp0"

if not exist "build\install\jadx-studio\bin\jadx-studio.bat" (
  echo [*] building ^(first run^)..
  if exist gradlew.bat ( call gradlew.bat installDist -q ) else ( call gradle.bat installDist -q )
)

call build\install\jadx-studio\bin\jadx-studio.bat %*