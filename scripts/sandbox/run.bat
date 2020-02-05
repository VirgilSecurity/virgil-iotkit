@echo off
set VM_NAME=sandbox_f29
set START_SCRIPT=/vagrant/run.sh vagrant

echo ### Halting VM ###
vagrant halt %VM_NAME%

echo ### Starting VM using Vagrant ###
vagrant up %VM_NAME%
IF %ERRORLEVEL% NEQ 0 (
  echo ### Failed to start VM. Exiting... ###
  pause
  exit /b %ERRORLEVEL%
)

echo ### Running IoT Sandbox inside VM ###
vagrant ssh %VM_NAME% -c "%START_SCRIPT%"

echo ### Halting VM ###
vagrant halt %VM_NAME%
pause
