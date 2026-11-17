@echo off
rem Double-click on the Windows laptop whose WSL must accept connections (server or listening peer).
rem Asks for administrator rights, then runs windows-setup.ps1: firewall rules and mirrored WSL networking.
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0windows-setup.ps1\"'"
