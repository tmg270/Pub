@echo off
rem Grants Lock pages in memory for 2 MiB pages. Run as Administrator once, then SIGN OUT.
razor.exe --enable-huge
pause
