@ECHO OFF
cd /d "%~dp0"
SQLitezer.py -i %1 -o %1_report -a -u -c
PAUSE