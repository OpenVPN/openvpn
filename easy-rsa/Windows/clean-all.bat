@echo off
rem move to the HOME directory specified in VARS script
cd %HOME%
rem set a temporary KEY_DIR variable
set d=%KEY_DIR%
rem delete the KEY_DIR and any subdirs quietly
rmdir /s /q %d%
rem make a new KEY_DIR
mkdir %d%
rem copy in a fesh index file so we begin with an empty database
copy index.txt.start %d%\index.txt
rem copy in a fresh serial file so we begin generating keys at index 01
copy serial.start %d%\serial.
