@echo off
cd %HOME%
rem build a dh file for the server side
openssl dhparam -out %KEY_DIR%/dh%KEY_SIZE%.pem %KEY_SIZE%
