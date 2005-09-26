@echo off
cd %HOME%
rem build a request for a cert that will be valid for ten years
openssl req -days 3650 -nodes -new -keyout %KEY_DIR%\%1.key -out %KEY_DIR%\%1.csr -config %KEY_CONFIG%
rem sign the cert request with our ca, creating a cert/key pair
openssl ca -days 3650 -out %KEY_DIR%\%1.crt -in %KEY_DIR%\%1.csr -extensions server -config %KEY_CONFIG%
rem delete any .old files created in this process, to avoid future file creation errors
del /q %KEY_DIR%\*.old
