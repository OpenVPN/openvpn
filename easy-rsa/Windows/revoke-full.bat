@echo off
cd %HOME%
rem revoke cert
openssl ca -revoke %KEY_DIR%\%1.crt -config %KEY_CONFIG%
rem generate new crl
openssl ca -gencrl -out %KEY_DIR%\crl.pem -config %KEY_CONFIG%
rem test revocation
rem first concatinate ca cert with newly generated crl
copy %KEY_DIR%\ca.crt+%KEY_DIR%\crl.pem %KEY_DIR%\revoke_test_file.pem
rem now verify the revocation
openssl verify -CAfile %KEY_DIR%\revoke_test_file.pem -crl_check %KEY_DIR%\%1.crt
rem delete temporary test file
del /q %KEY_DIR%\revoke_test_file.pem
