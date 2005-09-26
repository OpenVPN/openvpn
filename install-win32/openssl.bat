REM Build openssl.exe with DLL linkage to OpenSSL library
REM Run this script from top level of OpenSSL source tree
REM eg.: cp /y/openvpn/20/openvpn/install-win32/openssl.bat .

gcc -o openssl  tmp\verify.o tmp\asn1pars.o tmp\req.o tmp\dgst.o tmp\dh.o tmp\dhparam.o tmp\enc.o tmp\passwd.o tmp\gendh.o tmp\errstr.o tmp\ca.o tmp\pkcs7.o tmp\crl2p7.o tmp\crl.o tmp\rsa.o tmp\rsautl.o tmp\dsa.o tmp\dsaparam.o tmp\x509.o tmp\genrsa.o tmp\gendsa.o tmp\s_server.o tmp\s_client.o tmp\speed.o tmp\s_time.o tmp\apps.o tmp\s_cb.o tmp\s_socket.o tmp\app_rand.o tmp\version.o tmp\sess_id.o tmp\ciphers.o tmp\nseq.o tmp\pkcs12.o tmp\pkcs8.o tmp\spkac.o tmp\smime.o tmp\rand.o tmp\engine.o tmp\ocsp.o tmp\prime.o tmp\openssl.o -leay32 -lssl32 -L. -lwsock32 -lgdi32
