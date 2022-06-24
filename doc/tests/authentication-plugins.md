# TESTING OF MULTIPLE AUTHENTICATION PLUG-INS


OpenVPN 2.x can support loading and authenticating users through multiple
plug-ins at the same time.  But it can only support a single plug-in doing
deferred authentication.  However, a plug-in supporting deferred
authentication may be accompanied by other authentication plug-ins **not**
doing deferred authentication.

This is a test script useful to test the various combinations and order of
plug-in execution.

The configuration files are expected to be used from the root of the build
directory.

To build the needed authentication plug-in, run:

     make -C sample/sample-plugins


## Test configs

* Client config

      verb 4
      dev tun
      client
      remote x.x.x.x
      ca sample/sample-keys/ca.crt
      cert sample/sample-keys/client.crt
      key sample/sample-keys/client.key
      auth-user-pass

* Base server config (`base-server.conf`)

      verb 4
      dev tun
      server 10.8.0.0 255.255.255.0
      dh sample/sample-keys/dh2048.pem
      ca sample/sample-keys/ca.crt
      cert sample/sample-keys/server.crt
      key sample/sample-keys/server.key


## Test cases

### Test: *sanity-1*

This tests the basic authentication with an instant answer.

     config base-server.conf
     plugin multi-auth.so S1.1 0 foo bar

#### Expected results
 - Username/password `foo`/`bar`: **PASS**
 - Anything else: **FAIL**


### Test: *sanity-2*

This is similar to `sanity-1`, but does the authentication
through two plug-ins providing an instant reply.

     config base-server.conf
     plugin multi-auth.so S2.1 0 foo bar
     plugin multi-auth.so S2.2 0 foo bar

#### Expected results
 - Username/password `foo`/`bar`: **PASS**
 - Anything else: **FAIL**


### Test: *sanity-3*

This is also similar to `sanity-1`, but uses deferred authentication
with a 1 second delay on the response.

     plugin multi-auth.so S3.1 1000 foo bar

#### Expected results
 - Username/password `foo`/`bar`: **PASS**
 - Anything else: **FAIL**


### Test: *case-a*

Runs two authentications, the first one deferred by 1 second and the
second one providing an instant response.

     plugin multi-auth.so A.1 1000 foo bar
     plugin multi-auth.so A.2 0 foo bar

#### Expected results
 - Username/password `foo`/`bar`: **PASS**
 - Anything else: **FAIL**


### Test: *case-b*

This is similar to `case-a`, but the instant authentication response
is provided first before the deferred authentication.

     plugin multi-auth.so B.1 0 foo bar
     plugin multi-auth.so B.2 1000 test pass

#### Expected results
 - **Always FAIL**
 - This test should never pass, as each plug-in expects different
   usernames and passwords.


### Test: *case-c*

This is similar to the two prior tests, but the authentication result
is returned instantly in both steps.

     plugin multi-auth.so C.1 0 foo bar
     plugin multi-auth.so C.2 0 foo2 bar2

#### Expected results
 - **Always FAIL**
 - This test should never pass, as each plug-in expects different
   usernames and passwords.


### Test: *case-d*

This is similar to the `case-b` test, but the order of deferred
and instant response is reversed.

    plugin ./multi-auth.so D.1 2000 test pass
    plugin ./multi-auth.so D.2 0 foo bar

#### Expected results
 - **Always FAIL**
 - This test should never pass, as each plug-in expects different
   usernames and passwords.


### Test: *case-e*

This test case will run two deferred authentication plug-ins.  This is
**not** supported by OpenVPN, and should therefore fail instantly.

    plugin ./multi-auth.so E1 1000 test1 pass1
    plugin ./multi-auth.so E2 2000 test2 pass2

#### Expected results
 - The OpenVPN server process should stop running
 - An error about multiple deferred plug-ins being configured
   should be seen in the server log.
