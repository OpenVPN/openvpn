#!/bin/sh

# Sample script to perform OCSP queries with OpenSSL
# given a certificate serial number.

# If you run your own CA, you can set up a very simple
# OCSP server using the -port option to "openssl ocsp".

# Full documentation and examples:
# http://www.openssl.org/docs/apps/ocsp.html


# Edit the following values to suit your needs

# OCSP responder URL (mandatory)
# YOU MUST UNCOMMENT ONE OF THESE AND SET IT TO A VALID SERVER
#ocsp_url="http://ocsp.example.com/"
#ocsp_url="https://ocsp.secure.example.com/"

# Path to issuer certificate (mandatory)
# YOU MUST SET THIS TO THE PATH TO THE CA CERTIFICATE
issuer="/path/to/CAcert.crt"

# use a nonce in the query, set to "-no_nonce" to not use it
nonce="-nonce"

# Verify the response
# YOU MUST SET THIS TO THE PATH TO THE RESPONSE VERIFICATION CERT
verify="/path/to/CAcert.crt"

# Depth in the certificate chain where the cert to verify is.
# Set to -1 to run the verification at every level (NOTE that
# in that case you need a more complex script as the various
# parameters for the query will likely be different at each level)
# "0" is the usual value here, where the client certificate is
check_depth=0

cur_depth=$1     # this is the *CURRENT* depth
common_name=$2   # CN in case you need it

# minimal sanity checks

err=0
if [ -z "$issuer" ] || [ ! -e "$issuer" ]; then
  echo "Error: issuer certificate undefined or not found!" >&2
  err=1
fi

if [ -z "$verify" ] || [ ! -e "$verify" ]; then
  echo "Error: verification certificate undefined or not found!" >&2
  err=1
fi

if [ -z "$ocsp_url" ]; then
  echo "Error: OCSP server URL not defined!" >&2
  err=1
fi

if [ $err -eq 1 ]; then
  echo "Did you forget to customize the variables in the script?" >&2
  exit 1
fi

# begin
if [ $check_depth -eq -1 ] || [ $cur_depth -eq $check_depth ]; then

  eval serial="\$tls_serial_${cur_depth}"

  # To successfully complete, the following must happen:
  #
  # - The serial number must not be empty
  # - The exit status of "openssl ocsp" must be zero
  # - The output of the above command must contain the line
  #   "0x${serial}: good"
  #
  # Everything else fails with exit status 1.

  if [ -n "$serial" ]; then

    # This is only an example; you are encouraged to run this command (without
    # redirections) manually against your or your CA's OCSP server to see how
    # it responds, and adapt accordingly.
    # Sample output that is assumed here:
    #
    # Response verify OK
    # 0x428740A5: good
    #      This Update: Apr 24 19:38:49 2010 GMT
    #      Next Update: May  2 14:23:42 2010 GMT
    #
    # NOTE: It is needed to check the exit code of OpenSSL explicitly.  OpenSSL
    #       can in some circumstances give a "good" result if it could not
    #       reach the the OSCP server.  In this case, the exit code will indicate
    #       if OpenSSL itself failed or not.  If OpenSSL's exit code is not 0,
    #       don't trust the OpenSSL status.

    status=$(openssl ocsp -issuer "$issuer" \
                    "$nonce" \
                    -CAfile "$verify" \
                    -url "$ocsp_url" \
                    -serial "0x${serial}" 2>/dev/null)

    if [ $? -eq 0 ]; then
      # check that it's good
      if echo "$status" | grep -Fq "0x${serial}: good"; then
        exit 0
      fi
    fi
  fi
  # if we get here, something was wrong
  exit 1
fi
