PKCS#11 / SmartCard options
---------------------------

--pkcs11-cert-private args
  Set if access to certificate object should be performed after login.
  Every provider has its own setting.

  Valid syntaxes:
  ::

     pkcs11-cert-private 0
     pkcs11-cert-private 1

--pkcs11-id name
  Specify the serialized certificate id to be used. The id can be gotten
  by the standalone ``--show-pkcs11-ids`` option. See also the description
  of ``--pkcs11-providers`` option.

--pkcs11-id-management
  Acquire PKCS#11 id from management interface. In this case a
  :code:`NEED-STR 'pkcs11-id-request'` real-time message will be triggered,
  application may use pkcs11-id-count command to retrieve available number of
  certificates, and pkcs11-id-get command to retrieve certificate id and
  certificate body.
  See also the description of ``--pkcs11-providers`` option.

--pkcs11-pin-cache seconds
  Specify how many seconds the PIN can be cached, the default is until the
  token is removed.

--pkcs11-private-mode mode
  Specify which method to use in order to perform private key operations.
  A different mode can be specified for each provider. Mode is encoded as
  hex number, and can be a mask one of the following:

  :code:`0` (default)   Try to determine automatically.

  :code:`1`             Use sign.

  :code:`2`             Use sign recover.

  :code:`4`             Use decrypt.

  :code:`8`             Use unwrap.

--pkcs11-protected-authentication args
  Use PKCS#11 protected authentication path, useful for biometric and
  external keypad devices. Every provider has its own setting.

  Valid syntaxes:
  ::

     pkcs11-protected-authentication 0
     pkcs11-protected-authentication 1

--pkcs11-providers providers
  Specify an RSA Security Inc. PKCS #11 Cryptographic Token Interface
  (Cryptoki) providers to load. A space-separated list of one or more
  provider library names may be specified. This option along with ``--pkcs11-id``
  or ``pkcs11-id-management`` can be used instead of
  ``--cert`` and ``--key`` or ``--pkcs12``.

  If p11-kit is present on the system and was enabled during build, its
  :code:`p11-kit-proxy.so` module will be loaded by default if either
  the ``--pkcs11-id`` or ``--pkcs11-id-management`` options is present without
  ``--pkcs11-providers``. If default loading is not enabled in the build and
  no providers are specified, the former options will be ignored.

--show-pkcs11-ids args
  (Standalone) Show PKCS#11 token object list.

  Valid syntax:
  ::

     show-pkcs11 [provider] [cert_private]

  Specify ``cert_private`` as :code:`1` if certificates are stored as
  private objects.

  If *p11-kit* is present on the system, the ``provider`` argument is
  optional; if omitted the default :code:`p11-kit-proxy.so` module will be
  queried.

  ``--verb`` option can be used BEFORE this option to produce debugging
  information.
