OpenVPN Interactive Service Notes
=================================


Introduction
------------

OpenVPN Interactive Service, also known as "iservice" or
"OpenVPNServiceInteractive", is a Windows system service which allows
unprivileged openvpn.exe process to do certain privileged operations, such as
adding routes. This removes the need to always run OpenVPN as administrator,
which was the case for a long time, and continues to be the case for OpenVPN
2.3.x.

The 2.4.x release and git "master" versions of OpenVPN contain the Interactive
Service code and OpenVPN-GUI is setup to use it by default. Starting from
version 2.4.0, OpenVPN-GUI is expected to be started as user (do not right-click
and "run as administrator" or do not set the shortcut to run as administrator).
This ensures that OpenVPN and the GUI run with limited privileges.


How It Works
------------

Here is a brief explanation of how the Interactive Service works, based on
`Gert's email`_ to openvpn-devel mailing list. The example user, *joe*, is not
an administrator, and does not have any other extra privileges.

- OpenVPN-GUI runs as user *joe*.

- Interactive Service runs as a local Windows service with maximum privileges.

- OpenVPN-GUI connects to the Interactive Service and asks it to "run
  openvpn.exe with the given command line options".

- Interactive Service starts openvpn.exe process as user *joe*, and keeps a
  service pipe between Interactive Service and openvpn.exe.

- When openvpn.exe wants to perform any operation that require elevation (e.g.
  ipconfig, route, configure DNS), it sends a request over the service pipe to
  the Interactive Service, which will then execute it (and clean up should
  openvpn.exe crash).

- ``--up`` scripts are run by openvpn.exe itself, which is running as user
  *joe*, all privileges are nicely in place.

- Scripts run by the GUI will run as user *joe*, so that automated tasks like
  mapping of drives work as expected.

This avoids the use of scripts for privilege escalation (as was possible by
running an ``--up`` script from openvpn.exe which is run as administrator).


Client-Service Communication
----------------------------

Connecting
~~~~~~~~~~

The client (OpenVPN GUI) and the Interactive Service communicate using a named
message pipe. By default, the service provides the ``\\.\pipe\openvpn\service``
named pipe.

The client connects to the pipe for read/write and sets the pipe state to
``PIPE_READMODE_MESSAGE``::

   HANDLE pipe = CreateFile(_T("\\\\.\\pipe\\openvpn\\service"),
       GENERIC_READ | GENERIC_WRITE,
       0,
       NULL,
       OPEN_EXISTING,
       FILE_FLAG_OVERLAPPED,
       NULL);

   if (pipe == INVALID_HANDLE_VALUE)
   {
       // Error
   }

   DWORD dwMode = PIPE_READMODE_MESSAGE;
   if (!SetNamedPipeHandleState(pipe, &dwMode, NULL, NULL)
   {
       // Error
   }


openvpn.exe Startup
~~~~~~~~~~~~~~~~~~~

After the client is connected to the service, the client must send a startup
message to have the service start the openvpn.exe process. The startup message
is comprised of three UTF-16 strings delimited by U0000 zero characters::

   startupmsg     = workingdir WZERO openvpnoptions WZERO stdin WZERO

   workingdir     = WSTRING
   openvpnoptions = WSTRING
   stdin          = WSTRING

   WSTRING        = *WCHAR
   WCHAR          = %x0001-FFFF
   WZERO          = %x0000

``workingdir``
   Represents the folder openvpn.exe process should be started in.

``openvpnoptions``
   String contains ``--config`` and other OpenVPN command line options, without
   the ``argv[0]`` executable name ("openvpn" or "openvpn.exe"). When there is
   only one option specified, the ``--config`` option is assumed and the option
   is the configuration filename.

   Note that the interactive service validates the options. OpenVPN
   configuration file must reside in the configuration folder defined by
   ``config_dir`` registry value. The configuration file can also reside in any
   subfolder of the configuration folder. For all other folders the invoking
   user must be a member of local Administrators group, or a member of the group
   defined by ``ovpn_admin_group`` registry value ("OpenVPN Administrators" by
   default).

``stdin``
   The content of the ``stdin`` string is sent to the openvpn.exe process to its
   stdin stream after it starts.

   When a ``--management ... stdin`` option is present, the openvpn.exe process
   will prompt for the management interface password on start. In this case, the
   ``stdin`` must contain the password appended with an LF (U000A) to simulate
   the [Enter] key after the password is "typed" in.

   The openvpn.exe's stdout is redirected to ``NUL``. Should the client require
   openvpn.exe's stdout, one should specify ``--log`` option.

The message must be written in a single ``WriteFile()`` call.

Example::

   // Prepare the message.
   size_t msg_len =
       wcslen(workingdir) + 1 +
       wcslen(options   ) + 1 +
       wcslen(manage_pwd) + 1;
   wchar_t *msg_data = (wchar_t*)malloc(msg_len*sizeof(wchar_t));
   _snwprintf(msg_data, msg_len, L"%s%c%s%c%s",
       workingdir, L'\0',
       options, L'\0',
       manage_pwd)

   // Send the message.
   DWORD dwBytesWritten;
   if (!WriteFile(pipe,
       msg_data,
       msg_len*sizeof(wchar_t),
       &dwBytesWritten,
       NULL))
   {
       // Error
   }

   // Sanitize memory, since the stdin component of the message
   // contains the management interface password.
   SecureZeroMemory(msg_data, msg_len*sizeof(wchar_t));
   free(msg_data);


openvpn.exe Process ID
~~~~~~~~~~~~~~~~~~~~~~

After receiving the startup message, the Interactive Service validates the user
and specified options before launching the openvpn.exe process.

The Interactive Service replies with a process ID message. The process ID
message is comprised of three UTF-16 strings delimited by LFs (U000A)::

   pidmsg  = L"0x00000000" WLF L"0x" pid WLF L"Process ID"

   pid     = 8*8WHEXDIG

   WHEXDIG = WDIGIT / L"A" / L"B" / L"C" / L"D" / L"E" / L"F"
   WDIGIT  = %x0030-0039
   WLF     = %x000a

``pid``
   A UTF-16 eight-character hexadecimal process ID of the openvpn.exe process
   the Interactive Service launched on client's behalf.


openvpn.exe Monitoring and Termination
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the openvpn.exe process is launched, the client can disconnect the pipe to
the interactive service. However, it should monitor the openvpn.exe process
itself. OpenVPN Management Interface is recommended for this.

The client may choose to stay connected to the pipe. When the openvpn.exe
process terminates, the service disconnects the pipe. Should the openvpn.exe
process terminate with an error, the service sends an error message to the
client before disconnecting the pipe.

Note that Interactive Service terminates all child openvpn.exe processes when
the service is stopped or restarted. This allows a graceful elevation-required
clean-up (e.g. restore ipconfig, route, DNS).


Error Messages
~~~~~~~~~~~~~~

In case of an error, the Interactive Service sends an error message to the
client. Error messages are comprised of three UTF-16 strings delimited by LFs
(U000A)::

   errmsg = L"0x" errnum WLF func WLF msg

   errnum = 8*8WHEXDIG
   func   = WSTRING
   msg    = WSTRING

``errnum``
   A UTF-16 eight-character hexadecimal error code. Typically, it is one of the
   Win32 error codes returned by ``GetLastError()``.

   However, it can be one of the Interactive Service specific error codes:

   ===================== ==========
   Error                 Code
   ===================== ==========
   ERROR_OPENVPN_STARTUP 0x20000000
   ERROR_STARTUP_DATA    0x20000001
   ERROR_MESSAGE_DATA    0x20000002
   ERROR_MESSAGE_TYPE    0x20000003
   ===================== ==========

``func``
   The name of the function call that failed or an error description.

``msg``
  The error description returned by a
  ``FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM, 0, errnum, ...)`` call.


Interactive Service Configuration
---------------------------------

The Interactive Service settings are read from the
``HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN`` registry key by default.

All the following registry values are of the ``REG_SZ`` type:

*Default*
   Installation folder (required, hereinafter ``install_dir``)

``exe_path``
   The absolute path to the openvpn.exe binary; defaults to
   ``install_dir "\bin\openvpn.exe"``.

``config_dir``
   The path to the configuration folder; defaults to ``install_dir "\config"``.

``priority``
   openvpn.exe process priority; one of the following strings:

   - ``"IDLE_PRIORITY_CLASS"``
   - ``"BELOW_NORMAL_PRIORITY_CLASS"``
   - ``"NORMAL_PRIORITY_CLASS"`` (default)
   - ``"ABOVE_NORMAL_PRIORITY_CLASS"``
   - ``"HIGH_PRIORITY_CLASS"``

``ovpn_admin_group``
   The name of the local group, whose members are authorized to use the
   Interactive Service unrestricted; defaults to ``"OpenVPN Administrators"``


Multiple Interactive Service Instances
--------------------------------------

OpenVPN 2.4.5 extended the Interactive Service to support multiple side-by-side
running instances. This allows clients to use different Interactive Service
versions with different settings and/or openvpn.exe binary version on the same
computer.

OpenVPN installs the default Interactive Service instance only. The default
instance is used by OpenVPN GUI client and also provides backward compatibility.


Installing a Non-default Interactive Service Instance
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. Choose a unique instance name. For example: "$v2.5-test". The instance name
   is appended to the default registry path and service name. We choose to start
   it with a dollar "$" sign analogous to Microsoft SQL Server instance naming
   scheme. However, this is not imperative.

   Appending the name to the registry path and service name also implies the
   name cannot contain characters not allowed in Windows paths: "<", ">", double
   quote etc.

2. Create an ``HKEY_LOCAL_MACHINE\SOFTWARE\OpenVPN$v2.5-test`` registry key and
   configure the Interactive Service instance configuration appropriately.

   This allows using slightly or completely different settings from the default
   instance.

   See the `Interactive Service Configuration`_ section for the list of registry
   values.

3. Create and start the instance's Windows service from an elevated command
   prompt::

      sc create "OpenVPNServiceInteractive$v2.5-test" \
         start= auto \
         binPath= "<path to openvpnserv.exe> -instance interactive $v2.5-test" \
         depend= tap0901/Dhcp \
         DisplayName= "OpenVPN Interactive Service (v2.5-test)"

      sc start "OpenVPNServiceInteractive$v2.5-test"

   This allows using the same or a different version of openvpnserv.exe than the
   default instance.

   Note the space after "=" character in ``sc`` command line options.

4. Set your OpenVPN client to connect to the
   ``\\.\pipe\openvpn$v2.5-test\service``.

   This allows the client to select a different installed Interactive Service
   instance at run-time, thus allowing different OpenVPN settings and versions.

   At the time writing, the OpenVPN GUI client supports connecting to the
   default Interactive Service instance only.

.. _`Gert's email`: https://www.mail-archive.com/openvpn-devel@lists.sourceforge.net/msg00097.html
