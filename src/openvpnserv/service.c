/*
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
 * ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * Copyright (C) 1993 - 2000.  Microsoft Corporation.  All rights reserved.
 *                      2013 Heiko Hund <heiko.hund@sophos.com>
 */

#include "service.h"

#include <windows.h>
#include <stdio.h>
#include <process.h>


openvpn_service_t openvpn_service[_service_max];


BOOL
ReportStatusToSCMgr(SERVICE_STATUS_HANDLE service, SERVICE_STATUS *status)
{
    static DWORD dwCheckPoint = 1;
    BOOL res = TRUE;

    if (status->dwCurrentState == SERVICE_START_PENDING)
    {
        status->dwControlsAccepted = 0;
    }
    else
    {
        status->dwControlsAccepted = SERVICE_ACCEPT_STOP;
    }

    if (status->dwCurrentState == SERVICE_RUNNING
        || status->dwCurrentState == SERVICE_STOPPED)
    {
        status->dwCheckPoint = 0;
    }
    else
    {
        status->dwCheckPoint = dwCheckPoint++;
    }

    /* Report the status of the service to the service control manager. */
    res = SetServiceStatus(service, status);
    if (!res)
    {
        MsgToEventLog(MSG_FLAGS_ERROR, TEXT("SetServiceStatus"));
    }

    return res;
}

static int
CmdInstallServices()
{
    SC_HANDLE service;
    SC_HANDLE svc_ctl_mgr;
    TCHAR path[512];
    int i, ret = _service_max;

    if (GetModuleFileName(NULL, path + 1, 510) == 0)
    {
        _tprintf(TEXT("Unable to install service - %s\n"), GetLastErrorText());
        return 1;
    }

    path[0] = TEXT('\"');
    _tcscat(path, TEXT("\""));

    svc_ctl_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (svc_ctl_mgr == NULL)
    {
        _tprintf(TEXT("OpenSCManager failed - %s\n"), GetLastErrorText());
        return 1;
    }

    for (i = 0; i < _service_max; i++)
    {
        service = CreateService(svc_ctl_mgr,
                                openvpn_service[i].name,
                                openvpn_service[i].display_name,
                                SERVICE_QUERY_STATUS,
                                SERVICE_WIN32_SHARE_PROCESS,
                                openvpn_service[i].start_type,
                                SERVICE_ERROR_NORMAL,
                                path, NULL, NULL,
                                openvpn_service[i].dependencies,
                                NULL, NULL);
        if (service)
        {
            _tprintf(TEXT("%s installed.\n"), openvpn_service[i].display_name);
            CloseServiceHandle(service);
            --ret;
        }
        else
        {
            _tprintf(TEXT("CreateService failed - %s\n"), GetLastErrorText());
        }
    }

    CloseServiceHandle(svc_ctl_mgr);
    return ret;
}


static int
CmdStartService(openvpn_service_type type)
{
    int ret = 1;
    SC_HANDLE svc_ctl_mgr;
    SC_HANDLE service;

    svc_ctl_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (svc_ctl_mgr == NULL)
    {
        _tprintf(TEXT("OpenSCManager failed - %s\n"), GetLastErrorText());
        return 1;
    }

    service = OpenService(svc_ctl_mgr, openvpn_service[type].name, SERVICE_ALL_ACCESS);
    if (service)
    {
        if (StartService(service, 0, NULL))
        {
            _tprintf(TEXT("Service Started\n"));
            ret = 0;
        }
        else
        {
            _tprintf(TEXT("StartService failed - %s\n"), GetLastErrorText());
        }

        CloseServiceHandle(service);
    }
    else
    {
        _tprintf(TEXT("OpenService failed - %s\n"), GetLastErrorText());
    }

    CloseServiceHandle(svc_ctl_mgr);
    return ret;
}


static int
CmdRemoveServices()
{
    SC_HANDLE service;
    SC_HANDLE svc_ctl_mgr;
    SERVICE_STATUS status;
    int i, ret = _service_max;

    svc_ctl_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (svc_ctl_mgr == NULL)
    {
        _tprintf(TEXT("OpenSCManager failed - %s\n"), GetLastErrorText());
        return 1;
    }

    for (i = 0; i < _service_max; i++)
    {
        openvpn_service_t *ovpn_svc = &openvpn_service[i];
        service = OpenService(svc_ctl_mgr, ovpn_svc->name,
                              DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (service == NULL)
        {
            _tprintf(TEXT("OpenService failed - %s\n"), GetLastErrorText());
            goto out;
        }

        /* try to stop the service */
        if (ControlService(service, SERVICE_CONTROL_STOP, &status))
        {
            _tprintf(TEXT("Stopping %s."), ovpn_svc->display_name);
            Sleep(1000);

            while (QueryServiceStatus(service, &status))
            {
                if (status.dwCurrentState == SERVICE_STOP_PENDING)
                {
                    _tprintf(TEXT("."));
                    Sleep(1000);
                }
                else
                {
                    break;
                }
            }

            if (status.dwCurrentState == SERVICE_STOPPED)
            {
                _tprintf(TEXT("\n%s stopped.\n"), ovpn_svc->display_name);
            }
            else
            {
                _tprintf(TEXT("\n%s failed to stop.\n"), ovpn_svc->display_name);
            }
        }

        /* now remove the service */
        if (DeleteService(service))
        {
            _tprintf(TEXT("%s removed.\n"), ovpn_svc->display_name);
            --ret;
        }
        else
        {
            _tprintf(TEXT("DeleteService failed - %s\n"), GetLastErrorText());
        }

        CloseServiceHandle(service);
    }

out:
    CloseServiceHandle(svc_ctl_mgr);
    return ret;
}


int
_tmain(int argc, TCHAR *argv[])
{
    /*
     * Automatic + Interactive service (as a SERVICE_WIN32_SHARE_PROCESS)
     * This is the default.
     */
    const SERVICE_TABLE_ENTRY dispatchTable_shared[] = {
        { automatic_service.name, ServiceStartAutomatic },
        { interactive_service.name, ServiceStartInteractive },
        { NULL, NULL }
    };

    /* Automatic service only (as a SERVICE_WIN32_OWN_PROCESS) */
    const SERVICE_TABLE_ENTRY dispatchTable_automatic[] = {
        { TEXT(""), ServiceStartAutomaticOwn },
        { NULL, NULL }
    };

    /* Interactive service only (as a SERVICE_WIN32_OWN_PROCESS) */
    const SERVICE_TABLE_ENTRY dispatchTable_interactive[] = {
        { TEXT(""), ServiceStartInteractiveOwn },
        { NULL, NULL }
    };

    const SERVICE_TABLE_ENTRY *dispatchTable = dispatchTable_shared;

    openvpn_service[0] = automatic_service;
    openvpn_service[1] = interactive_service;

    for (int i = 1; i < argc; i++)
    {
        if (*argv[i] == TEXT('-') || *argv[i] == TEXT('/'))
        {
            if (_tcsicmp(TEXT("install"), argv[i] + 1) == 0)
            {
                return CmdInstallServices();
            }
            else if (_tcsicmp(TEXT("remove"), argv[i] + 1) == 0)
            {
                return CmdRemoveServices();
            }
            else if (_tcsicmp(TEXT("start"), argv[i] + 1) == 0)
            {
                BOOL is_auto = argc < i + 2 || _tcsicmp(TEXT("interactive"), argv[i + 1]) != 0;
                return CmdStartService(is_auto ? automatic : interactive);
            }
            else if (argc > i + 2 && _tcsicmp(TEXT("instance"), argv[i] + 1) == 0)
            {
                dispatchTable = _tcsicmp(TEXT("interactive"), argv[i + 1]) != 0 ?
                                dispatchTable_automatic :
                                dispatchTable_interactive;

                service_instance = argv[i + 2];
                i += 2;
            }
            else
            {
                _tprintf(TEXT("%s -install        to install the services\n"), APPNAME);
                _tprintf(TEXT("%s -start <name>   to start a service (\"automatic\" or \"interactive\")\n"), APPNAME);
                _tprintf(TEXT("%s -remove         to remove the services\n"), APPNAME);

                _tprintf(TEXT("\nService run-time parameters:\n"));
                _tprintf(TEXT("-instance <name> <id>\n")
                         TEXT("   Runs the service as an alternate instance. <name> can be \"automatic\" or\n")
                         TEXT("   \"interactive\". The service settings will be loaded from\n")
                         TEXT("   HKLM\\Software\\" PACKAGE_NAME "<id> registry key, and the interactive service will accept\n")
                         TEXT("   requests on \\\\.\\pipe\\" PACKAGE "<id>\\service named pipe.\n"));

                return 0;
            }
        }
    }

    /* If it doesn't match any of the above parameters
     * the service control manager may be starting the service
     * so we must call StartServiceCtrlDispatcher
     */
    _tprintf(TEXT("\nStartServiceCtrlDispatcher being called.\n"));
    _tprintf(TEXT("This may take several seconds. Please wait.\n"));

    if (!StartServiceCtrlDispatcher(dispatchTable))
    {
        MsgToEventLog(MSG_FLAGS_ERROR, TEXT("StartServiceCtrlDispatcher failed."));
    }

    return 0;
}
