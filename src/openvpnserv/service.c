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
        MsgToEventLog(MSG_FLAGS_ERROR, L"SetServiceStatus");
    }

    return res;
}

static int
CmdInstallServices(void)
{
    SC_HANDLE service;
    SC_HANDLE svc_ctl_mgr;
    WCHAR path[512];
    int i, ret = _service_max;

    if (GetModuleFileName(NULL, path + 1, _countof(path) - 2) == 0)
    {
        wprintf(L"Unable to install service - %ls\n", GetLastErrorText());
        return 1;
    }

    path[0] = L'\"';
    wcscat_s(path, _countof(path), L"\"");

    svc_ctl_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (svc_ctl_mgr == NULL)
    {
        wprintf(L"OpenSCManager failed - %ls\n", GetLastErrorText());
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
            wprintf(L"%ls installed.\n", openvpn_service[i].display_name);
            CloseServiceHandle(service);
            --ret;
        }
        else
        {
            wprintf(L"CreateService failed - %ls\n", GetLastErrorText());
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
        wprintf(L"OpenSCManager failed - %ls\n", GetLastErrorText());
        return 1;
    }

    service = OpenService(svc_ctl_mgr, openvpn_service[type].name, SERVICE_ALL_ACCESS);
    if (service)
    {
        if (StartService(service, 0, NULL))
        {
            wprintf(L"Service Started\n");
            ret = 0;
        }
        else
        {
            wprintf(L"StartService failed - %ls\n", GetLastErrorText());
        }

        CloseServiceHandle(service);
    }
    else
    {
        wprintf(L"OpenService failed - %ls\n", GetLastErrorText());
    }

    CloseServiceHandle(svc_ctl_mgr);
    return ret;
}


static int
CmdRemoveServices(void)
{
    SC_HANDLE service;
    SC_HANDLE svc_ctl_mgr;
    SERVICE_STATUS status;
    int i, ret = _service_max;

    svc_ctl_mgr = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (svc_ctl_mgr == NULL)
    {
        wprintf(L"OpenSCManager failed - %ls\n", GetLastErrorText());
        return 1;
    }

    for (i = 0; i < _service_max; i++)
    {
        openvpn_service_t *ovpn_svc = &openvpn_service[i];
        service = OpenService(svc_ctl_mgr, ovpn_svc->name,
                              DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS);
        if (service == NULL)
        {
            wprintf(L"OpenService failed - %ls\n", GetLastErrorText());
            goto out;
        }

        /* try to stop the service */
        if (ControlService(service, SERVICE_CONTROL_STOP, &status))
        {
            wprintf(L"Stopping %ls.", ovpn_svc->display_name);
            Sleep(1000);

            while (QueryServiceStatus(service, &status))
            {
                if (status.dwCurrentState == SERVICE_STOP_PENDING)
                {
                    wprintf(L".");
                    Sleep(1000);
                }
                else
                {
                    break;
                }
            }

            if (status.dwCurrentState == SERVICE_STOPPED)
            {
                wprintf(L"\n%ls stopped.\n", ovpn_svc->display_name);
            }
            else
            {
                wprintf(L"\n%ls failed to stop.\n", ovpn_svc->display_name);
            }
        }

        /* now remove the service */
        if (DeleteService(service))
        {
            wprintf(L"%ls removed.\n", ovpn_svc->display_name);
            --ret;
        }
        else
        {
            wprintf(L"DeleteService failed - %ls\n", GetLastErrorText());
        }

        CloseServiceHandle(service);
    }

out:
    CloseServiceHandle(svc_ctl_mgr);
    return ret;
}


int
wmain(int argc, WCHAR *argv[])
{
    /*
     * Interactive service (as a SERVICE_WIN32_SHARE_PROCESS)
     * This is the default.
     */
    const SERVICE_TABLE_ENTRY dispatchTable_shared[] = {
        { interactive_service.name, ServiceStartInteractive },
        { NULL, NULL }
    };

    /* Interactive service only (as a SERVICE_WIN32_OWN_PROCESS) */
    const SERVICE_TABLE_ENTRY dispatchTable_interactive[] = {
        { L"", ServiceStartInteractiveOwn },
        { NULL, NULL }
    };

    const SERVICE_TABLE_ENTRY *dispatchTable = dispatchTable_shared;

    openvpn_service[interactive] = interactive_service;

    for (int i = 1; i < argc; i++)
    {
        if (*argv[i] == L'-' || *argv[i] == L'/')
        {
            if (_wcsicmp(L"install", argv[i] + 1) == 0)
            {
                return CmdInstallServices();
            }
            else if (_wcsicmp(L"remove", argv[i] + 1) == 0)
            {
                return CmdRemoveServices();
            }
            else if (_wcsicmp(L"start", argv[i] + 1) == 0)
            {
                return CmdStartService(interactive);
            }
            else if (argc > i + 2 && _wcsicmp(L"instance", argv[i] + 1) == 0)
            {
                if (_wcsicmp(L"interactive", argv[i+1]) == 0)
                {
                    dispatchTable = dispatchTable_interactive;
                    service_instance = argv[i + 2];
                    i += 2;
                }
                else
                {
                    MsgToEventLog(M_ERR, L"Invalid argument to -instance <%s>. Service not started.", argv[i+1]);
                    return 1;
                }
            }
            else
            {
                wprintf(L"%ls -install        to install the interactive service\n", APPNAME);
                wprintf(L"%ls -start [name]   to start the service (name = \"interactive\") is optional\n", APPNAME);
                wprintf(L"%ls -remove         to remove the service\n", APPNAME);

                wprintf(L"\nService run-time parameters:\n");
                wprintf(L"-instance interactive <id>\n"
                        L"   Runs the service as an alternate instance.\n"
                        L"   The service settings will be loaded from\n"
                        L"   HKLM\\Software\\" _L(PACKAGE_NAME) L"<id> registry key, and the service will accept\n"
                        L"   requests on \\\\.\\pipe\\" _L(PACKAGE) L"<id>\\service named pipe.\n");

                return 0;
            }
        }
    }

    /* If it doesn't match any of the above parameters
     * the service control manager may be starting the service
     * so we must call StartServiceCtrlDispatcher
     */
    wprintf(L"\nStartServiceCtrlDispatcher being called.\n");
    wprintf(L"This may take several seconds. Please wait.\n");

    if (!StartServiceCtrlDispatcher(dispatchTable))
    {
        MsgToEventLog(MSG_FLAGS_ERROR, L"StartServiceCtrlDispatcher failed.");
    }

    return 0;
}
