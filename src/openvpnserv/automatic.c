/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2022 OpenVPN Inc <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This program allows one or more OpenVPN processes to be started
 * as a service.  To build, you must get the service sample from the
 * Platform SDK and replace Simple.c with this file.
 *
 * You should also apply service.patch to
 * service.c and service.h from the Platform SDK service sample.
 *
 * This code is designed to be built with the mingw compiler.
 */

#include "service.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <process.h>

static SERVICE_STATUS_HANDLE service;
static SERVICE_STATUS status = { .dwServiceType = SERVICE_WIN32_SHARE_PROCESS };

openvpn_service_t automatic_service = {
    automatic,
    TEXT(PACKAGE_NAME "ServiceLegacy"),
    TEXT(PACKAGE_NAME " Legacy Service"),
    TEXT(SERVICE_DEPENDENCIES),
    SERVICE_DEMAND_START
};

struct security_attributes
{
    SECURITY_ATTRIBUTES sa;
    SECURITY_DESCRIPTOR sd;
};

static HANDLE exit_event = NULL;

/* clear an object */
#define CLEAR(x) memset(&(x), 0, sizeof(x))


bool
init_security_attributes_allow_all(struct security_attributes *obj)
{
    CLEAR(*obj);

    obj->sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    obj->sa.lpSecurityDescriptor = &obj->sd;
    obj->sa.bInheritHandle = TRUE;
    if (!InitializeSecurityDescriptor(&obj->sd, SECURITY_DESCRIPTOR_REVISION))
    {
        return false;
    }
    if (!SetSecurityDescriptorDacl(&obj->sd, TRUE, NULL, FALSE))
    {
        return false;
    }
    return true;
}

HANDLE
create_event(LPCTSTR name, bool allow_all, bool initial_state, bool manual_reset)
{
    if (allow_all)
    {
        struct security_attributes sa;
        if (!init_security_attributes_allow_all(&sa))
        {
            return NULL;
        }
        return CreateEvent(&sa.sa, (BOOL)manual_reset, (BOOL)initial_state, name);
    }
    else
    {
        return CreateEvent(NULL, (BOOL)manual_reset, (BOOL)initial_state, name);
    }
}

void
close_if_open(HANDLE h)
{
    if (h != NULL)
    {
        CloseHandle(h);
    }
}

static bool
match(const WIN32_FIND_DATA *find, LPCTSTR ext)
{
    if (find->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        return false;
    }

    if (*ext == TEXT('\0'))
    {
        return true;
    }

    /* find the pointer to that last '.' in filename and match ext against the rest */

    const TCHAR *p = _tcsrchr(find->cFileName, TEXT('.'));
    return p && p != find->cFileName && _tcsicmp(p + 1, ext) == 0;
}

/*
 * Modify the extension on a filename.
 */
static bool
modext(LPTSTR dest, size_t size, LPCTSTR src, LPCTSTR newext)
{
    size_t i;

    if (size > 0 && (_tcslen(src) + 1) <= size)
    {
        _tcscpy(dest, src);
        dest [size - 1] = TEXT('\0');
        i = _tcslen(dest);
        while (i-- > 0)
        {
            if (dest[i] == TEXT('\\'))
            {
                break;
            }
            if (dest[i] == TEXT('.'))
            {
                dest[i] = TEXT('\0');
                break;
            }
        }
        if (_tcslen(dest) + _tcslen(newext) + 2 <= size)
        {
            _tcscat(dest, TEXT("."));
            _tcscat(dest, newext);
            return true;
        }
        dest[0] = TEXT('\0');
    }
    return false;
}

static DWORD WINAPI
ServiceCtrlAutomatic(DWORD ctrl_code, DWORD event, LPVOID data, LPVOID ctx)
{
    SERVICE_STATUS *status = ctx;
    switch (ctrl_code)
    {
        case SERVICE_CONTROL_STOP:
            status->dwCurrentState = SERVICE_STOP_PENDING;
            ReportStatusToSCMgr(service, status);
            if (exit_event)
            {
                SetEvent(exit_event);
            }
            return NO_ERROR;

        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;

        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}


VOID WINAPI
ServiceStartAutomaticOwn(DWORD dwArgc, LPTSTR *lpszArgv)
{
    status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ServiceStartAutomatic(dwArgc, lpszArgv);
}


VOID WINAPI
ServiceStartAutomatic(DWORD dwArgc, LPTSTR *lpszArgv)
{
    DWORD error = NO_ERROR;
    settings_t settings;
    TCHAR event_name[256];

    service = RegisterServiceCtrlHandlerEx(automatic_service.name, ServiceCtrlAutomatic, &status);
    if (!service)
    {
        return;
    }

    status.dwCurrentState = SERVICE_START_PENDING;
    status.dwServiceSpecificExitCode = NO_ERROR;
    status.dwWin32ExitCode = NO_ERROR;
    status.dwWaitHint = 3000;

    if (!ReportStatusToSCMgr(service, &status))
    {
        MsgToEventLog(M_ERR, TEXT("ReportStatusToSCMgr #1 failed"));
        goto finish;
    }

    /*
     * Create our exit event
     * This event is initially created in the non-signaled
     * state.  It will transition to the signaled state when
     * we have received a terminate signal from the Service
     * Control Manager which will cause an asynchronous call
     * of ServiceStop below.
     */

    openvpn_sntprintf(event_name, _countof(event_name), TEXT(PACKAGE "%s_exit_1"), service_instance);
    exit_event = create_event(event_name, false, false, true);
    if (!exit_event)
    {
        MsgToEventLog(M_ERR, TEXT("CreateEvent failed"));
        goto finish;
    }

    /*
     * If exit event is already signaled, it means we were not
     * shut down properly.
     */
    if (WaitForSingleObject(exit_event, 0) != WAIT_TIMEOUT)
    {
        MsgToEventLog(M_ERR, TEXT("Exit event is already signaled -- we were not shut down properly"));
        goto finish;
    }

    if (!ReportStatusToSCMgr(service, &status))
    {
        MsgToEventLog(M_ERR, TEXT("ReportStatusToSCMgr #2 failed"));
        goto finish;
    }

    /*
     * Read info from registry in key HKLM\SOFTWARE\OpenVPN
     */
    error = GetOpenvpnSettings(&settings);
    if (error != ERROR_SUCCESS)
    {
        goto finish;
    }

    /*
     * Instantiate an OpenVPN process for each configuration
     * file found.
     */
    {
        WIN32_FIND_DATA find_obj;
        HANDLE find_handle;
        BOOL more_files;
        TCHAR find_string[MAX_PATH];

        openvpn_sntprintf(find_string, MAX_PATH, TEXT("%s\\*"), settings.config_dir);

        find_handle = FindFirstFile(find_string, &find_obj);
        if (find_handle == INVALID_HANDLE_VALUE)
        {
            MsgToEventLog(M_ERR, TEXT("Cannot get configuration file list using: %s"), find_string);
            goto finish;
        }

        /*
         * Loop over each config file
         */
        do
        {
            HANDLE log_handle = NULL;
            STARTUPINFO start_info;
            PROCESS_INFORMATION proc_info;
            struct security_attributes sa;
            TCHAR log_file[MAX_PATH];
            TCHAR log_path[MAX_PATH];
            TCHAR command_line[256];

            CLEAR(start_info);
            CLEAR(proc_info);
            CLEAR(sa);

            if (!ReportStatusToSCMgr(service, &status))
            {
                MsgToEventLog(M_ERR, TEXT("ReportStatusToSCMgr #3 failed"));
                FindClose(find_handle);
                goto finish;
            }

            /* does file have the correct type and extension? */
            if (match(&find_obj, settings.ext_string))
            {
                /* get log file pathname */
                if (!modext(log_file, _countof(log_file), find_obj.cFileName, TEXT("log")))
                {
                    MsgToEventLog(M_ERR, TEXT("Cannot construct logfile name based on: %s"), find_obj.cFileName);
                    FindClose(find_handle);
                    goto finish;
                }
                openvpn_sntprintf(log_path, _countof(log_path),
                                  TEXT("%s\\%s"), settings.log_dir, log_file);

                /* construct command line */
                openvpn_sntprintf(command_line, _countof(command_line), TEXT("openvpn --service \"" PACKAGE "%s_exit_1\" 1 --config \"%s\""),
                                  service_instance,
                                  find_obj.cFileName);

                /* Make security attributes struct for logfile handle so it can
                 * be inherited. */
                if (!init_security_attributes_allow_all(&sa))
                {
                    error = MsgToEventLog(M_SYSERR, TEXT("InitializeSecurityDescriptor start_" PACKAGE " failed"));
                    goto finish;
                }

                /* open logfile as stdout/stderr for soon-to-be-spawned subprocess */
                log_handle = CreateFile(log_path,
                                        GENERIC_WRITE,
                                        FILE_SHARE_READ,
                                        &sa.sa,
                                        settings.append ? OPEN_ALWAYS : CREATE_ALWAYS,
                                        FILE_ATTRIBUTE_NORMAL,
                                        NULL);

                if (log_handle == INVALID_HANDLE_VALUE)
                {
                    error = MsgToEventLog(M_SYSERR, TEXT("Cannot open logfile: %s"), log_path);
                    FindClose(find_handle);
                    goto finish;
                }

                /* append to logfile? */
                if (settings.append)
                {
                    if (SetFilePointer(log_handle, 0, NULL, FILE_END) == INVALID_SET_FILE_POINTER)
                    {
                        error = MsgToEventLog(M_SYSERR, TEXT("Cannot seek to end of logfile: %s"), log_path);
                        FindClose(find_handle);
                        goto finish;
                    }
                }

                /* fill in STARTUPINFO struct */
                GetStartupInfo(&start_info);
                start_info.cb = sizeof(start_info);
                start_info.dwFlags = STARTF_USESTDHANDLES|STARTF_USESHOWWINDOW;
                start_info.wShowWindow = SW_HIDE;
                start_info.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
                start_info.hStdOutput = start_info.hStdError = log_handle;

                /* create an OpenVPN process for one config file */
                if (!CreateProcess(settings.exe_path,
                                   command_line,
                                   NULL,
                                   NULL,
                                   TRUE,
                                   settings.priority | CREATE_NEW_CONSOLE,
                                   NULL,
                                   settings.config_dir,
                                   &start_info,
                                   &proc_info))
                {
                    error = MsgToEventLog(M_SYSERR, TEXT("CreateProcess failed, exe='%s' cmdline='%s' dir='%s'"),
                                          settings.exe_path,
                                          command_line,
                                          settings.config_dir);

                    FindClose(find_handle);
                    CloseHandle(log_handle);
                    goto finish;
                }

                /* close unneeded handles */
                Sleep(1000); /* try to prevent race if we close logfile
                              * handle before child process DUPs it */
                if (!CloseHandle(proc_info.hProcess)
                    || !CloseHandle(proc_info.hThread)
                    || !CloseHandle(log_handle))
                {
                    error = MsgToEventLog(M_SYSERR, TEXT("CloseHandle failed"));
                    goto finish;
                }
            }

            /* more files to process? */
            more_files = FindNextFile(find_handle, &find_obj);

        } while (more_files);

        FindClose(find_handle);
    }

    /* we are now fully started */
    status.dwCurrentState = SERVICE_RUNNING;
    status.dwWaitHint = 0;
    if (!ReportStatusToSCMgr(service, &status))
    {
        MsgToEventLog(M_ERR, TEXT("ReportStatusToSCMgr SERVICE_RUNNING failed"));
        goto finish;
    }

    /* wait for our shutdown signal */
    if (WaitForSingleObject(exit_event, INFINITE) != WAIT_OBJECT_0)
    {
        MsgToEventLog(M_ERR, TEXT("wait for shutdown signal failed"));
    }

finish:
    if (exit_event)
    {
        CloseHandle(exit_event);
    }

    status.dwCurrentState = SERVICE_STOPPED;
    status.dwWin32ExitCode = error;
    ReportStatusToSCMgr(service, &status);
}
