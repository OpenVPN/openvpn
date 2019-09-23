/*
 *  tapctl -- Utility to manipulate TUN/TAP interfaces on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2018 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2008-2013 David Sommerseth <dazo@users.sourceforge.net>
 *  Copyright (C) 2018 Simon Rozman <simon@rozman.si>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#elif defined(_MSC_VER)
#include <config-msvc.h>
#endif
#ifdef HAVE_CONFIG_VERSION_H
#include <config-version.h>
#endif

#include "tap.h"
#include "error.h"

#include <objbase.h>
#include <setupapi.h>
#include <stdio.h>
#include <tchar.h>

#ifdef _MSC_VER
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#endif


const TCHAR title_string[] =
    TEXT(PACKAGE_NAME) TEXT(" ") TEXT(PACKAGE_VERSION)
    TEXT(" built on ") TEXT(__DATE__)
;

static const TCHAR usage_message[] =
    TEXT("%s\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl <command> [<command specific options>]\n")
    TEXT("\n")
    TEXT("Commands:\n")
    TEXT("\n")
    TEXT("create     Create a new TUN/TAP interface\n")
    TEXT("list       List TUN/TAP interfaces\n")
    TEXT("delete     Delete specified network interface\n")
    TEXT("help       Display this text\n")
    TEXT("\n")
    TEXT("Hint: Use \"tapctl help <command>\" to display help for particular command.\n")
;

static const TCHAR usage_message_create[] =
    TEXT("%s\n")
    TEXT("\n")
    TEXT("Creates a new TUN/TAP interface\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl create [<options>]\n")
    TEXT("\n")
    TEXT("Options:\n")
    TEXT("\n")
    TEXT("--name <name>  Set TUN/TAP interface name. Should the interface with given name\n")
    TEXT("               already exist, an error is returned. If this option is not      \n")
    TEXT("               specified, a default interface name is chosen by Windows.       \n")
    TEXT("               Note: This name can also be specified as OpenVPN's --dev-node   \n")
    TEXT("               option.                                                         \n")
    TEXT("--hwid <hwid>  Interface hardware id. Default value is root\\tap0901, which    \n")
    TEXT("               describes tap-windows6 driver. To work with wintun driver,      \n")
    TEXT("               specify 'wintun'.                                               \n")
    TEXT("Output:\n")
    TEXT("\n")
    TEXT("This command prints newly created TUN/TAP interface's GUID to stdout.          \n")
;

static const TCHAR usage_message_list[] =
    TEXT("%s\n")
    TEXT("\n")
    TEXT("Lists TUN/TAP interfaces\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl list\n")
    TEXT("\n")
    TEXT("Options:\n")
    TEXT("\n")
    TEXT("--hwid <hwid>  Interface hardware id. Default value is root\\tap0901, which    \n")
    TEXT("               describes tap-windows6 driver. To work with wintun driver,      \n")
    TEXT("               specify 'wintun'.                                               \n")
    TEXT("Output:\n")
    TEXT("\n")
    TEXT("This command prints all TUN/TAP interfaces to stdout.                          \n")
;

static const TCHAR usage_message_delete[] =
    TEXT("%s\n")
    TEXT("\n")
    TEXT("Deletes the specified network interface\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl delete <interface GUID | interface name>\n")
;


/**
 * Print the help message.
 */
static void
usage(void)
{
    _ftprintf(stderr,
              usage_message,
              title_string);
}


/**
 * Program entry point
 */
int __cdecl
_tmain(int argc, LPCTSTR argv[])
{
    int iResult;
    BOOL bRebootRequired = FALSE;

    /* Ask SetupAPI to keep quiet. */
    SetupSetNonInteractiveMode(TRUE);

    if (argc < 2)
    {
        usage();
        return 1;
    }
    else if (_tcsicmp(argv[1], TEXT("help")) == 0)
    {
        /* Output help. */
        if (argc < 3)
        {
            usage();
        }
        else if (_tcsicmp(argv[2], TEXT("create")) == 0)
        {
            _ftprintf(stderr, usage_message_create, title_string);
        }
        else if (_tcsicmp(argv[2], TEXT("list")) == 0)
        {
            _ftprintf(stderr, usage_message_list, title_string);
        }
        else if (_tcsicmp(argv[2], TEXT("delete")) == 0)
        {
            _ftprintf(stderr, usage_message_delete, title_string);
        }
        else
        {
            _ftprintf(stderr, TEXT("Unknown command \"%s\". Please, use \"tapctl help\" to list supported commands.\n"), argv[2]);
        }

        return 1;
    }
    else if (_tcsicmp(argv[1], TEXT("create")) == 0)
    {
        LPCTSTR szName = NULL;
        LPCTSTR szHwId = NULL;

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (_tcsicmp(argv[i], TEXT("--name")) == 0)
            {
                szName = argv[++i];
            }
            else
            if (_tcsicmp(argv[i], TEXT("--hwid")) == 0)
            {
                szHwId = argv[++i];
            }
            else
            {
                _ftprintf(stderr, TEXT("Unknown option \"%s\". Please, use \"tapctl help create\" to list supported options. Ignored.\n"), argv[i]);
            }
        }

        /* Create TUN/TAP interface. */
        GUID guidInterface;
        LPOLESTR szInterfaceId = NULL;
        DWORD dwResult = tap_create_interface(
            NULL,
            TEXT("Virtual Ethernet"),
            szHwId,
            &bRebootRequired,
            &guidInterface);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Creating TUN/TAP interface failed (error 0x%x).\n"), dwResult);
            iResult = 1; goto quit;
        }

        if (szName)
        {
            /* Get the list of all available interfaces. */
            struct tap_interface_node *pInterfaceList = NULL;
            dwResult = tap_list_interfaces(NULL, szHwId, &pInterfaceList, TRUE);
            if (dwResult != ERROR_SUCCESS)
            {
                _ftprintf(stderr, TEXT("Enumerating interfaces failed (error 0x%x).\n"), dwResult);
                iResult = 1; goto create_delete_interface;
            }

            /* Check for duplicates. */
            for (struct tap_interface_node *pInterface = pInterfaceList; pInterface; pInterface = pInterface->pNext)
            {
                if (_tcsicmp(szName, pInterface->szName) == 0)
                {
                    StringFromIID((REFIID)&pInterface->guid, &szInterfaceId);
                    _ftprintf(stderr, TEXT("Interface \"%s\" already exists (GUID %") TEXT(PRIsLPOLESTR) TEXT(").\n"), pInterface->szName, szInterfaceId);
                    CoTaskMemFree(szInterfaceId);
                    iResult = 1; goto create_cleanup_pInterfaceList;
                }
            }

            /* Rename the interface. */
            dwResult = tap_set_interface_name(&guidInterface, szName);
            if (dwResult != ERROR_SUCCESS)
            {
                StringFromIID((REFIID)&guidInterface, &szInterfaceId);
                _ftprintf(stderr, TEXT("Renaming TUN/TAP interface %") TEXT(PRIsLPOLESTR) TEXT(" to \"%s\" failed (error 0x%x).\n"), szInterfaceId, szName, dwResult);
                CoTaskMemFree(szInterfaceId);
                iResult = 1; goto quit;
            }

            iResult = 0;

create_cleanup_pInterfaceList:
            tap_free_interface_list(pInterfaceList);
            if (iResult)
            {
                goto create_delete_interface;
            }
        }

        /* Output interface GUID. */
        StringFromIID((REFIID)&guidInterface, &szInterfaceId);
        _ftprintf(stdout, TEXT("%") TEXT(PRIsLPOLESTR) TEXT("\n"), szInterfaceId);
        CoTaskMemFree(szInterfaceId);

        iResult = 0; goto quit;

create_delete_interface:
        tap_delete_interface(
            NULL,
            &guidInterface,
            &bRebootRequired);
        iResult = 1; goto quit;
    }
    else if (_tcsicmp(argv[1], TEXT("list")) == 0)
    {
        LPCTSTR szHwId = NULL;

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (_tcsicmp(argv[i], TEXT("--hwid")) == 0)
            {
                szHwId = argv[++i];
            }
            else
            {
                _ftprintf(stderr, TEXT("Unknown option \"%s\". Please, use \"tapctl help list\" to list supported options. Ignored.\n"), argv[i]);
            }
        }

        /* Output list of TUN/TAP interfaces. */
        struct tap_interface_node *pInterfaceList = NULL;
        DWORD dwResult = tap_list_interfaces(NULL, szHwId, &pInterfaceList, FALSE);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Enumerating TUN/TAP interfaces failed (error 0x%x).\n"), dwResult);
            iResult = 1; goto quit;
        }

        for (struct tap_interface_node *pInterface = pInterfaceList; pInterface; pInterface = pInterface->pNext)
        {
            LPOLESTR szInterfaceId = NULL;
            StringFromIID((REFIID)&pInterface->guid, &szInterfaceId);
            _ftprintf(stdout, TEXT("%") TEXT(PRIsLPOLESTR) TEXT("\t%") TEXT(PRIsLPTSTR) TEXT("\n"), szInterfaceId, pInterface->szName);
            CoTaskMemFree(szInterfaceId);
        }

        iResult = 0;
        tap_free_interface_list(pInterfaceList);
    }
    else if (_tcsicmp(argv[1], TEXT("delete")) == 0)
    {
        if (argc < 3)
        {
            _ftprintf(stderr, TEXT("Missing interface GUID or name. Please, use \"tapctl help delete\" for usage info.\n"));
            return 1;
        }

        GUID guidInterface;
        if (FAILED(IIDFromString(argv[2], (LPIID)&guidInterface)))
        {
            /* The argument failed to covert to GUID. Treat it as the interface name. */
            struct tap_interface_node *pInterfaceList = NULL;
            DWORD dwResult = tap_list_interfaces(NULL, NULL, &pInterfaceList, FALSE);
            if (dwResult != ERROR_SUCCESS)
            {
                _ftprintf(stderr, TEXT("Enumerating TUN/TAP interfaces failed (error 0x%x).\n"), dwResult);
                iResult = 1; goto quit;
            }

            for (struct tap_interface_node *pInterface = pInterfaceList;; pInterface = pInterface->pNext)
            {
                if (pInterface == NULL)
                {
                    _ftprintf(stderr, TEXT("\"%s\" interface not found.\n"), argv[2]);
                    iResult = 1; goto delete_cleanup_pInterfaceList;
                }
                else if (_tcsicmp(argv[2], pInterface->szName) == 0)
                {
                    memcpy(&guidInterface, &pInterface->guid, sizeof(GUID));
                    break;
                }
            }

            iResult = 0;

delete_cleanup_pInterfaceList:
            tap_free_interface_list(pInterfaceList);
            if (iResult)
            {
                goto quit;
            }
        }

        /* Delete the network interface. */
        DWORD dwResult = tap_delete_interface(
            NULL,
            &guidInterface,
            &bRebootRequired);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Deleting interface \"%s\" failed (error 0x%x).\n"), argv[2], dwResult);
            iResult = 1; goto quit;
        }

        iResult = 0; goto quit;
    }
    else
    {
        _ftprintf(stderr, TEXT("Unknown command \"%s\". Please, use \"tapctl help\" to list supported commands.\n"), argv[1]);
        return 1;
    }

quit:
    if (bRebootRequired)
    {
        _ftprintf(stderr, TEXT("A system reboot is required.\n"));
    }

    return iResult;
}


bool
dont_mute(unsigned int flags)
{
    UNREFERENCED_PARAMETER(flags);

    return true;
}


void
x_msg_va(const unsigned int flags, const char *format, va_list arglist)
{
    /* Output message string. Note: Message strings don't contain line terminators. */
    vfprintf(stderr, format, arglist);
    _ftprintf(stderr, TEXT("\n"));

    if ((flags & M_ERRNO) != 0)
    {
        /* Output system error message (if possible). */
        DWORD dwResult = GetLastError();
        LPTSTR szErrMessage = NULL;
        if (FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                0,
                dwResult,
                0,
                (LPTSTR)&szErrMessage,
                0,
                NULL) && szErrMessage)
        {
            /* Trim trailing whitespace. Set terminator after the last non-whitespace character. This prevents excessive trailing line breaks. */
            for (size_t i = 0, i_last = 0;; i++)
            {
                if (szErrMessage[i])
                {
                    if (!_istspace(szErrMessage[i]))
                    {
                        i_last = i + 1;
                    }
                }
                else
                {
                    szErrMessage[i_last] = 0;
                    break;
                }
            }

            /* Output error message. */
            _ftprintf(stderr, TEXT("Error 0x%x: %s\n"), dwResult, szErrMessage);

            LocalFree(szErrMessage);
        }
        else
        {
            _ftprintf(stderr, TEXT("Error 0x%x\n"), dwResult);
        }
    }
}
