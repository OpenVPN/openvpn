/*
 *  tapctl -- Utility to manipulate TUN/TAP adapters on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2023 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018-2023 Simon Rozman <simon@rozman.si>
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
;

static const TCHAR usage_message[] =
    TEXT("%") TEXT(PRIsLPTSTR) TEXT("\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl <command> [<command specific options>]\n")
    TEXT("\n")
    TEXT("Commands:\n")
    TEXT("\n")
    TEXT("create     Create a new TUN/TAP adapter\n")
    TEXT("list       List TUN/TAP adapters\n")
    TEXT("delete     Delete specified network adapter\n")
    TEXT("help       Display this text\n")
    TEXT("\n")
    TEXT("Hint: Use \"tapctl help <command>\" to display help for particular command.\n")
;

static const TCHAR usage_message_create[] =
    TEXT("%") TEXT(PRIsLPTSTR) TEXT("\n")
    TEXT("\n")
    TEXT("Creates a new TUN/TAP adapter\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl create [<options>]\n")
    TEXT("\n")
    TEXT("Options:\n")
    TEXT("\n")
    TEXT("--name <name>  Set TUN/TAP adapter name. Should the adapter with given name    \n")
    TEXT("               already exist, an error is returned. If this option is not      \n")
    TEXT("               specified, a default adapter name is chosen by Windows.         \n")
    TEXT("               Note: This name can also be specified as OpenVPN's --dev-node   \n")
    TEXT("               option.                                                         \n")
    TEXT("--hwid <hwid>  Adapter hardware ID. Default value is root\\tap0901, which      \n")
    TEXT("               describes tap-windows6 driver. To work with wintun or ovpn-dco  \n")
    TEXT("               driver, specify 'wintun' or 'ovpn-dco'.                         \n")
    TEXT("\n")
    TEXT("Output:\n")
    TEXT("\n")
    TEXT("This command prints newly created TUN/TAP adapter's GUID to stdout.            \n")
;

static const TCHAR usage_message_list[] =
    TEXT("%") TEXT(PRIsLPTSTR) TEXT("\n")
    TEXT("\n")
    TEXT("Lists TUN/TAP adapters\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl list\n")
    TEXT("\n")
    TEXT("Options:\n")
    TEXT("\n")
    TEXT("--hwid <hwid>  Adapter hardware ID. By default, root\\tap0901, tap0901, wintun and \n")
    TEXT("               ovpn-dco adapters are listed. Use this switch to limit the list.\n")
    TEXT("\n")
    TEXT("Output:\n")
    TEXT("\n")
    TEXT("This command prints all TUN/TAP adapters to stdout.                            \n")
;

static const TCHAR usage_message_delete[] =
    TEXT("%") TEXT(PRIsLPTSTR) TEXT("\n")
    TEXT("\n")
    TEXT("Deletes the specified network adapter\n")
    TEXT("\n")
    TEXT("Usage:\n")
    TEXT("\n")
    TEXT("tapctl delete <adapter GUID | adapter name>\n")
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
 * Checks if adapter with given name doesn't already exist
 */
static BOOL
is_adapter_name_available(LPCTSTR name, struct tap_adapter_node *adapter_list, BOOL log)
{
    for (struct tap_adapter_node *a = adapter_list; a; a = a->pNext)
    {
        if (_tcsicmp(name, a->szName) == 0)
        {
            if (log)
            {
                LPOLESTR adapter_id = NULL;
                StringFromIID((REFIID)&a->guid, &adapter_id);
                _ftprintf(stderr, TEXT("Adapter \"%") TEXT(PRIsLPTSTR) TEXT("\" already exists (GUID %")
                          TEXT(PRIsLPOLESTR) TEXT(").\n"), a->szName, adapter_id);
                CoTaskMemFree(adapter_id);
            }

            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Returns unique adapter name based on hwid or NULL if name cannot be generated.
 * Caller is responsible for freeing it.
 */
static LPTSTR
get_unique_adapter_name(LPCTSTR hwid, struct tap_adapter_node *adapter_list)
{
    if (hwid == NULL)
    {
        return NULL;
    }

    LPCTSTR base_name;
    if (_tcsicmp(hwid, TEXT("ovpn-dco")) == 0)
    {
        base_name = TEXT("OpenVPN Data Channel Offload");
    }
    else if (_tcsicmp(hwid, TEXT("wintun")) == 0)
    {
        base_name = TEXT("OpenVPN Wintun");
    }
    else if (_tcsicmp(hwid, TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID)) == 0)
    {
        base_name = TEXT("OpenVPN TAP-Windows6");
    }
    else
    {
        return NULL;
    }

    if (is_adapter_name_available(base_name, adapter_list, FALSE))
    {
        return _tcsdup(base_name);
    }

    size_t name_len = _tcslen(base_name) + 10;
    LPTSTR name = malloc(name_len * sizeof(TCHAR));
    if (name == NULL)
    {
        return NULL;
    }
    for (int i = 1; i < 100; ++i)
    {
        _stprintf_s(name, name_len, TEXT("%ls #%d"), base_name, i);

        if (is_adapter_name_available(name, adapter_list, FALSE))
        {
            return name;
        }
    }

    return NULL;
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
            _ftprintf(stderr, TEXT("Unknown command \"%") TEXT(PRIsLPTSTR)
                      TEXT("\". Please, use \"tapctl help\" to list supported commands.\n"), argv[2]);
        }

        return 1;
    }
    else if (_tcsicmp(argv[1], TEXT("create")) == 0)
    {
        LPCTSTR szName = NULL;
        LPCTSTR szHwId = TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID);

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (_tcsicmp(argv[i], TEXT("--name")) == 0)
            {
                szName = argv[++i];
            }
            else if (_tcsicmp(argv[i], TEXT("--hwid")) == 0)
            {
                szHwId = argv[++i];
            }
            else
            {
                _ftprintf(stderr, TEXT("Unknown option \"%") TEXT(PRIsLPTSTR)
                          TEXT("\". Please, use \"tapctl help create\" to list supported options. Ignored.\n"),
                          argv[i]);
            }
        }

        /* Create TUN/TAP adapter. */
        GUID guidAdapter;
        LPOLESTR szAdapterId = NULL;
        DWORD dwResult = tap_create_adapter(
            NULL,
            TEXT("Virtual Ethernet"),
            szHwId,
            &bRebootRequired,
            &guidAdapter);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Creating TUN/TAP adapter failed (error 0x%x).\n"), dwResult);
            iResult = 1; goto quit;
        }

        /* Get existing network adapters. */
        struct tap_adapter_node *pAdapterList = NULL;
        dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Enumerating adapters failed (error 0x%x).\n"), dwResult);
            iResult = 1;
            goto create_delete_adapter;
        }

        LPTSTR adapter_name = szName ? _tcsdup(szName) : get_unique_adapter_name(szHwId, pAdapterList);
        if (adapter_name)
        {
            /* Check for duplicates when name was specified,
             * otherwise get_adapter_default_name() takes care of it */
            if (szName && !is_adapter_name_available(adapter_name, pAdapterList, TRUE))
            {
                iResult = 1;
                goto create_cleanup_pAdapterList;
            }

            /* Rename the adapter. */
            dwResult = tap_set_adapter_name(&guidAdapter, adapter_name, FALSE);
            if (dwResult != ERROR_SUCCESS)
            {
                StringFromIID((REFIID)&guidAdapter, &szAdapterId);
                _ftprintf(stderr, TEXT("Renaming TUN/TAP adapter %") TEXT(PRIsLPOLESTR)
                          TEXT(" to \"%") TEXT(PRIsLPTSTR) TEXT("\" failed (error 0x%x).\n"),
                          szAdapterId, adapter_name, dwResult);
                CoTaskMemFree(szAdapterId);
                iResult = 1; goto quit;
            }
        }

        iResult = 0;

create_cleanup_pAdapterList:
        free(adapter_name);

        tap_free_adapter_list(pAdapterList);
        if (iResult)
        {
            goto create_delete_adapter;
        }

        /* Output adapter GUID. */
        StringFromIID((REFIID)&guidAdapter, &szAdapterId);
        _ftprintf(stdout, TEXT("%") TEXT(PRIsLPOLESTR) TEXT("\n"), szAdapterId);
        CoTaskMemFree(szAdapterId);

        iResult = 0; goto quit;

create_delete_adapter:
        tap_delete_adapter(
            NULL,
            &guidAdapter,
            &bRebootRequired);
        iResult = 1; goto quit;
    }
    else if (_tcsicmp(argv[1], TEXT("list")) == 0)
    {
        TCHAR szzHwId[0x100] =
            TEXT("root\\") TEXT(TAP_WIN_COMPONENT_ID) TEXT("\0")
            TEXT(TAP_WIN_COMPONENT_ID) TEXT("\0")
            TEXT("Wintun\0")
            TEXT("ovpn-dco\0");

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (_tcsicmp(argv[i], TEXT("--hwid")) == 0)
            {
                memset(szzHwId, 0, sizeof(szzHwId));
                ++i;
                memcpy_s(szzHwId, sizeof(szzHwId) - 2*sizeof(TCHAR) /*requires double zero termination*/, argv[i], _tcslen(argv[i])*sizeof(TCHAR));
            }
            else
            {
                _ftprintf(stderr, TEXT("Unknown option \"%") TEXT(PRIsLPTSTR)
                          TEXT("\". Please, use \"tapctl help list\" to list supported options. Ignored.\n"),
                          argv[i]);
            }
        }

        /* Output list of adapters with given hardware ID. */
        struct tap_adapter_node *pAdapterList = NULL;
        DWORD dwResult = tap_list_adapters(NULL, szzHwId, &pAdapterList);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Enumerating TUN/TAP adapters failed (error 0x%x).\n"), dwResult);
            iResult = 1; goto quit;
        }

        for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter; pAdapter = pAdapter->pNext)
        {
            LPOLESTR szAdapterId = NULL;
            StringFromIID((REFIID)&pAdapter->guid, &szAdapterId);
            _ftprintf(stdout, TEXT("%") TEXT(PRIsLPOLESTR) TEXT("\t%")
                      TEXT(PRIsLPTSTR) TEXT("\n"), szAdapterId, pAdapter->szName);
            CoTaskMemFree(szAdapterId);
        }

        iResult = 0;
        tap_free_adapter_list(pAdapterList);
    }
    else if (_tcsicmp(argv[1], TEXT("delete")) == 0)
    {
        if (argc < 3)
        {
            _ftprintf(stderr, TEXT("Missing adapter GUID or name. Please, use \"tapctl help delete\" for usage info.\n"));
            return 1;
        }

        GUID guidAdapter;
        if (FAILED(IIDFromString(argv[2], (LPIID)&guidAdapter)))
        {
            /* The argument failed to covert to GUID. Treat it as the adapter name. */
            struct tap_adapter_node *pAdapterList = NULL;
            DWORD dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
            if (dwResult != ERROR_SUCCESS)
            {
                _ftprintf(stderr, TEXT("Enumerating TUN/TAP adapters failed (error 0x%x).\n"), dwResult);
                iResult = 1; goto quit;
            }

            for (struct tap_adapter_node *pAdapter = pAdapterList;; pAdapter = pAdapter->pNext)
            {
                if (pAdapter == NULL)
                {
                    _ftprintf(stderr, TEXT("\"%") TEXT(PRIsLPTSTR) TEXT("\" adapter not found.\n"), argv[2]);
                    iResult = 1; goto delete_cleanup_pAdapterList;
                }
                else if (_tcsicmp(argv[2], pAdapter->szName) == 0)
                {
                    memcpy(&guidAdapter, &pAdapter->guid, sizeof(GUID));
                    break;
                }
            }

            iResult = 0;

delete_cleanup_pAdapterList:
            tap_free_adapter_list(pAdapterList);
            if (iResult)
            {
                goto quit;
            }
        }

        /* Delete the network adapter. */
        DWORD dwResult = tap_delete_adapter(
            NULL,
            &guidAdapter,
            &bRebootRequired);
        if (dwResult != ERROR_SUCCESS)
        {
            _ftprintf(stderr, TEXT("Deleting adapter \"%") TEXT(PRIsLPTSTR)
                      TEXT("\" failed (error 0x%x).\n"), argv[2], dwResult);
            iResult = 1; goto quit;
        }

        iResult = 0; goto quit;
    }
    else
    {
        _ftprintf(stderr, TEXT("Unknown command \"%") TEXT(PRIsLPTSTR)
                  TEXT("\". Please, use \"tapctl help\" to list supported commands.\n"), argv[1]);
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
            _ftprintf(stderr, TEXT("Error 0x%x: %") TEXT(PRIsLPTSTR) TEXT("\n"), dwResult, szErrMessage);

            LocalFree(szErrMessage);
        }
        else
        {
            _ftprintf(stderr, TEXT("Error 0x%x\n"), dwResult);
        }
    }
}
