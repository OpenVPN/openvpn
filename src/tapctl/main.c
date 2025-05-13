/*
 *  tapctl -- Utility to manipulate TUN/TAP adapters on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2024 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018-2024 Simon Rozman <simon@rozman.si>
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
#endif

#include "tap.h"
#include "error.h"

#include <objbase.h>
#include <setupapi.h>
#include <stdio.h>
#include <wchar.h>

#ifdef _MSC_VER
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "setupapi.lib")
#endif


const WCHAR title_string[] =
    _L(PACKAGE_NAME) L" " _L(PACKAGE_VERSION)
;

static const WCHAR usage_message[] =
    L"%ls\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl <command> [<command specific options>]\n"
    L"\n"
    L"Commands:\n"
    L"\n"
    L"create     Create a new TUN/TAP adapter\n"
    L"list       List TUN/TAP adapters\n"
    L"delete     Delete specified network adapter\n"
    L"help       Display this text\n"
    L"\n"
    L"Hint: Use \"tapctl help <command>\" to display help for particular command.\n"
;

static const WCHAR usage_message_create[] =
    L"%ls\n"
    L"\n"
    L"Creates a new TUN/TAP adapter\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl create [<options>]\n"
    L"\n"
    L"Options:\n"
    L"\n"
    L"--name <name>  Set TUN/TAP adapter name. Should the adapter with given name    \n"
    L"               already exist, an error is returned. If this option is not      \n"
    L"               specified, a default adapter name is chosen by Windows.         \n"
    L"               Note: This name can also be specified as OpenVPN's --dev-node   \n"
    L"               option.                                                         \n"
    L"--hwid <hwid>  Adapter hardware ID. Default value is root\\tap0901, which      \n"
    L"               describes tap-windows6 driver. To work with ovpn-dco driver,    \n"
    L"               driver, specify 'ovpn-dco'.                                     \n"
    L"\n"
    L"Output:\n"
    L"\n"
    L"This command prints newly created TUN/TAP adapter's GUID to stdout.            \n"
;

static const WCHAR usage_message_list[] =
    L"%ls\n"
    L"\n"
    L"Lists TUN/TAP adapters\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl list\n"
    L"\n"
    L"Options:\n"
    L"\n"
    L"--hwid <hwid>  Adapter hardware ID. By default, root\\tap0901, tap0901 and \n"
    L"               ovpn-dco adapters are listed. Use this switch to limit the list.\n"
    L"\n"
    L"Output:\n"
    L"\n"
    L"This command prints all TUN/TAP adapters to stdout.                            \n"
;

static const WCHAR usage_message_delete[] =
    L"%ls\n"
    L"\n"
    L"Deletes the specified network adapter\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl delete <adapter GUID | adapter name>\n"
;


/**
 * Print the help message.
 */
static void
usage(void)
{
    fwprintf(stderr,
             usage_message,
             title_string);
}

/**
 * Checks if adapter with given name doesn't already exist
 */
static BOOL
is_adapter_name_available(LPCWSTR name, struct tap_adapter_node *adapter_list, BOOL log)
{
    for (struct tap_adapter_node *a = adapter_list; a; a = a->pNext)
    {
        if (wcsicmp(name, a->szName) == 0)
        {
            if (log)
            {
                LPOLESTR adapter_id = NULL;
                StringFromIID((REFIID)&a->guid, &adapter_id);
                fwprintf(stderr, L"Adapter \"%ls\" already exists (GUID %"
                         L"ls).\n", a->szName, adapter_id);
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
static LPWSTR
get_unique_adapter_name(LPCWSTR hwid, struct tap_adapter_node *adapter_list)
{
    if (hwid == NULL)
    {
        return NULL;
    }

    LPCWSTR base_name;
    if (wcsicmp(hwid, L"ovpn-dco") == 0)
    {
        base_name = L"OpenVPN Data Channel Offload";
    }
    else if (wcsicmp(hwid, L"root\\" _L(TAP_WIN_COMPONENT_ID)) == 0)
    {
        base_name = L"OpenVPN TAP-Windows6";
    }
    else
    {
        return NULL;
    }

    if (is_adapter_name_available(base_name, adapter_list, FALSE))
    {
        return wcsdup(base_name);
    }

    size_t name_len = wcslen(base_name) + 10;
    LPWSTR name = malloc(name_len * sizeof(WCHAR));
    if (name == NULL)
    {
        return NULL;
    }
    for (int i = 1; i < 100; ++i)
    {
        swprintf_s(name, name_len, L"%ls #%d", base_name, i);

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
wmain(int argc, LPCWSTR argv[])
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
    else if (wcsicmp(argv[1], L"help") == 0)
    {
        /* Output help. */
        if (argc < 3)
        {
            usage();
        }
        else if (wcsicmp(argv[2], L"create") == 0)
        {
            fwprintf(stderr, usage_message_create, title_string);
        }
        else if (wcsicmp(argv[2], L"list") == 0)
        {
            fwprintf(stderr, usage_message_list, title_string);
        }
        else if (wcsicmp(argv[2], L"delete") == 0)
        {
            fwprintf(stderr, usage_message_delete, title_string);
        }
        else
        {
            fwprintf(stderr, L"Unknown command \"%ls"
                     L"\". Please, use \"tapctl help\" to list supported commands.\n", argv[2]);
        }

        return 1;
    }
    else if (wcsicmp(argv[1], L"create") == 0)
    {
        LPCWSTR szName = NULL;
        LPCWSTR szHwId = L"root\\" _L(TAP_WIN_COMPONENT_ID);

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (wcsicmp(argv[i], L"--name") == 0)
            {
                szName = argv[++i];
            }
            else if (wcsicmp(argv[i], L"--hwid") == 0)
            {
                szHwId = argv[++i];
            }
            else
            {
                fwprintf(stderr, L"Unknown option \"%ls"
                         L"\". Please, use \"tapctl help create\" to list supported options. Ignored.\n",
                         argv[i]);
            }
        }

        /* Create TUN/TAP adapter. */
        GUID guidAdapter;
        LPOLESTR szAdapterId = NULL;
        DWORD dwResult = tap_create_adapter(
            NULL,
            L"Virtual Ethernet",
            szHwId,
            &bRebootRequired,
            &guidAdapter);
        if (dwResult != ERROR_SUCCESS)
        {
            fwprintf(stderr, L"Creating TUN/TAP adapter failed (error 0x%x).\n", dwResult);
            iResult = 1; goto quit;
        }

        /* Get existing network adapters. */
        struct tap_adapter_node *pAdapterList = NULL;
        dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
        if (dwResult != ERROR_SUCCESS)
        {
            fwprintf(stderr, L"Enumerating adapters failed (error 0x%x).\n", dwResult);
            iResult = 1;
            goto create_delete_adapter;
        }

        LPWSTR adapter_name = szName ? wcsdup(szName) : get_unique_adapter_name(szHwId, pAdapterList);
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
                fwprintf(stderr, L"Renaming TUN/TAP adapter %ls"
                         L" to \"%ls\" failed (error 0x%x).\n",
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
        fwprintf(stdout, L"%ls\n", szAdapterId);
        CoTaskMemFree(szAdapterId);

        iResult = 0; goto quit;

create_delete_adapter:
        tap_delete_adapter(
            NULL,
            &guidAdapter,
            &bRebootRequired);
        iResult = 1; goto quit;
    }
    else if (wcsicmp(argv[1], L"list") == 0)
    {
        WCHAR szzHwId[0x100] =
            L"root\\" _L(TAP_WIN_COMPONENT_ID) L"\0"
            _L(TAP_WIN_COMPONENT_ID) L"\0"
            L"ovpn-dco\0";

        /* Parse options. */
        for (int i = 2; i < argc; i++)
        {
            if (wcsicmp(argv[i], L"--hwid") == 0)
            {
                memset(szzHwId, 0, sizeof(szzHwId));
                ++i;
                memcpy_s(szzHwId, sizeof(szzHwId) - 2*sizeof(WCHAR) /*requires double zero termination*/, argv[i], wcslen(argv[i])*sizeof(WCHAR));
            }
            else
            {
                fwprintf(stderr, L"Unknown option \"%ls"
                         L"\". Please, use \"tapctl help list\" to list supported options. Ignored.\n",
                         argv[i]);
            }
        }

        /* Output list of adapters with given hardware ID. */
        struct tap_adapter_node *pAdapterList = NULL;
        DWORD dwResult = tap_list_adapters(NULL, szzHwId, &pAdapterList);
        if (dwResult != ERROR_SUCCESS)
        {
            fwprintf(stderr, L"Enumerating TUN/TAP adapters failed (error 0x%x).\n", dwResult);
            iResult = 1; goto quit;
        }

        for (struct tap_adapter_node *pAdapter = pAdapterList; pAdapter; pAdapter = pAdapter->pNext)
        {
            LPOLESTR szAdapterId = NULL;
            StringFromIID((REFIID)&pAdapter->guid, &szAdapterId);
            fwprintf(stdout, L"%ls\t%"
                     L"ls\n", szAdapterId, pAdapter->szName);
            CoTaskMemFree(szAdapterId);
        }

        iResult = 0;
        tap_free_adapter_list(pAdapterList);
    }
    else if (wcsicmp(argv[1], L"delete") == 0)
    {
        if (argc < 3)
        {
            fwprintf(stderr, L"Missing adapter GUID or name. Please, use \"tapctl help delete\" for usage info.\n");
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
                fwprintf(stderr, L"Enumerating TUN/TAP adapters failed (error 0x%x).\n", dwResult);
                iResult = 1; goto quit;
            }

            for (struct tap_adapter_node *pAdapter = pAdapterList;; pAdapter = pAdapter->pNext)
            {
                if (pAdapter == NULL)
                {
                    fwprintf(stderr, L"\"%ls\" adapter not found.\n", argv[2]);
                    iResult = 1; goto delete_cleanup_pAdapterList;
                }
                else if (wcsicmp(argv[2], pAdapter->szName) == 0)
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
            fwprintf(stderr, L"Deleting adapter \"%ls"
                     L"\" failed (error 0x%x).\n", argv[2], dwResult);
            iResult = 1; goto quit;
        }

        iResult = 0; goto quit;
    }
    else
    {
        fwprintf(stderr, L"Unknown command \"%ls"
                 L"\". Please, use \"tapctl help\" to list supported commands.\n", argv[1]);
        return 1;
    }

quit:
    if (bRebootRequired)
    {
        fwprintf(stderr, L"A system reboot is required.\n");
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
    fwprintf(stderr, L"\n");

    if ((flags & M_ERRNO) != 0)
    {
        /* Output system error message (if possible). */
        DWORD dwResult = GetLastError();
        LPWSTR szErrMessage = NULL;
        if (FormatMessage(
                FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
                0,
                dwResult,
                0,
                (LPWSTR)&szErrMessage,
                0,
                NULL) && szErrMessage)
        {
            /* Trim trailing whitespace. Set terminator after the last non-whitespace character. This prevents excessive trailing line breaks. */
            for (size_t i = 0, i_last = 0;; i++)
            {
                if (szErrMessage[i])
                {
                    if (!iswspace(szErrMessage[i]))
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
            fwprintf(stderr, L"Error 0x%x: %ls\n", dwResult, szErrMessage);

            LocalFree(szErrMessage);
        }
        else
        {
            fwprintf(stderr, L"Error 0x%x\n", dwResult);
        }
    }
}
