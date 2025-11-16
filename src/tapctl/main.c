/*
 *  tapctl -- Utility to manipulate TUN/TAP adapters on Windows
 *            https://community.openvpn.net/openvpn/wiki/Tapctl
 *
 *  Copyright (C) 2002-2025 OpenVPN Inc <sales@openvpn.net>
 *  Copyright (C) 2018-2025 Simon Rozman <simon@rozman.si>
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
 *  with this program; if not, see <https://www.gnu.org/licenses/>.
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


/* clang-format off */
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
    L"create     Create a new VPN network adapter\n"
    L"list       List VPN network adapters\n"
    L"delete     Delete specified VPN network adapter\n"
    L"help       Display this text\n"
    L"\n"
    L"Hint: Use \"tapctl help <command>\" to display help for particular command.\n"
;

static const WCHAR usage_message_create[] =
    L"%ls\n"
    L"\n"
    L"Creates a new VPN network adapter\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl create [<options>]\n"
    L"\n"
    L"Options:\n"
    L"\n"
    L"--name <name>  Set VPN network adapter name. Should the adapter with given     \n"
    L"               name already exist, an error is returned. If this option is not \n"
    L"               specified, an OpenVPN-specific default name is chosen.          \n"
    L"               Note: This name can also be specified as OpenVPN's --dev-node   \n"
    L"               option.                                                         \n"
    L"--hwid <hwid>  Adapter hardware ID. Default value is ovpn-dco, which uses      \n"
    L"               the OpenVPN Data Channel Offload driver. To work with          \n"
    L"               tap-windows6 driver, specify root\\tap0901 or tap0901.         \n"
    L"\n"
    L"Output:\n"
    L"\n"
    L"This command prints newly created VPN network adapter's GUID, name and         \n"
    L"hardware ID to stdout.                                                         \n"
;

static const WCHAR usage_message_list[] =
    L"%ls\n"
    L"\n"
    L"Lists VPN network adapters\n"
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
    L"This command prints VPN network adapter GUID, name and hardware ID to stdout.  \n"
;

static const WCHAR usage_message_delete[] =
    L"%ls\n"
    L"\n"
    L"Deletes the specified VPN network adapter\n"
    L"\n"
    L"Usage:\n"
    L"\n"
    L"tapctl delete <adapter GUID | adapter name>\n"
;
/* clang-format on */


/**
 * Print the help message.
 */
static void
usage(void)
{
    fwprintf(stderr, usage_message, title_string);
}

/**
 * Locate an adapter node by its friendly name within the enumerated list.
 *
 * @param name          Friendly name to search for. Comparison is case-insensitive.
 * @param adapter_list  Head of the adapter list returned by tap_list_adapters().
 *
 * @return Pointer to the matching node, or NULL when not found.
 */
static struct tap_adapter_node *
find_adapter_by_name(LPCWSTR name, struct tap_adapter_node *adapter_list)
{
    for (struct tap_adapter_node *a = adapter_list; a; a = a->pNext)
    {
        if (_wcsicmp(name, a->szName) == 0)
        {
            return a;
        }
    }

    return NULL;
}

/**
 * Check whether the registry still reserves a given network-connection name.
 *
 * Windows keeps friendly names under
 * \\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Network\\{NETCLASS}\\{GUID}\\Connection\\Name,
 * even after an adapter is removed. netsh refuses to rename to any reserved name.
 *
 * @param name  Friendly name to test.
 *
 * @return TRUE if the name exists in the registry, FALSE otherwise.
 */
static BOOL
registry_name_exists(LPCWSTR name)
{
    static const WCHAR class_key[] =
        L"SYSTEM\\CurrentControlSet\\Control\\Network\\{4d36e972-e325-11ce-bfc1-08002be10318}";

    HKEY hClassKey = NULL;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, class_key, 0, KEY_READ, &hClassKey) != ERROR_SUCCESS)
    {
        return FALSE;
    }

    BOOL found = FALSE;

    for (DWORD index = 0;; ++index)
    {
        WCHAR adapter_id[64];
        DWORD adapter_id_len = _countof(adapter_id);
        LONG result = RegEnumKeyEx(hClassKey, index, adapter_id, &adapter_id_len, NULL, NULL, NULL,
                                   NULL);
        if (result == ERROR_NO_MORE_ITEMS)
        {
            break;
        }
        else if (result != ERROR_SUCCESS)
        {
            continue;
        }

        WCHAR connection_key[512];
        swprintf_s(connection_key, _countof(connection_key), L"%ls\\%ls\\Connection", class_key,
                   adapter_id);

        DWORD value_size = 0;
        LONG query = RegGetValueW(HKEY_LOCAL_MACHINE, connection_key, L"Name",
                                  RRF_RT_REG_SZ | RRF_NOEXPAND, NULL, NULL, &value_size);
        if (query != ERROR_SUCCESS || value_size < sizeof(WCHAR))
        {
            continue;
        }

        LPWSTR value = (LPWSTR)malloc(value_size);
        if (!value)
        {
            continue;
        }

        query = RegGetValueW(HKEY_LOCAL_MACHINE, connection_key, L"Name",
                             RRF_RT_REG_SZ | RRF_NOEXPAND, NULL, value, &value_size);
        if (query == ERROR_SUCCESS && _wcsicmp(name, value) == 0)
        {
            found = TRUE;
            free(value);
            break;
        }

        free(value);

        if (found)
        {
            break;
        }
    }

    RegCloseKey(hClassKey);
    return found;
}

/**
 * Determine whether a friendly name is currently in use by an adapter or reserved
 * in the registry.
 *
 * @param name          Friendly name to test.
 * @param adapter_list  Head of the adapter list returned by tap_list_adapters().
 *
 * @return TRUE when the name is taken/reserved, FALSE when available.
 */
static BOOL
tap_name_in_use(LPCWSTR name, struct tap_adapter_node *adapter_list)
{
    if (name == NULL)
    {
        return FALSE;
    }

    if (find_adapter_by_name(name, adapter_list))
    {
        return TRUE;
    }

    return registry_name_exists(name);
}

/**
 * Check whether a proposed adapter name satisfies Windows connection-name rules.
 *
 * Tabs, control characters (except space), and the following characters are disallowed:
 * \ / : * ? " < > |
 * Names must also be non-empty and no longer than 255 characters.
 */
BOOL
tap_is_valid_adapter_name(LPCWSTR name)
{
    if (name == NULL)
    {
        return FALSE;
    }

    size_t length = wcslen(name);
    if (length == 0 || length > 255)
    {
        return FALSE;
    }

    static const WCHAR invalid_chars[] = L"\\/:*?\"<>|";

    for (const WCHAR *p = name; *p; ++p)
    {
        WCHAR ch = *p;
        if (ch < L' ')
        {
            return FALSE;
        }
        if (wcschr(invalid_chars, ch))
        {
            return FALSE;
        }
    }

    return TRUE;
}

/**
 * Resolve the adapter name we should apply:
 *   - For user-specified names, ensure they are unique both in the adapter list and
 *     in the registry. On conflict, an explanatory message is printed and NULL is returned.
 *   - For automatic naming, derive the base string from HWID and append the first available
 *     suffix recognised by Windows.
 *
 * @param requested_name  Name provided via CLI or configuration (may be NULL/empty).
 * @param hwid            Hardware identifier of the adapter being created.
 * @param adapter_list    Existing adapters enumerated via tap_list_adapters().
 *
 * @return Newly allocated wide string containing the final name, or NULL on failure.
 */
static LPWSTR
tap_resolve_adapter_name(LPCWSTR requested_name, LPCWSTR hwid,
                         struct tap_adapter_node *adapter_list)
{
    if (requested_name && requested_name[0])
    {
        if (!tap_is_valid_adapter_name(requested_name))
        {
            fwprintf(stderr,
                     L"Adapter name \"%ls\" contains invalid characters. Avoid tabs or the "
                     L"characters \\ / : * ? \" < > | and keep the length within 255 characters.\n",
                     requested_name);
            return NULL;
        }

        struct tap_adapter_node *conflict = find_adapter_by_name(requested_name, adapter_list);
        if (conflict)
        {
            LPOLESTR adapter_id = NULL;
            StringFromIID((REFIID)&conflict->guid, &adapter_id);
            fwprintf(stderr,
                     L"Adapter \"%ls\" already exists (GUID %"
                     L"ls).\n",
                     conflict->szName, adapter_id);
            CoTaskMemFree(adapter_id);
            return NULL;
        }

        if (registry_name_exists(requested_name))
        {
            fwprintf(stderr, L"Adapter name \"%ls\" is already in use.\n", requested_name);
            return NULL;
        }

        return wcsdup(requested_name);
    }

    if (hwid == NULL)
    {
        return NULL;
    }

    LPCWSTR base_name = NULL;
    if (_wcsicmp(hwid, L"ovpn-dco") == 0)
    {
        base_name = L"OpenVPN Data Channel Offload";
    }
    else if (_wcsicmp(hwid, L"root\\" _L(TAP_WIN_COMPONENT_ID)) == 0
             || _wcsicmp(hwid, _L(TAP_WIN_COMPONENT_ID)) == 0)
    {
        base_name = L"OpenVPN TAP-Windows6";
    }
    else
    {
        fwprintf(stderr,
                 L"Cannot auto-generate adapter name for hardware ID \"%ls\".\n", hwid);
        return NULL;
    }

    if (!tap_name_in_use(base_name, adapter_list))
    {
        return wcsdup(base_name);
    }

    size_t name_len = wcslen(base_name) + 10;
    LPWSTR name = (LPWSTR)malloc(name_len * sizeof(WCHAR));
    if (name == NULL)
    {
        return NULL;
    }

    /* Windows never assigns the "#1" suffix, so skip it to avoid netsh failures. */
    for (int i = 2; i < 100; ++i)
    {
        swprintf_s(name, name_len, L"%ls #%d", base_name, i);

        if (!tap_name_in_use(name, adapter_list))
        {
            return name;
        }
    }

    free(name);
    fwprintf(stderr, L"Unable to find available adapter name based on \"%ls\".\n", base_name);
    return NULL;
}

static int
command_create(int argc, LPCWSTR argv[], BOOL *bRebootRequired)
{
    LPCWSTR szName = NULL;
    LPCWSTR defaultHwId = L"ovpn-dco";
    LPCWSTR szHwId = defaultHwId;
    LPWSTR adapter_name = NULL;
    struct tap_adapter_node *pAdapterList = NULL;
    GUID guidAdapter;
    LPOLESTR szAdapterId = NULL;
    DWORD dwResult;
    int iResult = 1;
    BOOL adapter_created = FALSE;

    for (int i = 2; i < argc; i++)
    {
        if (wcsicmp(argv[i], L"--name") == 0)
        {
            if (++i >= argc)
            {
                fwprintf(stderr, L"--name option requires a value. Ignored.\n");
                break;
            }
            szName = argv[i];
            if (szName[0] == L'\0')
            {
                fwprintf(stderr, L"--name option cannot be empty. Ignored.\n");
                szName = NULL;
            }
        }
        else if (wcsicmp(argv[i], L"--hwid") == 0)
        {
            if (++i >= argc)
            {
                fwprintf(stderr,
                         L"--hwid option requires a value. Using default \"%ls\".\n",
                         defaultHwId);
                break;
            }
            szHwId = argv[i];
            if (szHwId[0] == L'\0')
            {
                fwprintf(stderr,
                         L"--hwid option cannot be empty. Using default \"%ls\".\n",
                         defaultHwId);
                szHwId = defaultHwId;
            }
        }
        else
        {
            fwprintf(stderr,
                     L"Unknown option \"%ls"
                     L"\". Please, use \"tapctl help create\" to list supported options. Ignored.\n",
                     argv[i]);
        }
    }

    dwResult = tap_create_adapter(NULL, L"Virtual Ethernet", szHwId, bRebootRequired,
                                  &guidAdapter);
    if (dwResult != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Creating network adapter failed (error 0x%x).\n", dwResult);
        goto cleanup;
    }
    adapter_created = TRUE;

    dwResult = tap_list_adapters(NULL, NULL, &pAdapterList);
    if (dwResult != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Enumerating adapters failed (error 0x%x).\n", dwResult);
        goto cleanup;
    }

    adapter_name = tap_resolve_adapter_name(szName, szHwId, pAdapterList);
    if (adapter_name == NULL)
    {
        goto cleanup;
    }

    dwResult = tap_set_adapter_name(&guidAdapter, adapter_name, FALSE);
    if (dwResult != ERROR_SUCCESS)
    {
        StringFromIID((REFIID)&guidAdapter, &szAdapterId);
        fwprintf(stderr,
                 L"Renaming network adapter %ls to \"%ls\" failed (error 0x%x).\n", szAdapterId,
                 adapter_name, dwResult);
        CoTaskMemFree(szAdapterId);
        goto cleanup;
    }

    iResult = 0;
    StringFromIID((REFIID)&guidAdapter, &szAdapterId);
    const WCHAR *name_to_print = (adapter_name && adapter_name[0]) ? adapter_name : L"(unnamed)";
    const WCHAR *hwid_to_print = (szHwId && szHwId[0]) ? szHwId : L"(unknown hwid)";
    fwprintf(stdout, L"%ls\t%ls\t%ls\n", szAdapterId, name_to_print, hwid_to_print);
    CoTaskMemFree(szAdapterId);

cleanup:
    if (pAdapterList)
    {
        tap_free_adapter_list(pAdapterList);
    }
    free(adapter_name);

    if (adapter_created && iResult != 0)
    {
        tap_delete_adapter(NULL, &guidAdapter, bRebootRequired);
    }

    return iResult;
}

static int
command_list(int argc, LPCWSTR argv[])
{
    WCHAR szzHwId[0x100] =
        L"root\\" _L(TAP_WIN_COMPONENT_ID) L"\0" _L(TAP_WIN_COMPONENT_ID) L"\0"
                                                                          L"ovpn-dco\0";

    for (int i = 2; i < argc; i++)
    {
        if (wcsicmp(argv[i], L"--hwid") == 0)
        {
            memset(szzHwId, 0, sizeof(szzHwId));
            ++i;
            memcpy_s(szzHwId,
                     sizeof(szzHwId) - 2 * sizeof(WCHAR),
                     argv[i], wcslen(argv[i]) * sizeof(WCHAR));
        }
        else
        {
            fwprintf(stderr,
                     L"Unknown option \"%ls"
                     L"\". Please, use \"tapctl help list\" to list supported options. Ignored.\n",
                     argv[i]);
        }
    }

    struct tap_adapter_node *adapter_list = NULL;
    DWORD dwResult = tap_list_adapters(NULL, szzHwId, &adapter_list);
    if (dwResult != ERROR_SUCCESS)
    {
        fwprintf(stderr, L"Enumerating TUN/TAP adapters failed (error 0x%x).\n", dwResult);
        return 1;
    }

    for (struct tap_adapter_node *adapter = adapter_list; adapter; adapter = adapter->pNext)
    {
        LPOLESTR adapter_id = NULL;
        StringFromIID((REFIID)&adapter->guid, &adapter_id);
        const WCHAR *name = adapter->szName ? adapter->szName : L"";
        const WCHAR *hwid = (adapter->szzHardwareIDs && adapter->szzHardwareIDs[0])
                                ? adapter->szzHardwareIDs
                                : L"";
        fwprintf(stdout, L"%ls\t%ls\t%ls\n", adapter_id, name, hwid);
        CoTaskMemFree(adapter_id);
    }

    tap_free_adapter_list(adapter_list);

    return 0;
}

static int
command_delete(int argc, LPCWSTR argv[], BOOL *bRebootRequired)
{
    if (argc < 3)
    {
        fwprintf(stderr,
                 L"Missing adapter GUID or name. Please, use \"tapctl help delete\" for usage info.\n");
        return 1;
    }

    GUID guidAdapter;
    if (FAILED(IIDFromString(argv[2], (LPIID)&guidAdapter)))
    {
        struct tap_adapter_node *adapter_list = NULL;
        DWORD dwResult = tap_list_adapters(NULL, NULL, &adapter_list);
        if (dwResult != ERROR_SUCCESS)
        {
            fwprintf(stderr, L"Enumerating TUN/TAP adapters failed (error 0x%x).\n", dwResult);
            return 1;
        }

        BOOL found = FALSE;
        for (struct tap_adapter_node *adapter = adapter_list; adapter; adapter = adapter->pNext)
        {
            if (wcsicmp(argv[2], adapter->szName) == 0)
            {
                memcpy(&guidAdapter, &adapter->guid, sizeof(GUID));
                found = TRUE;
                break;
            }
        }

        tap_free_adapter_list(adapter_list);

        if (!found)
        {
            fwprintf(stderr, L"\"%ls\" adapter not found.\n", argv[2]);
            return 1;
        }
    }

    DWORD dwResult = tap_delete_adapter(NULL, &guidAdapter, bRebootRequired);
    if (dwResult != ERROR_SUCCESS)
    {
        fwprintf(stderr,
                 L"Deleting adapter \"%ls"
                 L"\" failed (error 0x%x).\n",
                 argv[2], dwResult);
        return 1;
    }

    return 0;
}

/**
 * Program entry point
 */
int __cdecl wmain(int argc, LPCWSTR argv[])
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
            fwprintf(stderr,
                     L"Unknown command \"%ls"
                     L"\". Please, use \"tapctl help\" to list supported commands.\n",
                     argv[2]);
        }

        return 1;
    }
    else if (wcsicmp(argv[1], L"create") == 0)
    {
        iResult = command_create(argc, argv, &bRebootRequired);
        goto quit;
    }
    else if (wcsicmp(argv[1], L"list") == 0)
    {
        iResult = command_list(argc, argv);
        goto quit;
    }
    else if (wcsicmp(argv[1], L"delete") == 0)
    {
        iResult = command_delete(argc, argv, &bRebootRequired);
        goto quit;
    }
    else
    {
        fwprintf(stderr,
                 L"Unknown command \"%ls"
                 L"\". Please, use \"tapctl help\" to list supported commands.\n",
                 argv[1]);
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
        if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER
                              | FORMAT_MESSAGE_IGNORE_INSERTS,
                          0, dwResult, 0, (LPWSTR)&szErrMessage, 0, NULL)
            && szErrMessage)
        {
            /* Trim trailing whitespace. Set terminator after the last non-whitespace character.
             * This prevents excessive trailing line breaks. */
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
