#define _WIN32_WINNT 0x0500
#include <windows.h>
#include <string>
#include <clocale>
#include <tlhelp32.h>

void debaka_show_version(void)
{
    printf("debaka version 0.0 by katahiromz\n");
}

void debaka_show_usage(void)
{
    printf(
        "debaka --- Debugger\n"
        "Usage: debaka --pid PID\n"
        "Usage: debaka --cmdline ...\n"
        "Usage: debaka --proc-list\n"
        "\n"
        "Options:\n"
        "  --help          Show this message.\n"
        "  --version       Show version info.\n"
        "  --pid PID       Specify the process ID to attach.\n"
        "  --cmdline ...   Specify the command line to debug.\n"
        "  --proc-list     Show process list.\n");
}

#define FLAG_HELP (1 << 0)
#define FLAG_VERSION (1 << 1)
#define FLAG_PROC_LIST (1 << 2)

typedef struct DEBAKA
{
    DWORD dwFlags = 0;
    std::wstring cmdline;
    DWORD pid = 0;
} DEBAKA;

int debaka_debug(HANDLE hProcess)
{
    DEBUG_EVENT event = { 0 };

    while (WaitForDebugEvent(&event, INFINITE))
    {
        auto& PID = event.dwProcessId;
        auto& TID = event.dwThreadId;
        EXCEPTION_DEBUG_INFO& Exception = event.u.Exception;
        DWORD dwContinueStatus = DBG_CONTINUE;

        switch (event.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
            switch (Exception.ExceptionRecord.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                printf("[pid %lu] [tid %lu] EXCEPTION_ACCESS_VIOLATION\n", PID, TID);
                break;
            case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
                printf("[pid %lu] [tid %lu] EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n", PID, TID);
                break;
            case EXCEPTION_BREAKPOINT:
                printf("[pid %lu] [tid %lu] EXCEPTION_BREAKPOINT\n", PID, TID);
                break;
            case EXCEPTION_DATATYPE_MISALIGNMENT:
                printf("[pid %lu] [tid %lu] EXCEPTION_DATATYPE_MISALIGNMENT\n", PID, TID);
                break;
            case EXCEPTION_FLT_DENORMAL_OPERAND:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_DENORMAL_OPERAND\n", PID, TID);
                break;
            case EXCEPTION_FLT_DIVIDE_BY_ZERO:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_DIVIDE_BY_ZERO\n", PID, TID);
                break;
            case EXCEPTION_FLT_INEXACT_RESULT:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_INEXACT_RESULT\n", PID, TID);
                break;
            case EXCEPTION_FLT_INVALID_OPERATION:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_INVALID_OPERATION\n", PID, TID);
                break;
            case EXCEPTION_FLT_OVERFLOW:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_OVERFLOW\n", PID, TID);
                break;
            case EXCEPTION_FLT_STACK_CHECK:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_STACK_CHECK\n", PID, TID);
                break;
            case EXCEPTION_FLT_UNDERFLOW:
                printf("[pid %lu] [tid %lu] EXCEPTION_FLT_UNDERFLOW\n", PID, TID);
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                printf("[pid %lu] [tid %lu] EXCEPTION_ILLEGAL_INSTRUCTION\n", PID, TID);
                break;
            case EXCEPTION_IN_PAGE_ERROR:
                printf("[pid %lu] [tid %lu] EXCEPTION_IN_PAGE_ERROR\n", PID, TID);
                break;
            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                printf("[pid %lu] [tid %lu] EXCEPTION_INT_DIVIDE_BY_ZERO\n", PID, TID);
                break;
            case EXCEPTION_INT_OVERFLOW:
                printf("[pid %lu] [tid %lu] EXCEPTION_INT_OVERFLOW\n", PID, TID);
                break;
            case EXCEPTION_INVALID_DISPOSITION:
                printf("[pid %lu] [tid %lu] EXCEPTION_INVALID_DISPOSITION\n", PID, TID);
                break;
            case EXCEPTION_NONCONTINUABLE_EXCEPTION:
                printf("[pid %lu] [tid %lu] EXCEPTION_NONCONTINUABLE_EXCEPTION\n", PID, TID);
                break;
            case EXCEPTION_PRIV_INSTRUCTION:
                printf("[pid %lu] [tid %lu] EXCEPTION_PRIV_INSTRUCTION\n", PID, TID);
                break;
            case EXCEPTION_SINGLE_STEP:
                printf("[pid %lu] [tid %lu] EXCEPTION_SINGLE_STEP\n", PID, TID);
                break;
            case EXCEPTION_STACK_OVERFLOW:
                printf("[pid %lu] [tid %lu] EXCEPTION_STACK_OVERFLOW\n", PID, TID);
                break;
            case EXCEPTION_GUARD_PAGE:
                printf("[pid %lu] [tid %lu] EXCEPTION_GUARD_PAGE\n", PID, TID);
                break;
            case EXCEPTION_INVALID_HANDLE:
                printf("[pid %lu] [tid %lu] EXCEPTION_INVALID_HANDLE\n", PID, TID);
                break;
            case CONTROL_C_EXIT:
                printf("[pid %lu] [tid %lu] CONTROL_C_EXIT\n", PID, TID);
                break;
            default:
                break;
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            {
                CREATE_THREAD_DEBUG_INFO& CreateThread = event.u.CreateThread;
                printf("[pid %lu] [tid %lu] CREATE_THREAD_DEBUG_EVENT\n", PID, TID);
            }
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            {
                CREATE_PROCESS_DEBUG_INFO& CreateProcessInfo = event.u.CreateProcessInfo;
                printf("[pid %lu] [tid %lu] CREATE_PROCESS_DEBUG_EVENT\n", PID, TID);
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            {
                EXIT_THREAD_DEBUG_INFO& ExitThread = event.u.ExitThread;
                printf("[pid %lu] [tid %lu] EXIT_THREAD_DEBUG_EVENT\n", PID, TID);
            }
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            {
                EXIT_PROCESS_DEBUG_INFO& ExitProcess = event.u.ExitProcess;
                printf("[pid %lu] [tid %lu] EXIT_PROCESS_DEBUG_EVENT (dwExitCode: %ld)\n",
                       PID, TID, ExitProcess.dwExitCode);
                return EXIT_SUCCESS;
            }
        case LOAD_DLL_DEBUG_EVENT:
            {
                LOAD_DLL_DEBUG_INFO& LoadDll = event.u.LoadDll;
                printf("[pid %lu] [tid %lu] LOAD_DLL_DEBUG_EVENT\n", PID, TID);
            }
            break;
        case UNLOAD_DLL_DEBUG_EVENT:
            {
                UNLOAD_DLL_DEBUG_INFO& UnloadDll = event.u.UnloadDll;
                printf("[pid %lu] [tid %lu] UNLOAD_DLL_DEBUG_EVENT\n", PID, TID);
            }
            break;
        case OUTPUT_DEBUG_STRING_EVENT:
            {
                OUTPUT_DEBUG_STRING_INFO& DebugString = event.u.DebugString;
                //printf("OUTPUT_DEBUG_STRING_EVENT\n");
                if (DebugString.fUnicode)
                {
                    std::wstring str;
                    str.resize(DebugString.nDebugStringLength);
                    DWORD got;
                    ReadProcessMemory(hProcess, DebugString.lpDebugStringData, &str[0],
                                      DebugString.nDebugStringLength * 2, &got);
                    printf("[pid %lu] [tid %lu] OUTPUT_DEBUG_STRING_EVENT: %ls\n",
                           PID, TID, str.c_str());
                }
                else
                {
                    std::string str;
                    str.resize(DebugString.nDebugStringLength);
                    DWORD got;
                    ReadProcessMemory(hProcess, DebugString.lpDebugStringData, &str[0],
                                      DebugString.nDebugStringLength, &got);
                    printf("[pid %lu] [tid %lu] OUTPUT_DEBUG_STRING_EVENT: %s\n",
                           PID, TID, str.c_str());
                }
            }
            break;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, dwContinueStatus);
    }

    return EXIT_SUCCESS;
}

int debaka_proc_list(void)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return EXIT_FAILURE;

    PROCESSENTRY32W pe32 = { sizeof(pe32) };
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            printf("[pid %lu] %ls\n", pe32.th32ProcessID, pe32.szExeFile);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    return EXIT_SUCCESS;
}

int debaka_do(DEBAKA& debaka)
{
    auto& dwFlags = debaka.dwFlags;
    auto& pid = debaka.pid;
    auto& cmdline = debaka.cmdline;

    if (dwFlags & FLAG_HELP)
    {
        debaka_show_usage();
        return EXIT_SUCCESS;
    }
    if (dwFlags & FLAG_VERSION)
    {
        debaka_show_version();
        return EXIT_SUCCESS;
    }
    if (dwFlags & FLAG_PROC_LIST)
    {
        return debaka_proc_list();
    }
    if ((pid && cmdline.size()) || (!pid && cmdline.empty()))
    {
        fprintf(stderr, "ERROR: Specify either --pid or --cmdline.\n");
        return EXIT_FAILURE;
    }

    if (pid)
    {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, TRUE, pid);
        return debaka_debug(hProcess);
    }

    if (cmdline.size())
    {
        STARTUPINFOW si = { sizeof(si) };
        PROCESS_INFORMATION pi = { NULL };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWDEFAULT;
        if (!CreateProcessW(NULL, &cmdline[0], NULL, NULL, TRUE,
                            DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, NULL, NULL,
                            &si, &pi))
        {
            fprintf(stderr, "ERROR: Cannot create process --- '%ls'.\n", cmdline.c_str());
            return EXIT_FAILURE;
        }

        return debaka_debug(pi.hProcess);
    }

    debaka_show_usage();
    return EXIT_FAILURE;
}

int wmain(int argc, wchar_t **argv)
{
    if (argc <= 1)
    {
        debaka_show_usage();
        return EXIT_SUCCESS;
    }

    std::setlocale(LC_CTYPE, "");

    DEBAKA debaka;
    auto& dwFlags = debaka.dwFlags;
    auto& pid = debaka.pid;
    auto& cmdline = debaka.cmdline;

    for (int iarg = 1; iarg < argc; ++iarg)
    {
        auto arg = argv[iarg];
        if (arg[0] == L'-' || arg[0] == L'/')
        {
            if (lstrcmpiW(&arg[1], L"?") == 0 ||
                lstrcmpiW(&arg[1], L"help") == 0 ||
                lstrcmpiW(&arg[1], L"-help") == 0)
            {
                dwFlags |= FLAG_HELP;
                continue;
            }
            if (lstrcmpiW(&arg[1], L"V") == 0 ||
                lstrcmpiW(&arg[1], L"version") == 0 ||
                lstrcmpiW(&arg[1], L"-version") == 0)
            {
                dwFlags |= FLAG_VERSION;
                continue;
            }
            if (lstrcmpiW(&arg[1], L"pid") == 0 ||
                lstrcmpiW(&arg[1], L"-pid") == 0)
            {
                if (iarg + 1 < argc)
                {
                    ++iarg;
                    pid = wcstoul(argv[iarg], NULL, 0);
                }
                else
                {
                    fprintf(stderr, "ERROR: --pid needs an argument.\n");
                    return EXIT_FAILURE;
                }
                continue;
            }
            if (lstrcmpiW(&arg[1], L"proc-list") == 0 ||
                lstrcmpiW(&arg[1], L"-proc-list") == 0)
            {
                dwFlags |= FLAG_PROC_LIST;
                continue;
            }
            if (lstrcmpiW(&arg[1], L"cmdline") == 0 ||
                lstrcmpiW(&arg[1], L"-cmdline") == 0)
            {
                if (iarg + 1 < argc)
                {
                    ++iarg;
                    for (; iarg < argc; ++iarg)
                    {
                        if (cmdline.size())
                            cmdline += L' ';
                        std::wstring arg = argv[iarg];
                        if (arg.find_first_of(L" \t") != arg.npos)
                        {
                            cmdline += L'\"';
                            cmdline += arg;
                            cmdline += L'\"';
                        }
                        else
                        {
                            cmdline += arg;
                        }
                    }
                    break;
                }
                else
                {
                    fprintf(stderr, "ERROR: --cmdline needs the command line.\n");
                    return EXIT_FAILURE;
                }
            }
        }

        fprintf(stderr, "ERROR: Invalid argument '%ls'.\n", arg);
        return EXIT_FAILURE;
    }

    return debaka_do(debaka);
}

int main(int argc, char **argv)
{
    INT my_argc;
    LPWSTR *my_argv = CommandLineToArgvW(GetCommandLineW(), &my_argc);
    INT ret = wmain(my_argc, my_argv);
    LocalFree(my_argv);
    return ret;
}
