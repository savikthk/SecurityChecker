#include "Utils.h"
#include "WinCom.h"
#include <shellapi.h>
#include <cstdio>

namespace util {

bool isRunningAsAdmin()
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    // SID группы "Администраторы"
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

bool relaunchAsAdmin()
{
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, path, MAX_PATH))
        return false;

    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.lpVerb = L"runas";          // "runas" вызывает окно UAC
    sei.lpFile = path;
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) == TRUE;
}

void initComSecurity()
{
    // Вызывается в главном потоке до создания окна. Нужна для запросов к WMI.
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);
}

std::wstring winErrorText(unsigned long code)
{
    wchar_t* buf = nullptr;
    DWORD len = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                               FORMAT_MESSAGE_IGNORE_INSERTS,
                               nullptr, code, 0, reinterpret_cast<LPWSTR>(&buf), 0, nullptr);
    std::wstring text = (len && buf) ? std::wstring(buf, len) : L"неизвестная ошибка";
    if (buf)
        LocalFree(buf);
    while (!text.empty() && (text.back() == L'\n' || text.back() == L'\r' ||
                             text.back() == L' ' || text.back() == L'.'))
        text.pop_back();
    // Коды HRESULT (COM, WMI) удобнее читать в шестнадцатеричном виде
    wchar_t num[16];
    if (code & 0x80000000UL)
        swprintf_s(num, L"0x%08lX", code);
    else
        swprintf_s(num, L"%lu", code);
    return text + L" (код " + num + L")";
}

std::string toUtf8(const std::wstring& s)
{
    if (s.empty())
        return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string out(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), &out[0], size, nullptr, nullptr);
    return out;
}

std::wstring envVar(const wchar_t* name)
{
    wchar_t buf[MAX_PATH];
    DWORD len = GetEnvironmentVariableW(name, buf, MAX_PATH);
    return (len > 0 && len < MAX_PATH) ? std::wstring(buf, len) : std::wstring();
}

std::wstring workDir()
{
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring dir = std::wstring(tmp) + L"SecurityChecker\\";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

bool fileExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool folderExists(const std::wstring& path)
{
    DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

bool serviceRunning(const wchar_t* serviceName, std::wstring& stateText)
{
    stateText = L"нет доступа к диспетчеру служб";
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    bool running = false;
    SC_HANDLE svc = OpenServiceW(scm, serviceName, SERVICE_QUERY_STATUS);
    if (!svc) {
        stateText = L"служба не найдена";
    } else {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD needed = 0;
        if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp),
                                 sizeof(ssp), &needed)) {
            switch (ssp.dwCurrentState) {
            case SERVICE_RUNNING:       stateText = L"работает"; running = true; break;
            case SERVICE_STOPPED:       stateText = L"остановлена"; break;
            case SERVICE_START_PENDING: stateText = L"запускается"; break;
            case SERVICE_STOP_PENDING:  stateText = L"останавливается"; break;
            case SERVICE_PAUSED:        stateText = L"приостановлена"; break;
            default:                    stateText = L"неизвестное состояние"; break;
            }
        }
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

void sleepMs(unsigned long ms)
{
    Sleep(ms);
}

std::wstring exePath()
{
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::wstring(path, len);
}

std::wstring computerName()
{
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD len = MAX_COMPUTERNAME_LENGTH + 1;
    return GetComputerNameW(buf, &len) ? std::wstring(buf, len) : L"неизвестно";
}

std::wstring userName()
{
    wchar_t buf[257];
    DWORD len = 257;
    return GetUserNameW(buf, &len) ? std::wstring(buf) : L"неизвестно";
}

static std::wstring regString(const wchar_t* key, const wchar_t* value)
{
    wchar_t buf[256];
    DWORD size = sizeof(buf);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, nullptr, buf, &size) != ERROR_SUCCESS)
        return {};
    return buf;
}

std::wstring osVersion()
{
    const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    std::wstring name = regString(key, L"ProductName");
    const std::wstring display = regString(key, L"DisplayVersion");
    const std::wstring build = regString(key, L"CurrentBuild");

    // В реестре Windows 11 по-прежнему записано "Windows 10", отличаем по номеру сборки
    if (!build.empty() && std::stoi(build) >= 22000) {
        const auto pos = name.find(L"Windows 10");
        if (pos != std::wstring::npos)
            name.replace(pos, 10, L"Windows 11");
    }
    std::wstring text = name.empty() ? L"Windows" : name;
    if (!display.empty())
        text += L" " + display;
    if (!build.empty())
        text += L" (сборка " + build + L")";
    return text;
}

std::wstring nowText()
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t buf[32];
    swprintf_s(buf, L"%02u.%02u.%04u %02u:%02u:%02u", t.wDay, t.wMonth, t.wYear, t.wHour, t.wMinute, t.wSecond);
    return buf;
}

}
