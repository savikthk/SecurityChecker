#include "ProductDetector.h"
#include "SecurityCenter.h"
#include "WinCom.h"
#include "Utils.h"
#include <iterator>

namespace {

enum Kind { AV = 1, FW = 2 };

// Известные средства защиты и пути, по которым их можно обнаружить на диске
struct KnownProduct { const wchar_t* name; int kind; const wchar_t* path; };
const KnownProduct kKnownProducts[] = {
    { L"Microsoft Defender",           AV,      L"%ProgramFiles%\\Windows Defender\\MpCmdRun.exe" },
    { L"Брандмауэр Защитника Windows", FW,      L"%SystemRoot%\\System32\\mpssvc.dll" },
    { L"Kaspersky",                    AV | FW, L"%ProgramFiles(x86)%\\Kaspersky Lab" },
    { L"ESET",                         AV | FW, L"%ProgramFiles%\\ESET" },
    { L"Dr.Web",                       AV | FW, L"%ProgramFiles%\\DrWeb" },
    { L"Avast",                        AV | FW, L"%ProgramFiles%\\Avast Software" },
    { L"AVG",                          AV | FW, L"%ProgramFiles%\\AVG" },
    { L"Avira",                        AV,      L"%ProgramFiles%\\Avira" },
    { L"Bitdefender",                  AV | FW, L"%ProgramFiles%\\Bitdefender" },
    { L"Norton",                       AV | FW, L"%ProgramFiles%\\Norton" },
    { L"McAfee",                       AV | FW, L"%ProgramFiles%\\McAfee" },
    { L"COMODO",                       AV | FW, L"%ProgramFiles%\\COMODO" },
    { L"Malwarebytes",                 AV,      L"%ProgramFiles%\\Malwarebytes" },
};

// Службы Windows, связанные с защитой
struct ServiceInfo { const wchar_t* name; const wchar_t* title; };
const ServiceInfo kServices[] = {
    { L"WinDefend", L"Служба антивирусной программы Microsoft Defender" },
    { L"MpsSvc",    L"Брандмауэр Защитника Windows" },
    { L"wscsvc",    L"Центр обеспечения безопасности" },
};

std::wstring expand(const wchar_t* path)
{
    wchar_t buf[MAX_PATH];
    DWORD len = ExpandEnvironmentStringsW(path, buf, MAX_PATH);
    return (len > 0 && len <= MAX_PATH) ? std::wstring(buf) : std::wstring(path);
}

std::wstring kindText(int kind)
{
    if (kind == (AV | FW)) return L"антивирус + МЭ";
    return kind == AV ? L"антивирус" : L"межсетевой экран";
}

std::wstring joinNames(const std::vector<std::wstring>& names)
{
    std::wstring s;
    for (const auto& n : names)
        s += (s.empty() ? L"" : L", ") + n;
    return s;
}

}

CheckResult ProductDetector::run()
{
    CheckResult r;

    std::vector<std::wstring> avActive, avInactive;   // имена антивирусов
    std::vector<std::wstring> fwActive, fwInactive;   // имена межсетевых экранов
    bool avOutdated = false;

    // Источник 1. Центр безопасности Windows
    r.add(L"Источник 1. Центр безопасности Windows (WMI, ROOT\\SecurityCenter2):");
    std::vector<SecurityProduct> avList, fwList;
    std::wstring error;
    if (SecurityCenter::antivirusProducts(avList, error)) {
        if (avList.empty())
            r.add(L"    • антивирусы не зарегистрированы");
        for (const auto& p : avList) {
            r.add(L"    • Антивирус: " + p.name + L" — " + SecurityCenter::stateText(p, true));
            (p.enabled ? avActive : avInactive).push_back(p.name);
            if (p.enabled && !p.upToDate)
                avOutdated = true;
        }
    } else {
        r.add(L"    • сведения об антивирусах недоступны: " + error);
    }
    error.clear();
    if (SecurityCenter::firewallProducts(fwList, error)) {
        if (fwList.empty())
            r.add(L"    • сторонние межсетевые экраны не зарегистрированы");
        for (const auto& p : fwList) {
            r.add(L"    • Межсетевой экран: " + p.name + L" — " + SecurityCenter::stateText(p, false));
            (p.enabled ? fwActive : fwInactive).push_back(p.name);
        }
    } else {
        r.add(L"    • сведения о межсетевых экранах недоступны: " + error);
    }

    // Источник 2. Брандмауэр Защитника Windows
    r.add(L"Источник 2. Брандмауэр Защитника Windows (INetFwPolicy2):");
    const WindowsFirewallStatus winFw = SecurityCenter::windowsFirewall();
    if (winFw.available) {
        for (const auto& p : winFw.profiles)
            r.add(L"    • Профиль «" + p.name + L"»" + (p.active ? L" (активен)" : L"") + L": " +
                  (p.enabled ? L"включён" : L"выключен"));
        (winFw.enabledInActiveProfiles() ? fwActive : fwInactive).push_back(L"Брандмауэр Защитника Windows");
    } else {
        r.add(L"    • недоступен: " + winFw.error);
    }

    // Источник 3. Файлы и папки установленных программ
    r.add(L"Источник 3. Поиск файлов установленных средств защиты:");
    int filesFound = 0;
    bool avFiles = false, fwFiles = false;
    for (const auto& k : kKnownProducts) {
        const std::wstring path = expand(k.path);
        if (util::fileExists(path) || util::folderExists(path)) {
            ++filesFound;
            if (k.kind & AV) avFiles = true;
            if (k.kind & FW) fwFiles = true;
            r.add(L"    • найден " + std::wstring(k.name) + L" (" + kindText(k.kind) + L"): " + path);
        }
    }
    r.add(L"    Проверено продуктов: " + std::to_wstring(std::size(kKnownProducts)) +
          L", найдено: " + std::to_wstring(filesFound));

    // Источник 4. Службы Windows
    r.add(L"Источник 4. Службы Windows:");
    for (const auto& s : kServices) {
        std::wstring state;
        util::serviceRunning(s.name, state);
        r.add(L"    • " + std::wstring(s.title) + L" (" + s.name + L"): " + state);
    }

    // Итог
    const bool avInstalled = !avActive.empty() || !avInactive.empty() || avFiles;
    const bool fwInstalled = !fwActive.empty() || !fwInactive.empty() || fwFiles;

    std::wstring avText = !avActive.empty()   ? joinNames(avActive)
                        : !avInactive.empty() ? joinNames(avInactive) + L" (выключен)"
                        : avFiles             ? L"найден по файлам"
                                              : L"не установлен";
    std::wstring fwText = !fwActive.empty()   ? joinNames(fwActive)
                        : !fwInactive.empty() ? joinNames(fwInactive) + L" (выключен)"
                        : fwFiles             ? L"найден по файлам"
                                              : L"не установлен";
    r.summary = L"АВ: " + avText + L"\nМЭ: " + fwText;

    if (!avInstalled || !fwInstalled) {
        r.status = CheckStatus::Fail;
        if (!avInstalled)
            r.recommend(L"Установите антивирус (или включите встроенный Microsoft Defender).");
        if (!fwInstalled)
            r.recommend(L"Установите межсетевой экран или включите Брандмауэр Защитника Windows.");
    } else if (avActive.empty() || fwActive.empty() || avOutdated) {
        r.status = CheckStatus::Warning;
        if (avActive.empty())
            r.recommend(L"Антивирус установлен, но выключен — включите защиту в его настройках.");
        if (fwActive.empty())
            r.recommend(L"Межсетевой экран выключен — включите его: «Безопасность Windows → Брандмауэр и защита сети».");
        if (avOutdated)
            r.recommend(L"Обновите антивирусные базы.");
    } else {
        r.status = CheckStatus::Ok;
    }
    return r;
}
