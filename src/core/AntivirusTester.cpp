#include "AntivirusTester.h"
#include "SecurityCenter.h"
#include "WinCom.h"
#include "Utils.h"
#include <winevt.h>
#include <cstdio>

namespace {

// Стандартная тестовая строка EICAR (www.eicar.org). Не является вирусом:
// антивирусы по соглашению распознают её как тестовую угрозу.
const char kEicar[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

const wchar_t* const kTestFileName = L"eicar_test.txt";

// Результат попытки работы с тестовым файлом
enum class FileState {
    Present,   // файл на месте и читается - антивирус не отреагировал
    Removed,   // файл удалён (помещён в карантин)
    Blocked,   // доступ к файлу заблокирован антивирусом
    Changed,   // содержимое файла изменено (вылечен)
};

bool isAvBlockCode(DWORD code)
{
    return code == ERROR_VIRUS_INFECTED || code == ERROR_VIRUS_DELETED || code == ERROR_ACCESS_DENIED;
}

FileState inspectFile(const std::wstring& path, DWORD& code)
{
    code = 0;
    if (!util::fileExists(path))
        return FileState::Removed;

    // Открытие на чтение само по себе запускает проверку файла резидентным монитором
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND)
            return FileState::Removed;
        if (code == ERROR_SHARING_VIOLATION)   // файл сейчас сканируется - проверим позже
            return FileState::Present;
        return FileState::Blocked;
    }
    char buf[128] = {};
    DWORD read = 0;
    const BOOL ok = ReadFile(h, buf, sizeof(buf) - 1, &read, nullptr);
    if (!ok)
        code = GetLastError();
    CloseHandle(h);
    if (!ok)
        return FileState::Blocked;
    return std::string(buf, read) == kEicar ? FileState::Present : FileState::Changed;
}

std::wstring secondsText(double sec)
{
    wchar_t buf[32];
    swprintf_s(buf, L"%.1f с", sec);
    return buf;
}

}

CheckResult AntivirusTester::run()
{
    CheckResult r;

    // Шаг 1. Антивирусы по данным Центра безопасности
    r.add(L"Шаг 1. Антивирусы в Центре безопасности Windows:");
    std::vector<SecurityProduct> avList;
    std::wstring error;
    bool anyEnabled = false, anyOutdated = false;
    if (SecurityCenter::antivirusProducts(avList, error)) {
        if (avList.empty())
            r.add(L"    • антивирусы не зарегистрированы");
        for (const auto& p : avList) {
            r.add(L"    • " + p.name + L" — " + SecurityCenter::stateText(p, true));
            if (p.enabled) {
                anyEnabled = true;
                if (!p.upToDate)
                    anyOutdated = true;
            }
        }
    } else {
        r.add(L"    • сведения недоступны: " + error);
    }

    // Шаг 2. Microsoft Defender
    const DefenderStatus d = SecurityCenter::defenderStatus();
    if (d.available) {
        r.add(L"Шаг 2. Microsoft Defender:");
        if (!d.runningMode.empty())
            r.add(L"    • режим работы: " + d.runningMode);
        r.add(std::wstring(L"    • служба антивируса: ") + (d.serviceEnabled ? L"работает" : L"не работает"));
        r.add(std::wstring(L"    • защита в реальном времени: ") + (d.realTimeEnabled ? L"включена" : L"ВЫКЛЮЧЕНА"));
        r.add(std::wstring(L"    • защита от подделки: ") + (d.tamperProtected ? L"включена" : L"выключена"));
        if (!d.signatureVersion.empty())
            r.add(L"    • версия баз: " + d.signatureVersion + L", возраст: " +
                  std::to_wstring(d.signatureAgeDays) + L" дн.");
    } else {
        r.add(L"Шаг 2. Microsoft Defender: сведения недоступны (" + d.error + L")");
    }

    // Шаг 3. Тест резидентного монитора файлом EICAR
    const std::wstring path = util::workDir() + kTestFileName;
    DeleteFileW(path.c_str());   // остаток от прошлого запуска
    r.add(L"Шаг 3. Тест резидентного монитора, файл " + path + L":");

    LARGE_INTEGER freq, start, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    auto elapsed = [&] {
        QueryPerformanceCounter(&now);
        return double(now.QuadPart - start.QuadPart) / double(freq.QuadPart);
    };

    FileState state = FileState::Present;
    DWORD code = 0;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        code = GetLastError();
        if (!isAvBlockCode(code)) {
            r.add(L"    3.1. Не удалось создать файл: " + util::winErrorText(code));
            r.status = CheckStatus::Error;
            r.summary = L"Не удалось создать тестовый файл";
            return r;
        }
        state = FileState::Blocked;
        r.add(L"    3.1. Создание файла заблокировано антивирусом: " + util::winErrorText(code));
    } else {
        DWORD written = 0;
        const BOOL ok = WriteFile(h, kEicar, DWORD(sizeof(kEicar) - 1), &written, nullptr);
        if (!ok)
            code = GetLastError();
        CloseHandle(h);
        if (!ok && isAvBlockCode(code)) {
            state = FileState::Blocked;
            r.add(L"    3.1. Запись в файл заблокирована антивирусом: " + util::winErrorText(code));
        } else {
            r.add(L"    3.1. Файл создан, записано " + std::to_wstring(written) + L" байт тестовой строки EICAR.");
        }
    }

    // Ждём реакции антивируса не дольше заданного времени, проверяя файл каждые полсекунды
    if (state == FileState::Present) {
        r.add(L"    3.2. Ожидание реакции антивируса (до " + std::to_wstring(waitSec_) + L" с)...");
        while (elapsed() < waitSec_) {
            util::sleepMs(500);
            state = inspectFile(path, code);
            if (state != FileState::Present)
                break;
        }
    }
    const double reaction = elapsed();

    switch (state) {
    case FileState::Removed:
        r.add(L"    3.3. Файл удалён антивирусом через " + secondsText(reaction) + L" (помещён в карантин).");
        break;
    case FileState::Blocked:
        r.add(L"    3.3. Доступ к файлу заблокирован через " + secondsText(reaction) +
              (code ? L": " + util::winErrorText(code) : std::wstring()) + L".");
        break;
    case FileState::Changed:
        r.add(L"    3.3. Содержимое файла изменено антивирусом через " + secondsText(reaction) + L" (вылечен).");
        break;
    case FileState::Present:
        r.add(L"    3.3. За " + std::to_wstring(waitSec_) + L" с антивирус не отреагировал: файл на месте и читается.");
        break;
    }
    DeleteFileW(path.c_str());   // убираем за собой, если файл остался

    // Шаг 4. Подтверждение по журналу Defender
    std::wstring threat;
    error.clear();
    util::sleepMs(500);   // запись в журнал появляется с небольшой задержкой
    if (defenderLoggedDetection(threat, error))
        r.add(L"Шаг 4. Журнал Microsoft Defender: зафиксировано обнаружение «" + threat + L"».");
    else if (!error.empty())
        r.add(L"Шаг 4. Журнал Microsoft Defender недоступен: " + error);
    else
        r.add(L"Шаг 4. Журнал Microsoft Defender: событий об обнаружении тестового файла нет.");

    // Итог
    const bool detected = state != FileState::Present;
    if (detected) {
        r.summary = L"Антивирус обнаружил тестовый файл EICAR за " + secondsText(reaction);
        if (anyOutdated || (d.available && d.signatureAgeDays > 7)) {
            r.status = CheckStatus::Warning;
            r.recommend(L"Резидентный монитор работает, но базы устарели — обновите их.");
        } else {
            r.status = CheckStatus::Ok;
        }
    } else {
        r.status = CheckStatus::Fail;
        r.summary = L"Резидентная защита не сработала за " + std::to_wstring(waitSec_) + L" с";
        if (!anyEnabled && !(d.available && d.realTimeEnabled))
            r.recommend(L"Включите защиту в реальном времени: «Безопасность Windows → Защита от вирусов и угроз».");
        r.recommend(L"Проверьте, не добавлена ли папка %TEMP% в исключения антивируса.");
        r.recommend(L"Увеличьте время ожидания и повторите проверку.");
    }
    return r;
}

bool AntivirusTester::defenderLoggedDetection(std::wstring& threatName, std::wstring& error)
{
    // 1116 - обнаружена угроза, 1117 - выполнено действие над угрозой; события за последние 3 минуты
    const wchar_t* channel = L"Microsoft-Windows-Windows Defender/Operational";
    const wchar_t* query =
        L"*[System[(EventID=1116 or EventID=1117) and TimeCreated[timediff(@SystemTime) <= 180000]]]";

    EVT_HANDLE results = EvtQuery(nullptr, channel, query, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!results) {
        error = util::winErrorText(GetLastError());
        return false;
    }

    bool found = false;
    EVT_HANDLE events[8];
    DWORD got = 0;
    while (!found && EvtNext(results, 8, events, 1000, 0, &got)) {
        for (DWORD i = 0; i < got; ++i) {
            DWORD used = 0, props = 0;
            EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &used, &props);
            std::vector<wchar_t> xml(used / sizeof(wchar_t) + 1);
            if (!found && EvtRender(nullptr, events[i], EvtRenderEventXml,
                                    DWORD(xml.size() * sizeof(wchar_t)), xml.data(), &used, &props)) {
                const std::wstring text(xml.data());
                if (text.find(L"EICAR") != std::wstring::npos) {
                    found = true;
                    // <Data Name='Threat Name'>Virus:DOS/EICAR_Test_File</Data>
                    const auto key = text.find(L"Threat Name");
                    const auto open = key == std::wstring::npos ? key : text.find(L'>', key);
                    const auto close = open == std::wstring::npos ? open : text.find(L'<', open);
                    threatName = close == std::wstring::npos ? L"EICAR" : text.substr(open + 1, close - open - 1);
                }
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(results);
    return found;
}
