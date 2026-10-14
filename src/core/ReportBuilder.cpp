#include "ReportBuilder.h"
#include "WinCom.h"
#include "Utils.h"
#include <cstdio>

namespace {

// Чем больше число, тем серьёзнее результат
int severity(CheckStatus s)
{
    switch (s) {
    case CheckStatus::Ok:      return 1;
    case CheckStatus::Warning: return 2;
    case CheckStatus::Error:   return 3;
    case CheckStatus::Fail:    return 4;
    default:                   return 0;
    }
}

std::wstring secondsText(double sec)
{
    wchar_t buf[32];
    swprintf_s(buf, L"%.1f с", sec);
    return buf;
}

}

ReportBuilder::SystemInfo ReportBuilder::systemInfo()
{
    SystemInfo info;
    info.dateTime = util::nowText();
    info.computer = util::computerName();
    info.user = util::userName();
    info.os = util::osVersion();
    info.admin = util::isRunningAsAdmin();
    return info;
}

CheckStatus ReportBuilder::overall(const std::vector<ReportItem>& items)
{
    CheckStatus worst = CheckStatus::NotRun;
    for (const auto& item : items) {
        if (severity(item.result.status) > severity(worst))
            worst = item.result.status;
    }
    return worst;
}

std::wstring ReportBuilder::conclusion(CheckStatus overall)
{
    switch (overall) {
    case CheckStatus::Ok:
        return L"Средства защиты компьютера установлены и работают корректно.";
    case CheckStatus::Warning:
        return L"Средства защиты работают, но есть замечания — выполните рекомендации.";
    case CheckStatus::Fail:
        return L"Обнаружены неработающие средства защиты! Компьютер уязвим — выполните рекомендации.";
    case CheckStatus::Error:
        return L"Часть проверок выполнить не удалось — повторите их или запустите программу от имени администратора.";
    default:
        return L"Проверки не выполнялись.";
    }
}

std::wstring ReportBuilder::buildText(const std::vector<ReportItem>& items, const SystemInfo& info)
{
    const std::wstring line(64, L'=');
    const std::wstring thin(64, L'-');

    std::wstring t;
    t += L"РЕЗУЛЬТАТЫ ПРОВЕРКИ СРЕДСТВ ЗАЩИТЫ КОМПЬЮТЕРА\n" + line + L"\n";
    t += L"Дата и время:  " + info.dateTime + L"\n";
    t += L"Компьютер:     " + info.computer + L"\n";
    t += L"Пользователь:  " + info.user + L"\n";
    t += L"ОС:            " + info.os + L"\n";
    t += std::wstring(L"Права:         ") + (info.admin ? L"администратор" : L"обычный пользователь") + L"\n\n";

    int n = 0;
    for (const auto& item : items) {
        const CheckResult& r = item.result;
        t += std::to_wstring(++n) + L". " + item.title + L"\n" + thin + L"\n";
        if (r.status == CheckStatus::NotRun) {
            t += L"   Проверка не выполнялась.\n\n";
            continue;
        }
        t += std::wstring(L"   Результат: ") + statusText(r.status) + L" (" + secondsText(r.durationSec) + L")\n";

        const std::wstring label = L"   Итог:      ";
        const std::wstring indent = L"\n" + std::wstring(label.size(), L' ');
        std::wstring summary = r.summary;   // многострочный итог выводим с отступом
        for (size_t pos = 0; (pos = summary.find(L'\n', pos)) != std::wstring::npos; pos += indent.size())
            summary.replace(pos, 1, indent);
        t += label + summary + L"\n";

        if (!r.details.empty()) {
            t += L"   Подробности:\n";
            for (const auto& d : r.details)
                t += L"     " + d + L"\n";
        }
        if (!r.recommendations.empty()) {
            t += L"   Рекомендации:\n";
            for (const auto& rec : r.recommendations)
                t += L"     - " + rec + L"\n";
        }
        t += L"\n";
    }

    t += line + L"\nОБЩИЙ ВЫВОД: " + conclusion(overall(items)) + L"\n";
    return t;
}

bool ReportBuilder::save(const std::wstring& path, const std::wstring& text, std::wstring& error)
{
    // Переводы строк в формате Windows
    std::wstring crlf;
    crlf.reserve(text.size() + text.size() / 20);
    for (wchar_t c : text) {
        if (c == L'\n')
            crlf += L'\r';
        crlf += c;
    }
    const std::string data = "\xEF\xBB\xBF" + util::toUtf8(crlf);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        error = util::winErrorText(GetLastError());
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(h, data.data(), DWORD(data.size()), &written, nullptr);
    if (!ok)
        error = util::winErrorText(GetLastError());
    CloseHandle(h);
    return ok && written == data.size();
}

std::wstring ReportBuilder::defaultFileName()
{
    SYSTEMTIME t;
    GetLocalTime(&t);
    wchar_t buf[64];
    swprintf_s(buf, L"SecurityReport_%04u-%02u-%02u_%02u-%02u.txt", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute);
    return buf;
}
