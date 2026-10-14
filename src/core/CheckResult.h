#pragma once
#include <string>
#include <vector>

// Итог одной проверки
enum class CheckStatus {
    NotRun,   // проверка не выполнялась
    Ok,       // всё в порядке
    Warning,  // есть замечания
    Fail,     // защита не работает
    Error     // проверку не удалось выполнить
};

struct CheckResult {
    CheckStatus status = CheckStatus::NotRun;
    std::wstring summary;                      // краткий вывод (одна строка)
    std::vector<std::wstring> details;         // подробности для отчёта
    std::vector<std::wstring> recommendations; // что сделать пользователю
    double durationSec = 0.0;                  // время выполнения

    void add(const std::wstring& line) { details.push_back(line); }
    void recommend(const std::wstring& line) { recommendations.push_back(line); }
};

inline const wchar_t* statusText(CheckStatus s)
{
    switch (s) {
    case CheckStatus::Ok:      return L"Норма";
    case CheckStatus::Warning: return L"Внимание";
    case CheckStatus::Fail:    return L"Не работает";
    case CheckStatus::Error:   return L"Ошибка";
    default:                   return L"Не выполнялась";
    }
}
