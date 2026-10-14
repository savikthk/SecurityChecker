#pragma once
#include "CheckResult.h"

// Одна строка отчёта: название проверки и её результат
struct ReportItem {
    std::wstring title;
    CheckResult result;
};

// Модуль 5. Формирование отчёта о проверках и сохранение его в файл.
class ReportBuilder {
public:
    // Сведения о компьютере для шапки отчёта
    struct SystemInfo {
        std::wstring dateTime, computer, user, os;
        bool admin = false;
    };
    static SystemInfo systemInfo();

    // Общий итог - худший статус среди выполненных проверок
    static CheckStatus overall(const std::vector<ReportItem>& items);
    static std::wstring conclusion(CheckStatus overall);

    // Текст отчёта для сохранения в файл
    static std::wstring buildText(const std::vector<ReportItem>& items, const SystemInfo& info);

    // Сохранение в UTF-8 (с BOM, чтобы Блокнот корректно показал кириллицу)
    static bool save(const std::wstring& path, const std::wstring& text, std::wstring& error);

    // Имя файла по умолчанию: SecurityReport_2026-10-14_15-30.txt
    static std::wstring defaultFileName();
};
