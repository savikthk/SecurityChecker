#pragma once
#include <string>

// Вспомогательные функции
namespace util {

bool isRunningAsAdmin();          // запущена ли программа с правами администратора
bool relaunchAsAdmin();           // перезапуск с запросом прав (окно UAC)
void initComSecurity();           // настройка безопасности COM (один раз, в main)

std::wstring winErrorText(unsigned long code);   // текст системной ошибки по коду
std::string toUtf8(const std::wstring& s);
std::wstring envVar(const wchar_t* name);        // переменная окружения
std::wstring workDir();                          // %TEMP%\SecurityChecker\ (создаётся)

bool fileExists(const std::wstring& path);
bool folderExists(const std::wstring& path);

// Состояние службы Windows: true, если служба запущена.
// В stateText - текстовое состояние ("работает", "остановлена", "не найдена"...)
bool serviceRunning(const wchar_t* serviceName, std::wstring& stateText);

void sleepMs(unsigned long ms);

// Сведения о системе для отчёта
std::wstring exePath();                          // полный путь к SecurityChecker.exe
std::wstring computerName();
std::wstring userName();
std::wstring osVersion();                        // "Windows 10 Pro 22H2 (сборка 19045)"
std::wstring nowText();                          // "14.10.2026 15:30:12"

}
