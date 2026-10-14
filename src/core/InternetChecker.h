#pragma once
#include "CheckResult.h"

// Модуль 1. Проверка наличия подключения к Интернету.
// Проверка идёт по уровням: сетевой адаптер -> ICMP (ping) -> DNS -> HTTP.
// Так можно отличить "нет сети" от "нет DNS" и от "интернет есть, но закрыт ping".
class InternetChecker {
public:
    CheckResult run();

private:
    struct PingReply { bool ok = false; unsigned long rttMs = 0; std::wstring error; };

    static std::vector<std::wstring> activeAdapters();
    static PingReply ping(const char* ipv4, unsigned long timeoutMs);
    static bool resolve(const wchar_t* host, std::wstring& ip, std::wstring& error);
    static bool httpProbe(std::wstring& info);
};
