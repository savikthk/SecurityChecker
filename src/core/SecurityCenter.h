#pragma once
#include <string>
#include <vector>

// Продукт, зарегистрированный в Центре безопасности Windows (WMI, ROOT\SecurityCenter2)
struct SecurityProduct {
    std::wstring name;
    std::wstring exePath;
    unsigned long state = 0;   // productState - битовая маска состояния
    bool enabled = false;      // защита включена
    bool upToDate = false;     // базы актуальны (имеет смысл для антивирусов)
};

// Состояние встроенного антивируса Microsoft Defender (ROOT\Microsoft\Windows\Defender)
struct DefenderStatus {
    bool available = false;
    bool serviceEnabled = false;     // AMServiceEnabled
    bool antivirusEnabled = false;   // AntivirusEnabled
    bool realTimeEnabled = false;    // RealTimeProtectionEnabled
    bool tamperProtected = false;    // IsTamperProtected
    int signatureAgeDays = -1;       // AntivirusSignatureAge
    std::wstring signatureVersion;   // AntivirusSignatureVersion
    std::wstring runningMode;        // AMRunningMode: Normal / Passive Mode ...
    std::wstring error;
};

// Профиль Брандмауэра Защитника Windows
struct FirewallProfile {
    std::wstring name;
    bool active = false;          // профиль сейчас применяется к сети
    bool enabled = false;         // брандмауэр включён в этом профиле
    bool blockInbound = true;     // входящие по умолчанию блокируются
    bool blockOutbound = false;   // исходящие по умолчанию блокируются
    bool blockAllInbound = false; // "блокировать все входящие подключения"
};

struct WindowsFirewallStatus {
    bool available = false;
    std::vector<FirewallProfile> profiles;
    std::wstring error;

    // Включён ли брандмауэр во всех профилях, которые сейчас активны
    bool enabledInActiveProfiles() const;
};

class SecurityCenter {
public:
    static bool antivirusProducts(std::vector<SecurityProduct>& out, std::wstring& error);
    static bool firewallProducts(std::vector<SecurityProduct>& out, std::wstring& error);
    static DefenderStatus defenderStatus();
    static WindowsFirewallStatus windowsFirewall();

    // "включён, базы актуальны" / "выключен"
    static std::wstring stateText(const SecurityProduct& p, bool antivirus);
};
