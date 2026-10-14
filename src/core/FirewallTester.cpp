#include "FirewallTester.h"
#include "SecurityCenter.h"
#include "WinCom.h"
#include "Utils.h"
#include <ws2tcpip.h>
#include <netfw.h>

namespace {

// Тестовый ресурс: зарезервированный для примеров домен (RFC 2606), порт HTTP
const wchar_t* const kTestHost = L"example.com";
const unsigned short kTestPort = 80;
const wchar_t* const kRuleName = L"SecurityChecker - временное тестовое правило";

std::wstring socketErrorText(int code)
{
    switch (code) {
    case WSAEACCES:       return L"доступ запрещён — соединение заблокировано";
    case WSAETIMEDOUT:    return L"превышено время ожидания";
    case WSAECONNREFUSED: return L"соединение отклонено сервером";
    case WSAENETUNREACH:  return L"сеть недоступна";
    case WSAEHOSTUNREACH: return L"узел недоступен";
    default:              return util::winErrorText(code);
    }
}

bool resolveIpv4(const wchar_t* host, std::wstring& ip)
{
    ADDRINFOW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW res = nullptr;
    if (GetAddrInfoW(host, nullptr, &hints, &res) != 0 || !res)
        return false;
    wchar_t text[64] = {};
    InetNtopW(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, text, 64);
    ip = text;
    FreeAddrInfoW(res);
    return true;
}

// Гарантирует удаление тестового правила при любом выходе из функции
struct RuleGuard {
    void (*remove)();
    ~RuleGuard() { remove(); }
};

}

CheckResult FirewallTester::run()
{
    CheckResult r;
    WinsockInit wsa;

    // Шаг 1. Служба брандмауэра
    std::wstring svcState;
    util::serviceRunning(L"MpsSvc", svcState);
    r.add(L"Шаг 1. Служба «Брандмауэр Защитника Windows» (MpsSvc): " + svcState);

    // Шаг 2. Профили брандмауэра Windows
    r.add(L"Шаг 2. Профили Брандмауэра Защитника Windows:");
    const WindowsFirewallStatus fw = SecurityCenter::windowsFirewall();
    if (fw.available) {
        for (const auto& p : fw.profiles) {
            std::wstring line = L"    • «" + p.name + L"»" + (p.active ? L" (активен)" : L"") + L": ";
            if (!p.enabled) {
                line += L"выключен";
            } else {
                line += L"включён; входящие — ";
                line += p.blockAllInbound ? L"блокируются все" : (p.blockInbound ? L"блокируются" : L"разрешены");
                line += L"; исходящие — ";
                line += p.blockOutbound ? L"блокируются" : L"разрешены";
            }
            r.add(line);
        }
    } else {
        r.add(L"    • недоступен: " + fw.error);
    }
    const bool winFwOn = fw.available && fw.enabledInActiveProfiles();

    // Шаг 3. Сторонние межсетевые экраны
    std::vector<SecurityProduct> third;
    std::wstring error;
    SecurityCenter::firewallProducts(third, error);
    std::wstring thirdName;
    for (const auto& p : third) {
        if (p.enabled && thirdName.empty())
            thirdName = p.name;
    }
    r.add(L"Шаг 3. Сторонний межсетевой экран: " + (thirdName.empty() ? std::wstring(L"не обнаружен") : thirdName));

    if (!winFwOn && thirdName.empty()) {
        r.status = CheckStatus::Fail;
        r.summary = L"Межсетевой экран выключен — компьютер не защищён";
        r.recommend(L"Включите брандмауэр: «Безопасность Windows → Брандмауэр и защита сети».");
        r.recommend(L"Убедитесь, что служба MpsSvc запущена и тип запуска — «Автоматически».");
        return r;
    }

    // Шаг 4. Активный тест
    if (!util::isRunningAsAdmin()) {
        r.add(L"Шаг 4. Активный тест пропущен: для создания тестового правила нужны права администратора.");
        r.status = CheckStatus::Warning;
        r.summary = L"МЭ включён, но активный тест требует прав администратора";
        r.recommend(L"Перезапустите программу от имени администратора, чтобы проверить фильтрацию на практике.");
        return r;
    }
    if (!winFwOn) {
        r.add(L"Шаг 4. Активный тест через правила Брандмауэра Windows неприменим: трафик фильтрует " + thirdName + L".");
        r.status = CheckStatus::Warning;
        r.summary = L"Работает сторонний МЭ " + thirdName + L"; проверьте его журнал";
        r.recommend(L"Проверьте работу стороннего межсетевого экрана его собственными средствами.");
        return r;
    }

    std::wstring ip;
    if (!resolveIpv4(kTestHost, ip)) {
        r.add(L"Шаг 4. Не удалось определить адрес тестового ресурса " + std::wstring(kTestHost) + L".");
        r.status = CheckStatus::Warning;
        r.summary = L"МЭ включён; активный тест невозможен без Интернета";
        r.recommend(L"Проверьте подключение к Интернету и повторите проверку.");
        return r;
    }
    const std::wstring target = std::wstring(kTestHost) + L" (" + ip + L":" + std::to_wstring(kTestPort) + L")";
    r.add(L"Шаг 4. Активный тест — обращение к запрещённому ресурсу " + target + L":");

    int err = 0;
    const bool before = tcpConnect(ip, kTestPort, 4000, err);
    r.add(L"    4.1. Соединение без запрещающего правила: " +
          (before ? std::wstring(L"установлено") : L"не установлено — " + socketErrorText(err)));
    if (!before) {
        r.status = CheckStatus::Warning;
        r.summary = L"МЭ включён; тестовый ресурс недоступен, активный тест не выполнен";
        r.recommend(L"Проверьте подключение к Интернету и повторите проверку.");
        return r;
    }

    removeBlockRule();   // на случай, если правило осталось после аварийного завершения
    if (!addBlockRule(util::exePath(), ip, error)) {
        r.add(L"    4.2. Не удалось создать запрещающее правило: " + error);
        r.status = CheckStatus::Error;
        r.summary = L"Не удалось создать тестовое правило МЭ";
        return r;
    }
    bool blocked = false;
    {
        RuleGuard guard{ &FirewallTester::removeBlockRule };
        r.add(L"    4.2. Добавлено правило «" + std::wstring(kRuleName) + L"»: запрет исходящих TCP-соединений к " + ip);
        util::sleepMs(1000);   // даём брандмауэру применить правило

        const bool during = tcpConnect(ip, kTestPort, 4000, err);
        blocked = !during;
        r.add(L"    4.3. Повторное обращение к запрещённому ресурсу: " +
              (during ? std::wstring(L"СОЕДИНЕНИЕ УСТАНОВЛЕНО — правило не сработало")
                      : L"заблокировано (" + socketErrorText(err) + L")"));
    }
    r.add(L"    4.4. Тестовое правило удалено.");

    util::sleepMs(500);
    const bool after = tcpConnect(ip, kTestPort, 4000, err);
    r.add(L"    4.5. Соединение после удаления правила: " +
          (after ? std::wstring(L"восстановлено") : L"не установлено — " + socketErrorText(err)));

    if (blocked) {
        r.status = CheckStatus::Ok;
        r.summary = L"МЭ работает: обращение к запрещённому ресурсу заблокировано";
    } else {
        r.status = CheckStatus::Fail;
        r.summary = L"МЭ не заблокировал обращение к запрещённому ресурсу";
        r.recommend(L"Сбросьте настройки брандмауэра: «Брандмауэр Защитника Windows → Восстановить значения по умолчанию».");
        r.recommend(L"Проверьте, не отключает ли фильтрацию сторонняя программа или групповая политика.");
    }
    return r;
}

bool FirewallTester::tcpConnect(const std::wstring& ip, unsigned short port, unsigned long timeoutMs, int& wsaError)
{
    wsaError = 0;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) {
        wsaError = WSAGetLastError();
        return false;
    }
    u_long nonBlocking = 1;
    ioctlsocket(s, FIONBIO, &nonBlocking);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    InetPtonW(AF_INET, ip.c_str(), &addr.sin_addr);

    bool ok = false;
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        ok = true;
    } else if (WSAGetLastError() == WSAEWOULDBLOCK) {
        // Ждём завершения подключения не дольше timeoutMs
        fd_set wr, ex;
        FD_ZERO(&wr); FD_ZERO(&ex);
        FD_SET(s, &wr); FD_SET(s, &ex);
        timeval tv{ static_cast<long>(timeoutMs / 1000), static_cast<long>((timeoutMs % 1000) * 1000) };
        const int n = select(0, nullptr, &wr, &ex, &tv);
        if (n > 0 && FD_ISSET(s, &wr)) {
            ok = true;
        } else if (n > 0) {
            int soError = 0, len = sizeof(soError);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &len);
            wsaError = soError;
        } else {
            wsaError = WSAETIMEDOUT;
        }
    } else {
        wsaError = WSAGetLastError();
    }
    closesocket(s);
    return ok;
}

bool FirewallTester::addBlockRule(const std::wstring& exe, const std::wstring& remoteIp, std::wstring& error)
{
    ComInit com;
    ComPtr<INetFwPolicy2> policy;
    ComPtr<INetFwRules> rules;
    ComPtr<INetFwRule> rule;

    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), policy.putVoid());
    if (SUCCEEDED(hr))
        hr = policy->get_Rules(rules.put());
    if (SUCCEEDED(hr))
        hr = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
                              __uuidof(INetFwRule), rule.putVoid());
    if (FAILED(hr)) {
        error = util::winErrorText(hr);
        return false;
    }

    rule->put_Name(Bstr(kRuleName));
    rule->put_Description(Bstr(L"Создано программой SecurityChecker для проверки МЭ и удаляется сразу после теста"));
    rule->put_ApplicationName(Bstr(exe.c_str()));
    rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
    rule->put_RemoteAddresses(Bstr(remoteIp.c_str()));
    rule->put_Direction(NET_FW_RULE_DIR_OUT);
    rule->put_Action(NET_FW_ACTION_BLOCK);
    rule->put_Profiles(NET_FW_PROFILE2_ALL);
    rule->put_Enabled(VARIANT_TRUE);

    hr = rules->Add(rule.get());
    if (FAILED(hr)) {
        error = util::winErrorText(hr);
        return false;
    }
    return true;
}

void FirewallTester::removeBlockRule()
{
    ComInit com;
    ComPtr<INetFwPolicy2> policy;
    ComPtr<INetFwRules> rules;
    if (FAILED(CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                __uuidof(INetFwPolicy2), policy.putVoid())) ||
        FAILED(policy->get_Rules(rules.put())))
        return;

    // Remove удаляет по одному правилу с таким именем - повторяем, пока они есть
    for (int i = 0; i < 10; ++i) {
        ComPtr<INetFwRule> existing;
        if (FAILED(rules->Item(Bstr(kRuleName), existing.put())))
            break;
        rules->Remove(Bstr(kRuleName));
    }
}
