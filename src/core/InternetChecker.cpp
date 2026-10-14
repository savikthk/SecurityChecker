#include "InternetChecker.h"
#include "WinCom.h"
#include "Utils.h"
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <winhttp.h>
#include <cstring>

namespace {

// Узлы для ping: публичные DNS-серверы, которые обычно отвечают на ICMP
struct PingTarget { const char* ip; const wchar_t* name; };
const PingTarget kPingTargets[] = {
    { "77.88.8.8", L"Яндекс DNS" },
    { "8.8.8.8",   L"Google DNS" },
    { "1.1.1.1",   L"Cloudflare DNS" },
};

const wchar_t* const kDnsHosts[] = { L"ya.ru", L"www.google.com" };

// Этот же адрес использует сама Windows (служба NCSI), чтобы понять, есть ли Интернет
const wchar_t* const kProbeHost = L"www.msftconnecttest.com";
const wchar_t* const kProbePath = L"/connecttest.txt";
const char* const kProbeAnswer = "Microsoft Connect Test";

std::wstring widen(const char* s)
{
    return std::wstring(s, s + std::strlen(s));
}

std::wstring adapterType(IFTYPE type)
{
    switch (type) {
    case IF_TYPE_ETHERNET_CSMACD: return L"Ethernet";
    case IF_TYPE_IEEE80211:       return L"Wi-Fi";
    case IF_TYPE_PPP:             return L"PPP";
    case IF_TYPE_WWANPP:
    case IF_TYPE_WWANPP2:         return L"мобильная сеть";
    case IF_TYPE_TUNNEL:          return L"туннель";
    default:                      return L"другой";
    }
}

std::wstring icmpStatusText(unsigned long code)
{
    switch (code) {
    case IP_REQ_TIMED_OUT:         return L"нет ответа (таймаут)";
    case IP_DEST_HOST_UNREACHABLE: return L"узел недоступен";
    case IP_DEST_NET_UNREACHABLE:  return L"сеть недоступна";
    case IP_TTL_EXPIRED_TRANSIT:   return L"истёк TTL";
    case IP_GENERAL_FAILURE:       return L"общая ошибка ICMP";
    default:                       return L"ошибка ICMP, код " + std::to_wstring(code);
    }
}

std::wstring httpErrorText(unsigned long code)
{
    switch (code) {
    case ERROR_WINHTTP_TIMEOUT:            return L"истекло время ожидания";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:  return L"не удалось определить IP-адрес сервера";
    case ERROR_WINHTTP_CANNOT_CONNECT:     return L"не удалось подключиться к серверу";
    case ERROR_WINHTTP_CONNECTION_ERROR:   return L"соединение разорвано";
    case ERROR_WINHTTP_SECURE_FAILURE:     return L"ошибка защищённого соединения";
    default:                               return L"ошибка WinHTTP, код " + std::to_wstring(code);
    }
}

// Дескриптор WinHTTP, который сам закрывается
class HttpHandle {
public:
    explicit HttpHandle(HINTERNET h) : h_(h) {}
    ~HttpHandle() { if (h_) WinHttpCloseHandle(h_); }
    operator HINTERNET() const { return h_; }
    HttpHandle(const HttpHandle&) = delete;
    HttpHandle& operator=(const HttpHandle&) = delete;
private:
    HINTERNET h_;
};

}

CheckResult InternetChecker::run()
{
    CheckResult r;
    WinsockInit wsa;

    // Шаг 1. Есть ли вообще активное подключение к сети
    const auto adapters = activeAdapters();
    r.add(L"Шаг 1. Активные сетевые адаптеры с основным шлюзом: " + std::to_wstring(adapters.size()));
    for (const auto& a : adapters)
        r.add(L"    • " + a);

    // Шаг 2. Доступность внешних узлов по ICMP (команда ping)
    r.add(L"Шаг 2. Проверка ping (ICMP Echo):");
    int pingOk = 0;
    for (const auto& t : kPingTargets) {
        const PingReply p = ping(t.ip, 1500);
        std::wstring line = L"    • " + widen(t.ip) + L" (" + t.name + L") — ";
        if (p.ok) {
            ++pingOk;
            line += L"ответ за " + std::to_wstring(p.rttMs) + L" мс";
        } else {
            line += p.error;
        }
        r.add(line);
    }

    // Шаг 3. Работает ли DNS
    r.add(L"Шаг 3. Разрешение доменных имён (DNS):");
    int dnsOk = 0;
    for (const wchar_t* host : kDnsHosts) {
        std::wstring ip, error;
        if (resolve(host, ip, error)) {
            ++dnsOk;
            r.add(L"    • " + std::wstring(host) + L" → " + ip);
        } else {
            r.add(L"    • " + std::wstring(host) + L" — " + error);
        }
    }

    // Шаг 4. Реальный HTTP-запрос: самый надёжный признак доступа в Интернет
    std::wstring httpInfo;
    const bool httpOk = httpProbe(httpInfo);
    r.add(L"Шаг 4. HTTP-запрос к " + std::wstring(kProbeHost) + L": " + httpInfo);

    if (httpOk) {
        r.status = CheckStatus::Ok;
        r.summary = L"Компьютер подключён к Интернету";
        if (pingOk == 0)
            r.add(L"Примечание: ping не проходит, но HTTP работает — ICMP закрыт сетью или межсетевым экраном.");
    } else if (adapters.empty()) {
        r.status = CheckStatus::Fail;
        r.summary = L"Компьютер не подключён к сети";
        r.recommend(L"Проверьте сетевой кабель или подключение к Wi-Fi.");
        r.recommend(L"Убедитесь, что сетевой адаптер включён в «Параметры → Сеть и Интернет».");
    } else if (pingOk > 0 && dnsOk == 0) {
        r.status = CheckStatus::Warning;
        r.summary = L"Сеть есть, но не работает DNS";
        r.recommend(L"Проверьте адреса DNS-серверов в настройках адаптера (например, 77.88.8.8 или 8.8.8.8).");
        r.recommend(L"Выполните в командной строке: ipconfig /flushdns.");
    } else if (pingOk > 0 || dnsOk > 0) {
        r.status = CheckStatus::Warning;
        r.summary = L"Доступ в Интернет ограничен";
        r.recommend(L"Проверьте настройки прокси-сервера и правила межсетевого экрана для HTTP.");
        r.recommend(L"Если сеть требует авторизации (гостевой Wi-Fi), откройте браузер и войдите.");
    } else {
        r.status = CheckStatus::Fail;
        r.summary = L"Компьютер не подключён к Интернету";
        r.recommend(L"Проверьте подключение роутера к провайдеру.");
        r.recommend(L"Перезагрузите роутер и повторите проверку.");
    }
    return r;
}

std::vector<std::wstring> InternetChecker::activeAdapters()
{
    std::vector<std::wstring> list;
    std::vector<unsigned char> buf;
    ULONG size = 16 * 1024;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.resize(size);
        rc = GetAdaptersAddresses(AF_INET,
                                  GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                  nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()), &size);
    }
    if (rc != NO_ERROR)
        return list;

    for (auto* a = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buf.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp || a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (!a->FirstGatewayAddress)   // без шлюза выйти в Интернет нельзя
            continue;

        std::wstring ip = L"нет IPv4";
        if (a->FirstUnicastAddress) {
            wchar_t text[64] = {};
            auto* sin = reinterpret_cast<sockaddr_in*>(a->FirstUnicastAddress->Address.lpSockaddr);
            InetNtopW(AF_INET, &sin->sin_addr, text, 64);
            ip = text;
        }
        list.push_back(std::wstring(a->FriendlyName) + L" (" + adapterType(a->IfType) + L", " + ip + L")");
    }
    return list;
}

InternetChecker::PingReply InternetChecker::ping(const char* ipv4, unsigned long timeoutMs)
{
    PingReply reply;
    IN_ADDR addr{};
    if (inet_pton(AF_INET, ipv4, &addr) != 1) {
        reply.error = L"неверный адрес";
        return reply;
    }

    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) {
        reply.error = util::winErrorText(GetLastError());
        return reply;
    }

    char data[32] = "SecurityChecker ping";
    std::vector<unsigned char> answer(sizeof(ICMP_ECHO_REPLY) + sizeof(data) + 8);
    DWORD count = IcmpSendEcho(icmp, addr.S_un.S_addr, data, sizeof(data), nullptr,
                               answer.data(), static_cast<DWORD>(answer.size()), timeoutMs);
    if (count > 0) {
        auto* echo = reinterpret_cast<PICMP_ECHO_REPLY>(answer.data());
        if (echo->Status == IP_SUCCESS) {
            reply.ok = true;
            reply.rttMs = echo->RoundTripTime;
        } else {
            reply.error = icmpStatusText(echo->Status);
        }
    } else {
        reply.error = icmpStatusText(GetLastError());
    }
    IcmpCloseHandle(icmp);
    return reply;
}

bool InternetChecker::resolve(const wchar_t* host, std::wstring& ip, std::wstring& error)
{
    ADDRINFOW hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    PADDRINFOW res = nullptr;

    const int rc = GetAddrInfoW(host, nullptr, &hints, &res);
    if (rc != 0 || !res) {
        error = L"не удалось разрешить имя: " + util::winErrorText(rc);
        return false;
    }
    wchar_t text[64] = {};
    InetNtopW(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, text, 64);
    ip = text;
    FreeAddrInfoW(res);
    return true;
}

bool InternetChecker::httpProbe(std::wstring& info)
{
    HttpHandle session(WinHttpOpen(L"SecurityChecker/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                   WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) {
        info = httpErrorText(GetLastError());
        return false;
    }
    WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000);

    HttpHandle connection(WinHttpConnect(session, kProbeHost, INTERNET_DEFAULT_HTTP_PORT, 0));
    HttpHandle request(connection ? WinHttpOpenRequest(connection, L"GET", kProbePath, nullptr,
                                                       WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0)
                                  : nullptr);
    if (!request ||
        !WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request, nullptr)) {
        info = httpErrorText(GetLastError());
        return false;
    }

    DWORD code = 0, len = sizeof(code);
    WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &code, &len, WINHTTP_NO_HEADER_INDEX);

    std::string body;
    char chunk[1024];
    DWORD read = 0;
    while (body.size() < 4096 && WinHttpReadData(request, chunk, sizeof(chunk), &read) && read > 0)
        body.append(chunk, read);

    if (code == 200 && body.find(kProbeAnswer) != std::string::npos) {
        info = L"HTTP " + std::to_wstring(code) + L", ответ сервера корректный";
        return true;
    }
    // Сервер ответил, но не тем текстом: обычно это страница авторизации гостевой сети
    info = L"HTTP " + std::to_wstring(code) + L", ответ подменён (возможно, сеть требует входа)";
    return false;
}
