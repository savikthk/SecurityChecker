#include "SecurityCenter.h"
#include "WinCom.h"
#include "Utils.h"
#include <wbemidl.h>
#include <netfw.h>
#include <functional>

namespace {

using RowHandler = std::function<void(IWbemClassObject*)>;

// Выполняет WQL-запрос в пространстве имён WMI и вызывает handler для каждой строки
bool wmiQuery(const wchar_t* ns, const wchar_t* wql, const RowHandler& handler, std::wstring& error)
{
    ComInit com;   // объявлен первым, поэтому уничтожается последним - после всех ComPtr
    ComPtr<IWbemLocator> locator;
    HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IWbemLocator, locator.putVoid());
    if (FAILED(hr)) {
        error = L"служба WMI недоступна: " + util::winErrorText(hr);
        return false;
    }

    ComPtr<IWbemServices> services;
    hr = locator->ConnectServer(Bstr(ns), nullptr, nullptr, nullptr, 0, nullptr, nullptr, services.put());
    if (FAILED(hr)) {
        error = L"нет доступа к " + std::wstring(ns) + L": " + util::winErrorText(hr);
        return false;
    }
    CoSetProxyBlanket(services.get(), RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    ComPtr<IEnumWbemClassObject> rows;
    hr = services->ExecQuery(Bstr(L"WQL"), Bstr(wql),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, rows.put());
    if (FAILED(hr)) {
        error = L"ошибка запроса WMI: " + util::winErrorText(hr);
        return false;
    }

    for (;;) {
        ComPtr<IWbemClassObject> row;
        ULONG got = 0;
        rows->Next(5000, 1, row.put(), &got);
        if (got == 0)
            break;
        handler(row.get());
    }
    return true;
}

std::wstring propString(IWbemClassObject* row, const wchar_t* name)
{
    VARIANT v;
    VariantInit(&v);
    std::wstring s;
    if (SUCCEEDED(row->Get(name, 0, &v, nullptr, nullptr)) && v.vt == VT_BSTR && v.bstrVal)
        s = v.bstrVal;
    VariantClear(&v);
    return s;
}

long propInt(IWbemClassObject* row, const wchar_t* name, long def)
{
    VARIANT v;
    VariantInit(&v);
    long n = def;
    if (SUCCEEDED(row->Get(name, 0, &v, nullptr, nullptr)) && v.vt != VT_NULL && v.vt != VT_EMPTY &&
        SUCCEEDED(VariantChangeType(&v, &v, 0, VT_I4)))
        n = v.lVal;
    VariantClear(&v);
    return n;
}

bool propBool(IWbemClassObject* row, const wchar_t* name)
{
    VARIANT v;
    VariantInit(&v);
    bool b = false;
    if (SUCCEEDED(row->Get(name, 0, &v, nullptr, nullptr)) && v.vt != VT_NULL && v.vt != VT_EMPTY &&
        SUCCEEDED(VariantChangeType(&v, &v, 0, VT_BOOL)))
        b = v.boolVal == VARIANT_TRUE;
    VariantClear(&v);
    return b;
}

// productState имеет вид 0xPPSSDD:
//   SS - состояние защиты (0x10 - включена), DD - базы (0x00 - актуальны, 0x10 - устарели)
SecurityProduct makeProduct(IWbemClassObject* row)
{
    SecurityProduct p;
    p.name = propString(row, L"displayName");
    p.exePath = propString(row, L"pathToSignedProductExe");
    p.state = static_cast<unsigned long>(propInt(row, L"productState", 0));
    p.enabled = ((p.state >> 12) & 0xF) == 1;
    p.upToDate = ((p.state >> 4) & 0xF) == 0;
    return p;
}

}

bool WindowsFirewallStatus::enabledInActiveProfiles() const
{
    bool anyActive = false;
    for (const auto& p : profiles) {
        if (!p.active)
            continue;
        anyActive = true;
        if (!p.enabled)
            return false;
    }
    return anyActive;
}

bool SecurityCenter::antivirusProducts(std::vector<SecurityProduct>& out, std::wstring& error)
{
    return wmiQuery(L"ROOT\\SecurityCenter2",
                    L"SELECT displayName, pathToSignedProductExe, productState FROM AntiVirusProduct",
                    [&](IWbemClassObject* row) { out.push_back(makeProduct(row)); }, error);
}

bool SecurityCenter::firewallProducts(std::vector<SecurityProduct>& out, std::wstring& error)
{
    // Брандмауэр Windows здесь не регистрируется - только сторонние межсетевые экраны
    return wmiQuery(L"ROOT\\SecurityCenter2",
                    L"SELECT displayName, pathToSignedProductExe, productState FROM FirewallProduct",
                    [&](IWbemClassObject* row) { out.push_back(makeProduct(row)); }, error);
}

DefenderStatus SecurityCenter::defenderStatus()
{
    DefenderStatus d;
    wmiQuery(L"ROOT\\Microsoft\\Windows\\Defender", L"SELECT * FROM MSFT_MpComputerStatus",
             [&](IWbemClassObject* row) {
                 d.available = true;
                 d.serviceEnabled = propBool(row, L"AMServiceEnabled");
                 d.antivirusEnabled = propBool(row, L"AntivirusEnabled");
                 d.realTimeEnabled = propBool(row, L"RealTimeProtectionEnabled");
                 d.tamperProtected = propBool(row, L"IsTamperProtected");
                 d.signatureAgeDays = propInt(row, L"AntivirusSignatureAge", -1);
                 d.signatureVersion = propString(row, L"AntivirusSignatureVersion");
                 d.runningMode = propString(row, L"AMRunningMode");
             },
             d.error);
    return d;
}

WindowsFirewallStatus SecurityCenter::windowsFirewall()
{
    WindowsFirewallStatus st;
    ComInit com;
    ComPtr<INetFwPolicy2> policy;
    HRESULT hr = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER,
                                  __uuidof(INetFwPolicy2), policy.putVoid());
    if (FAILED(hr)) {
        st.error = L"интерфейс INetFwPolicy2 недоступен: " + util::winErrorText(hr);
        return st;
    }

    long current = 0;
    policy->get_CurrentProfileTypes(&current);

    const struct { NET_FW_PROFILE_TYPE2 type; const wchar_t* name; } kProfiles[] = {
        { NET_FW_PROFILE2_DOMAIN,  L"доменный" },
        { NET_FW_PROFILE2_PRIVATE, L"частный" },
        { NET_FW_PROFILE2_PUBLIC,  L"общедоступный" },
    };
    for (const auto& k : kProfiles) {
        FirewallProfile p;
        p.name = k.name;
        p.active = (current & k.type) != 0;

        VARIANT_BOOL on = VARIANT_FALSE;
        policy->get_FirewallEnabled(k.type, &on);
        p.enabled = on == VARIANT_TRUE;

        NET_FW_ACTION in = NET_FW_ACTION_BLOCK, out = NET_FW_ACTION_ALLOW;
        policy->get_DefaultInboundAction(k.type, &in);
        policy->get_DefaultOutboundAction(k.type, &out);
        p.blockInbound = in == NET_FW_ACTION_BLOCK;
        p.blockOutbound = out == NET_FW_ACTION_BLOCK;

        VARIANT_BOOL all = VARIANT_FALSE;
        policy->get_BlockAllInboundTraffic(k.type, &all);
        p.blockAllInbound = all == VARIANT_TRUE;

        st.profiles.push_back(p);
    }
    st.available = true;
    return st;
}

std::wstring SecurityCenter::stateText(const SecurityProduct& p, bool antivirus)
{
    std::wstring s = p.enabled ? L"включён" : L"выключен";
    if (antivirus)
        s += p.upToDate ? L", базы актуальны" : L", базы устарели";
    return s;
}
