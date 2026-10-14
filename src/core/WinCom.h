#pragma once
// Небольшие RAII-обёртки для работы с COM (WMI, брандмауэр Windows)
#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <oleauto.h>

// Инициализация COM в текущем потоке (каждая проверка выполняется в своём потоке)
class ComInit {
public:
    ComInit() : hr_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}
    ~ComInit() { if (SUCCEEDED(hr_)) CoUninitialize(); }
    bool ok() const { return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE; }
    ComInit(const ComInit&) = delete;
    ComInit& operator=(const ComInit&) = delete;
private:
    HRESULT hr_;
};

// Умный указатель на COM-интерфейс: сам вызывает Release()
template <class T>
class ComPtr {
public:
    ComPtr() = default;
    ~ComPtr() { reset(); }
    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    T* get() const { return p_; }
    T** put() { reset(); return &p_; }
    void** putVoid() { return reinterpret_cast<void**>(put()); }
    T* operator->() const { return p_; }
    explicit operator bool() const { return p_ != nullptr; }
    void reset() { if (p_) { p_->Release(); p_ = nullptr; } }
private:
    T* p_ = nullptr;
};

// Инициализация Winsock (нужна для сокетов, DNS и ping)
class WinsockInit {
public:
    WinsockInit() { WSADATA d; ok_ = WSAStartup(MAKEWORD(2, 2), &d) == 0; }
    ~WinsockInit() { if (ok_) WSACleanup(); }
    bool ok() const { return ok_; }
    WinsockInit(const WinsockInit&) = delete;
    WinsockInit& operator=(const WinsockInit&) = delete;
private:
    bool ok_;
};

// Строка BSTR, которая сама освобождается
class Bstr {
public:
    explicit Bstr(const wchar_t* s) : b_(SysAllocString(s)) {}
    ~Bstr() { SysFreeString(b_); }
    operator BSTR() const { return b_; }
    Bstr(const Bstr&) = delete;
    Bstr& operator=(const Bstr&) = delete;
private:
    BSTR b_;
};
