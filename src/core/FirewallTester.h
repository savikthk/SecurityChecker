#pragma once
#include "CheckResult.h"

// Модуль 3. Проверка работоспособности межсетевого экрана.
// Пассивная часть: служба брандмауэра, состояние профилей, сторонние МЭ.
// Активная часть (по методическим указаниям - обращение к запрещённому ресурсу):
//   1) соединяемся с тестовым ресурсом - он должен быть доступен;
//   2) добавляем временное правило, запрещающее этой программе доступ к ресурсу;
//   3) соединяемся снова - МЭ обязан заблокировать соединение;
//   4) удаляем правило и убеждаемся, что доступ восстановлен.
// Активная часть требует прав администратора.
class FirewallTester {
public:
    CheckResult run();

private:
    static bool tcpConnect(const std::wstring& ip, unsigned short port, unsigned long timeoutMs, int& wsaError);
    static bool addBlockRule(const std::wstring& exe, const std::wstring& remoteIp, std::wstring& error);
    static void removeBlockRule();
};
