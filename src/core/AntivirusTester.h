#pragma once
#include "CheckResult.h"

// Модуль 4. Проверка работоспособности антивирусного ПО.
// 1) Состояние антивирусов по данным Центра безопасности Windows.
// 2) Состояние Microsoft Defender: защита в реальном времени, возраст баз.
// 3) Тест резидентного монитора (по методическим указаниям): создаётся файл *.txt
//    со стандартной тестовой строкой EICAR, и в течение заданного времени
//    проверяется, удалил или заблокировал ли его антивирус.
// 4) Подтверждение обнаружения по журналу событий Microsoft Defender.
class AntivirusTester {
public:
    explicit AntivirusTester(int waitSec = 10) : waitSec_(waitSec) {}
    CheckResult run();

private:
    // Ищет в журнале Defender событие об обнаружении тестового файла за последние минуты
    static bool defenderLoggedDetection(std::wstring& threatName, std::wstring& error);

    int waitSec_;
};
