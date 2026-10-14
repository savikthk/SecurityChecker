cmake_minimum_required(VERSION 3.16)
project(SecurityChecker VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Widgets Concurrent)

add_executable(SecurityChecker WIN32
    src/main.cpp

    # Ядро: проверки (чистый C++ + WinAPI, без Qt)
    src/core/CheckResult.h
    src/core/WinCom.h
    src/core/Utils.h            src/core/Utils.cpp
    src/core/InternetChecker.h  src/core/InternetChecker.cpp
    src/core/SecurityCenter.h   src/core/SecurityCenter.cpp
    src/core/ProductDetector.h  src/core/ProductDetector.cpp
    src/core/FirewallTester.h   src/core/FirewallTester.cpp
    src/core/AntivirusTester.h  src/core/AntivirusTester.cpp
    src/core/ReportBuilder.h    src/core/ReportBuilder.cpp

    # Интерфейс (Qt Widgets)
    src/ui/Theme.h
    src/ui/CheckCard.h          src/ui/CheckCard.cpp
    src/ui/MainWindow.h         src/ui/MainWindow.cpp
)

target_include_directories(SecurityChecker PRIVATE src)

target_compile_definitions(SecurityChecker PRIVATE
    UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)

if(MSVC)
    target_compile_options(SecurityChecker PRIVATE /utf-8)
endif()

target_link_libraries(SecurityChecker PRIVATE
    Qt6::Widgets Qt6::Concurrent
    ws2_32 iphlpapi winhttp      # сеть: сокеты, ICMP, HTTP
    ole32 oleaut32 wbemuuid      # COM и WMI
    advapi32 shell32 wevtapi     # службы, UAC, журнал событий
    dwmapi)                      # тёмный заголовок окна

# После сборки копируем рядом с exe библиотеки Qt, чтобы программа запускалась без Qt Creator
get_target_property(QMAKE_EXE Qt6::qmake IMPORTED_LOCATION)
get_filename_component(QT_BIN_DIR "${QMAKE_EXE}" DIRECTORY)
find_program(WINDEPLOYQT windeployqt HINTS "${QT_BIN_DIR}")
if(WINDEPLOYQT)
    add_custom_command(TARGET SecurityChecker POST_BUILD
        COMMAND "${WINDEPLOYQT}" --no-translations --no-system-d3d-compiler --no-opengl-sw
                "$<TARGET_FILE:SecurityChecker>"
        COMMENT "Копирование библиотек Qt (windeployqt)")
endif()
