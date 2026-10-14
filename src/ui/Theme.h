#pragma once
// Оформление приложения: цвета, таблица стилей (QSS) и значки
#include <QColor>
#include <QFont>
#include <QIcon>
#include <QPainter>
#include <QPixmap>
#include <QString>
#include "core/CheckResult.h"

namespace theme {

// Палитра (тёмная тема)
inline const QColor kBg       ("#0E1118");
inline const QColor kSurface  ("#151A25");
inline const QColor kSurface2 ("#10141D");
inline const QColor kBorder   ("#232A3A");
inline const QColor kText     ("#E6E9F0");
inline const QColor kMuted    ("#8B94A8");
inline const QColor kAccent   ("#5B8CFF");
inline const QColor kAccent2  ("#8B5CF6");
inline const QColor kOk       ("#2ECC8F");
inline const QColor kWarn     ("#F5B544");
inline const QColor kFail     ("#FF5D6C");
inline const QColor kError    ("#B18CFF");
inline const QColor kIdle     ("#5F687C");

// Шрифт значков Windows 10/11
inline const char* kIconFont = "Segoe MDL2 Assets";

// Коды значков Segoe MDL2 Assets
namespace glyph {
inline const QChar Shield   (0xEA18);
inline const QChar Globe    (0xE774);
inline const QChar Search   (0xE721);
inline const QChar Lock     (0xE72E);
inline const QChar Bug      (0xEBE8);
inline const QChar Play     (0xE768);
inline const QChar Document (0xE8A5);
inline const QChar Save     (0xE74E);
inline const QChar Power    (0xE7E8);
inline const QChar Admin    (0xE7EF);
inline const QChar Clock    (0xE823);
}

inline QColor statusColor(CheckStatus s)
{
    switch (s) {
    case CheckStatus::Ok:      return kOk;
    case CheckStatus::Warning: return kWarn;
    case CheckStatus::Fail:    return kFail;
    case CheckStatus::Error:   return kError;
    default:                   return kIdle;
    }
}

// Значение динамического свойства status для QSS
inline QString statusKey(CheckStatus s)
{
    switch (s) {
    case CheckStatus::Ok:      return "ok";
    case CheckStatus::Warning: return "warn";
    case CheckStatus::Fail:    return "fail";
    case CheckStatus::Error:   return "error";
    default:                   return "idle";
    }
}

// Значок из шрифта Segoe MDL2 Assets для кнопок
inline QIcon glyphIcon(QChar g, const QColor& color, int size = 16)
{
    const qreal dpr = 2.0;
    QPixmap pm(int(size * dpr), int(size * dpr));
    pm.setDevicePixelRatio(dpr);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::TextAntialiasing);
    QFont f(kIconFont);
    f.setPixelSize(int(size * 0.85));
    p.setFont(f);
    p.setPen(color);
    p.drawText(QRectF(0, 0, size, size), Qt::AlignCenter, QString(g));
    return QIcon(pm);
}

inline QString styleSheet()
{
    return QStringLiteral(R"(
* { font-family: "Segoe UI"; color: #E6E9F0; }
QMainWindow, #central { background: #0E1118; }
QToolTip { background: #1C2230; color: #E6E9F0; border: 1px solid #2A3245; padding: 6px; }

/* ---------- Шапка ---------- */
#header {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #161D2E, stop:1 #1B1631);
    border: 1px solid #262E40; border-radius: 18px;
}
#logo {
    font-family: "Segoe MDL2 Assets"; font-size: 26px; color: white;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #5B8CFF, stop:1 #8B5CF6);
    border-radius: 16px; min-width: 56px; max-width: 56px; min-height: 56px; max-height: 56px;
}
#appTitle { font-size: 22px; font-weight: 700; }
#appSubtitle { color: #8B94A8; font-size: 13px; }

#chip { border-radius: 13px; padding: 5px 12px; font-size: 12px; font-weight: 600; }
#chip[status="ok"]   { background: rgba(46, 204, 143, 36); color: #2ECC8F; }
#chip[status="warn"] { background: rgba(245, 181, 68, 36); color: #F5B544; }

/* ---------- Кнопки ---------- */
QPushButton {
    background: #1E2433; border: 1px solid #2A3245; border-radius: 10px;
    padding: 9px 16px; font-size: 13px; font-weight: 600;
}
QPushButton:hover   { background: #252C3E; border-color: #3A4560; }
QPushButton:pressed { background: #1A1F2C; }
QPushButton:disabled { color: #4F586B; background: #171B26; border-color: #20263A; }

QPushButton#primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #5B8CFF, stop:1 #8B5CF6);
    border: none; color: white; padding: 12px 22px; font-size: 14px;
}
QPushButton#primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #739DFF, stop:1 #9C74F8);
}
QPushButton#primary:disabled { background: #262D45; color: #6F7894; }

QPushButton#accent { border-color: #3B4E85; background: rgba(91, 140, 255, 30); color: #A9C1FF; }
QPushButton#accent:hover { background: rgba(91, 140, 255, 55); }

QPushButton#danger:hover { background: rgba(255, 93, 108, 40); border-color: #FF5D6C; color: #FF8A95; }

QPushButton#link {
    background: transparent; border: none; color: #8FB0FF; padding: 2px 4px; font-weight: 600;
}
QPushButton#link:hover { color: #B9CCFF; text-decoration: underline; }

/* ---------- Карточки проверок ---------- */
#card { background: #151A25; border: 1px solid #232A3A; border-radius: 18px; }
#card:hover { border-color: #303A52; }
#card[status="ok"]    { border-color: rgba(46, 204, 143, 110); }
#card[status="warn"]  { border-color: rgba(245, 181, 68, 110); }
#card[status="fail"]  { border-color: rgba(255, 93, 108, 130); }
#card[status="error"] { border-color: rgba(177, 140, 255, 110); }
#card[status="run"]   { border-color: rgba(91, 140, 255, 140); }

#cardIcon {
    font-family: "Segoe MDL2 Assets"; font-size: 19px; color: #8FB0FF;
    background: rgba(91, 140, 255, 30); border-radius: 12px;
    min-width: 44px; max-width: 44px; min-height: 44px; max-height: 44px;
}
#cardIcon[status="ok"]    { color: #2ECC8F; background: rgba(46, 204, 143, 30); }
#cardIcon[status="warn"]  { color: #F5B544; background: rgba(245, 181, 68, 30); }
#cardIcon[status="fail"]  { color: #FF5D6C; background: rgba(255, 93, 108, 30); }
#cardIcon[status="error"] { color: #B18CFF; background: rgba(177, 140, 255, 30); }

#cardNumber { color: #5F687C; font-size: 12px; font-weight: 700; }
#cardTitle  { font-size: 15px; font-weight: 700; }
#cardDesc   { color: #8B94A8; font-size: 12px; }
#cardTime   { color: #5F687C; font-size: 12px; }

#cardSummary {
    background: #10141D; border-radius: 10px; padding: 10px 12px;
    font-size: 13px; color: #9AA3B6; border-left: 3px solid #2A3245;
}
#cardSummary[status="ok"]    { color: #E6E9F0; border-left-color: #2ECC8F; }
#cardSummary[status="warn"]  { color: #E6E9F0; border-left-color: #F5B544; }
#cardSummary[status="fail"]  { color: #E6E9F0; border-left-color: #FF5D6C; }
#cardSummary[status="error"] { color: #E6E9F0; border-left-color: #B18CFF; }
#cardSummary[status="run"]   { color: #A9C1FF; border-left-color: #5B8CFF; }

#pill { border-radius: 11px; padding: 3px 10px; font-size: 11px; font-weight: 700; }
#pill[status="idle"]  { background: #1E2433; color: #7D879C; }
#pill[status="run"]   { background: rgba(91, 140, 255, 40); color: #A9C1FF; }
#pill[status="ok"]    { background: rgba(46, 204, 143, 36); color: #2ECC8F; }
#pill[status="warn"]  { background: rgba(245, 181, 68, 36); color: #F5B544; }
#pill[status="fail"]  { background: rgba(255, 93, 108, 40); color: #FF7D89; }
#pill[status="error"] { background: rgba(177, 140, 255, 36); color: #B18CFF; }

#optionLabel { color: #8B94A8; font-size: 12px; }
QSpinBox {
    background: #10141D; border: 1px solid #2A3245; border-radius: 8px;
    padding: 4px 6px; min-width: 52px; font-weight: 600;
}
QSpinBox:focus { border-color: #5B8CFF; }
QSpinBox:disabled { color: #4F586B; }

QPushButton#stepper {
    padding: 0; border-radius: 8px; font-size: 15px; font-weight: 700; color: #A9C1FF;
    background: rgba(91, 140, 255, 30); border: 1px solid #3B4E85;
}
QPushButton#stepper:hover { background: rgba(91, 140, 255, 60); }
QPushButton#stepper:disabled { color: #3A4256; background: #171B26; border-color: #20263A; }

/* ---------- Панель отчёта ---------- */
#panel { background: #151A25; border: 1px solid #232A3A; border-radius: 18px; }
#panelTitle { font-size: 15px; font-weight: 700; }
#panelHint  { color: #8B94A8; font-size: 12px; }

QTextBrowser {
    background: #10141D; border: 1px solid #1F2635; border-radius: 12px;
    padding: 6px; selection-background-color: #3A4E86;
}

#stat { background: #10141D; border-radius: 10px; }
#statValue { font-size: 18px; font-weight: 700; }
#statLabel { color: #8B94A8; font-size: 11px; }

/* ---------- Полоса прогресса и статус ---------- */
QProgressBar#progress { background: #1A2030; border: none; border-radius: 3px; min-height: 6px; max-height: 6px; }
QProgressBar#progress::chunk {
    border-radius: 3px;
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #5B8CFF, stop:1 #8B5CF6);
}
#statusText { color: #8B94A8; font-size: 12px; }

/* ---------- Полосы прокрутки ---------- */
QScrollBar:vertical { background: transparent; width: 10px; margin: 4px 2px; }
QScrollBar::handle:vertical { background: #2A3245; border-radius: 3px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #3A4560; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }
QScrollBar:horizontal { height: 0; }
)");
}

}
