#include "MainWindow.h"
#include "CheckCard.h"
#include "Theme.h"
#include "core/AntivirusTester.h"
#include "core/FirewallTester.h"
#include "core/InternetChecker.h"
#include "core/ProductDetector.h"
#include "core/Utils.h"

#include <QApplication>
#include <QCloseEvent>
#include <QDir>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardPaths>
#include <QStyle>
#include <QTextBrowser>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrent>
#include <chrono>

#include <windows.h>
#include <dwmapi.h>

namespace {

// Названия проверок на карточках и в отчёте
const char* const kCardTitles[] = {
    "Подключение к Интернету",
    "Наличие МЭ и антивируса",
    "Работа межсетевого экрана",
    "Работа антивируса",
};
const wchar_t* const kReportTitles[] = {
    L"Проверка подключения к Интернету",
    L"Проверка наличия межсетевого экрана и антивируса",
    L"Проверка работоспособности межсетевого экрана",
    L"Проверка работоспособности антивирусного ПО",
};

QString hex(const QColor& c) { return c.name(QColor::HexRgb); }

// Строка подробностей: экранирование HTML и сохранение отступов
QString htmlLine(const std::wstring& line)
{
    QString s = QString::fromStdWString(line);
    int spaces = 0;
    while (spaces < s.size() && s[spaces] == ' ')
        ++spaces;
    return QString("&nbsp;").repeated(spaces * 2) + s.mid(spaces).toHtmlEscaped();
}

// Значок приложения: щит на градиентном скруглённом квадрате
QIcon appIcon()
{
    QIcon icon;
    for (int size : { 16, 24, 32, 48, 64, 128, 256 }) {
        QPixmap pm(size, size);
        pm.fill(Qt::transparent);
        QPainter p(&pm);
        p.setRenderHint(QPainter::Antialiasing);
        QLinearGradient g(0, 0, size, size);
        g.setColorAt(0, theme::kAccent);
        g.setColorAt(1, theme::kAccent2);
        p.setBrush(g);
        p.setPen(Qt::NoPen);
        p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22);
        QFont f(theme::kIconFont);
        f.setPixelSize(int(size * 0.56));
        p.setFont(f);
        p.setPen(Qt::white);
        p.drawText(QRectF(0, 0, size, size), Qt::AlignCenter, QString(theme::glyph::Shield));
        icon.addPixmap(pm);
    }
    return icon;
}

// Тёмный заголовок окна Windows 10 (20H1+) и Windows 11
void useDarkTitleBar(QWidget* w)
{
    const BOOL dark = TRUE;
    const HWND hwnd = reinterpret_cast<HWND>(w->winId());
    if (FAILED(DwmSetWindowAttribute(hwnd, 20 /* DWMWA_USE_IMMERSIVE_DARK_MODE */, &dark, sizeof(dark))))
        DwmSetWindowAttribute(hwnd, 19 /* то же для ранних сборок Windows 10 */, &dark, sizeof(dark));
}

}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("Программа проверки информационной безопасности");
    setWindowIcon(appIcon());
    resize(1320, 840);
    setMinimumSize(1120, 720);

    auto* central = new QWidget;
    central->setObjectName("central");
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(20, 20, 20, 14);
    layout->setSpacing(16);
    layout->addWidget(buildHeader());

    auto* body = new QHBoxLayout;
    body->setSpacing(16);
    body->addWidget(buildCards(), 11);
    body->addWidget(buildReportPanel(), 9);
    layout->addLayout(body, 1);
    layout->addWidget(buildFooter());
    setCentralWidget(central);

    connect(&watcher_, &QFutureWatcher<CheckResult>::finished, this, &MainWindow::onCheckFinished);
    useDarkTitleBar(this);
    setStatus("Готово к работе. Запустите проверки по отдельности или все сразу.");
}

QWidget* MainWindow::buildHeader()
{
    auto* header = new QFrame;
    header->setObjectName("header");

    auto* logo = new QLabel(QString(theme::glyph::Shield));
    logo->setObjectName("logo");
    logo->setAlignment(Qt::AlignCenter);

    auto* title = new QLabel("Проверка средств защиты ПК");
    title->setObjectName("appTitle");
    auto* subtitle = new QLabel("Контроль работоспособности антивируса и межсетевого экрана");
    subtitle->setObjectName("appSubtitle");

    // Плашка с уровнем прав: от них зависит активный тест межсетевого экрана
    const bool admin = util::isRunningAsAdmin();
    auto* chip = new QLabel(admin ? "●  Запущено от имени администратора"
                                  : "●  Без прав администратора — активный тест МЭ недоступен");
    chip->setObjectName("chip");
    chip->setProperty("status", admin ? "ok" : "warn");

    auto* chips = new QHBoxLayout;
    chips->setSpacing(8);
    chips->addWidget(chip);
    if (!admin) {
        auto* elevate = new QPushButton("Перезапустить от имени администратора");
        elevate->setObjectName("link");
        elevate->setCursor(Qt::PointingHandCursor);
        connect(elevate, &QPushButton::clicked, this, &MainWindow::relaunchAsAdmin);
        chips->addWidget(elevate);
    }
    chips->addStretch(1);

    auto* texts = new QVBoxLayout;
    texts->setSpacing(4);
    texts->addWidget(title);
    texts->addWidget(subtitle);
    texts->addSpacing(4);
    texts->addLayout(chips);

    runAllButton_ = new QPushButton("  Запустить все проверки");
    runAllButton_->setObjectName("primary");
    runAllButton_->setIcon(theme::glyphIcon(theme::glyph::Play, Qt::white, 16));
    runAllButton_->setCursor(Qt::PointingHandCursor);
    connect(runAllButton_, &QPushButton::clicked, this, &MainWindow::runAll);

    auto* row = new QHBoxLayout(header);
    row->setContentsMargins(20, 18, 22, 18);
    row->setSpacing(16);
    row->addWidget(logo, 0, Qt::AlignTop);
    row->addLayout(texts, 1);
    row->addWidget(runAllButton_, 0, Qt::AlignVCenter);
    return header;
}

QWidget* MainWindow::buildCards()
{
    const QChar icons[] = { theme::glyph::Globe, theme::glyph::Search, theme::glyph::Lock, theme::glyph::Bug };
    const char* descriptions[] = {
        "Сетевые адаптеры, ping (ICMP), DNS и HTTP-запрос — по уровням, чтобы найти, где именно обрыв.",
        "Центр безопасности Windows, брандмауэр, файлы известных продуктов и службы защиты.",
        "Временное запрещающее правило и обращение к запрещённому ресурсу: МЭ должен его заблокировать.",
        "Тестовый файл EICAR: резидентный монитор должен удалить или заблокировать его за заданное время.",
    };

    auto* box = new QWidget;
    auto* grid = new QGridLayout(box);
    grid->setContentsMargins(0, 0, 0, 0);
    grid->setSpacing(16);
    for (int i = 0; i < CheckCount; ++i) {
        cards_[i] = new CheckCard(i + 1, icons[i], kCardTitles[i], descriptions[i]);
        connect(cards_[i], &CheckCard::runRequested, this, [this, i] { startCheck(i); });
        grid->addWidget(cards_[i], i / 2, i % 2);
    }
    grid->setRowStretch(0, 1);
    grid->setRowStretch(1, 1);
    grid->setColumnStretch(0, 1);
    grid->setColumnStretch(1, 1);

    // Время ожидания реакции антивируса (по методическим указаниям - "заданное время")
    auto* waitLabel = new QLabel("Время ожидания реакции");
    waitLabel->setObjectName("optionLabel");
    waitSpin_ = new QSpinBox;
    waitSpin_->setRange(3, 60);
    waitSpin_->setValue(10);
    waitSpin_->setSuffix(" с");
    waitSpin_->setAlignment(Qt::AlignCenter);
    waitSpin_->setButtonSymbols(QAbstractSpinBox::NoButtons);
    waitSpin_->setToolTip("Сколько секунд ждать реакции антивируса на тестовый файл");

    // Свои кнопки "−" и "+" вместо стандартных стрелок, которые плохо видны в тёмной теме
    auto* minus = new QPushButton("−");
    auto* plus = new QPushButton("+");
    for (auto* b : { minus, plus }) {
        b->setObjectName("stepper");
        b->setCursor(Qt::PointingHandCursor);
        b->setFixedSize(28, 28);
    }
    connect(minus, &QPushButton::clicked, waitSpin_, &QSpinBox::stepDown);
    connect(plus, &QPushButton::clicked, waitSpin_, &QSpinBox::stepUp);
    connect(waitSpin_, &QSpinBox::valueChanged, this, [this, minus, plus](int v) {
        minus->setEnabled(waitSpin_->isEnabled() && v > waitSpin_->minimum());
        plus->setEnabled(waitSpin_->isEnabled() && v < waitSpin_->maximum());
    });
    stepButtons_ = { minus, plus };

    auto* option = new QWidget;
    auto* optionRow = new QHBoxLayout(option);
    optionRow->setContentsMargins(0, 0, 0, 0);
    optionRow->setSpacing(4);
    optionRow->addWidget(waitLabel);
    optionRow->addStretch(1);
    optionRow->addWidget(minus);
    optionRow->addWidget(waitSpin_);
    optionRow->addWidget(plus);
    cards_[Antivirus]->addOption(option);
    return box;
}

QWidget* MainWindow::buildReportPanel()
{
    auto* panel = new QFrame;
    panel->setObjectName("panel");

    auto* title = new QLabel("Результаты проверок и рекомендации");
    title->setObjectName("panelTitle");
    auto* hint = new QLabel("Отчёт формируется по кнопке «Вывести результаты» или после запуска всех проверок");
    hint->setObjectName("panelHint");
    hint->setWordWrap(true);

    // Счётчики результатов
    const struct { const char* label; QColor color; } stats[] = {
        { "Норма", theme::kOk }, { "Внимание", theme::kWarn },
        { "Не работает", theme::kFail }, { "Ошибка", theme::kError },
    };
    auto* statsRow = new QHBoxLayout;
    statsRow->setSpacing(8);
    for (int i = 0; i < 4; ++i) {
        auto* box = new QFrame;
        box->setObjectName("stat");
        auto* value = new QLabel("—");
        value->setObjectName("statValue");
        value->setStyleSheet(QString("color: %1;").arg(hex(stats[i].color)));
        auto* label = new QLabel(stats[i].label);
        label->setObjectName("statLabel");
        auto* v = new QVBoxLayout(box);
        v->setContentsMargins(12, 8, 12, 8);
        v->setSpacing(0);
        v->addWidget(value);
        v->addWidget(label);
        statsRow->addWidget(box, 1);
        statValues_[i] = value;
    }

    report_ = new QTextBrowser;
    report_->setOpenLinks(false);
    report_->setHtml(placeholderHtml());

    showButton_ = new QPushButton("  Вывести результаты");
    showButton_->setObjectName("accent");
    showButton_->setIcon(theme::glyphIcon(theme::glyph::Document, QColor("#A9C1FF")));
    saveButton_ = new QPushButton("  Сохранить в файл");
    saveButton_->setIcon(theme::glyphIcon(theme::glyph::Save, theme::kText));
    exitButton_ = new QPushButton("  Выход");
    exitButton_->setObjectName("danger");
    exitButton_->setIcon(theme::glyphIcon(theme::glyph::Power, theme::kText));
    for (auto* b : { showButton_, saveButton_, exitButton_ })
        b->setCursor(Qt::PointingHandCursor);
    connect(showButton_, &QPushButton::clicked, this, &MainWindow::showResults);
    connect(saveButton_, &QPushButton::clicked, this, &MainWindow::saveResults);
    connect(exitButton_, &QPushButton::clicked, this, &MainWindow::close);

    auto* buttons = new QHBoxLayout;
    buttons->setSpacing(8);
    buttons->addWidget(showButton_);
    buttons->addWidget(saveButton_);
    buttons->addStretch(1);
    buttons->addWidget(exitButton_);

    auto* layout = new QVBoxLayout(panel);
    layout->setContentsMargins(18, 16, 18, 16);
    layout->setSpacing(10);
    layout->addWidget(title);
    layout->addWidget(hint);
    layout->addLayout(statsRow);
    layout->addWidget(report_, 1);
    layout->addLayout(buttons);
    return panel;
}

QWidget* MainWindow::buildFooter()
{
    auto* footer = new QWidget;
    progress_ = new QProgressBar;
    progress_->setObjectName("progress");
    progress_->setTextVisible(false);
    progress_->setFixedWidth(220);
    progress_->setRange(0, CheckCount);
    progress_->setValue(0);

    statusText_ = new QLabel;
    statusText_->setObjectName("statusText");

    auto* about = new QLabel("SecurityChecker 1.0 · C++17 · Qt 6 · WinAPI");
    about->setObjectName("statusText");

    auto* row = new QHBoxLayout(footer);
    row->setContentsMargins(4, 0, 4, 0);
    row->setSpacing(12);
    row->addWidget(progress_);
    row->addWidget(statusText_, 1);
    row->addWidget(about);
    return footer;
}

void MainWindow::startCheck(int index)
{
    running_ = index;
    setBusy(true);
    cards_[index]->setRunning();
    if (runAllMode_) {
        progress_->setRange(0, CheckCount);
        progress_->setValue(index);
    } else {
        progress_->setRange(0, 0);   // неопределённый прогресс для одиночной проверки
    }
    setStatus(QString("Выполняется: %1…").arg(QString::fromWCharArray(kReportTitles[index])));

    const int waitSec = waitSpin_->value();
    watcher_.setFuture(QtConcurrent::run([index, waitSec] {
        const auto started = std::chrono::steady_clock::now();
        CheckResult r;
        switch (index) {
        case Internet:  r = InternetChecker().run(); break;
        case Products:  r = ProductDetector().run(); break;
        case Firewall:  r = FirewallTester().run(); break;
        case Antivirus: r = AntivirusTester(waitSec).run(); break;
        default: break;
        }
        r.durationSec = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        return r;
    }));
}

void MainWindow::onCheckFinished()
{
    const int index = running_;
    running_ = -1;
    results_[index] = watcher_.result();
    cards_[index]->setResult(results_[index]);

    if (runAllMode_ && index + 1 < CheckCount) {
        startCheck(index + 1);
        return;
    }
    const bool wasRunAll = runAllMode_;
    runAllMode_ = false;
    setBusy(false);
    progress_->setRange(0, CheckCount);
    progress_->setValue(CheckCount);

    if (wasRunAll) {
        showResults();
    } else {
        setStatus(QString("Готово: %1 — %2")
                      .arg(QString::fromWCharArray(kReportTitles[index]),
                           QString::fromWCharArray(statusText(results_[index].status))));
    }
}

void MainWindow::runAll()
{
    for (auto* card : cards_)
        card->reset();
    results_ = {};
    runAllMode_ = true;
    startCheck(Internet);
}

void MainWindow::showResults()
{
    std::vector<ReportItem> items;
    for (int i = 0; i < CheckCount; ++i)
        items.push_back({ kReportTitles[i], results_[i] });

    const auto info = ReportBuilder::systemInfo();
    lastReport_ = ReportBuilder::buildText(items, info);
    report_->setHtml(reportHtml(items, info));
    updateStats(items);

    // По методическим указаниям после вывода поля проверок очищаются,
    // чтобы при повторной проверке не остались старые результаты
    for (int i = 0; i < CheckCount; ++i) {
        results_[i] = CheckResult{};
        cards_[i]->reset();
    }
    setStatus("Отчёт сформирован. Результаты перенесены в отчёт, поля проверок очищены.");
}

void MainWindow::saveResults()
{
    if (lastReport_.empty())
        showResults();

    const QString dir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    const QString suggested = QDir(dir).filePath(QString::fromStdWString(ReportBuilder::defaultFileName()));
    const QString path = QFileDialog::getSaveFileName(this, "Сохранить отчёт", suggested,
                                                      "Текстовый файл (*.txt)");
    if (path.isEmpty())
        return;

    std::wstring error;
    if (ReportBuilder::save(QDir::toNativeSeparators(path).toStdWString(), lastReport_, error))
        setStatus("Отчёт сохранён: " + QDir::toNativeSeparators(path));
    else
        setStatus("Не удалось сохранить отчёт: " + QString::fromStdWString(error));
}

void MainWindow::relaunchAsAdmin()
{
    if (running_ >= 0) {
        setStatus("Дождитесь окончания текущей проверки.");
        return;
    }
    if (util::relaunchAsAdmin())
        qApp->quit();
    else
        setStatus("Запуск с правами администратора отменён.");
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // Не закрываемся посреди проверки: тест МЭ должен успеть удалить своё временное правило
    if (running_ >= 0) {
        setStatus("Дождитесь окончания текущей проверки, затем закройте программу.");
        event->ignore();
        return;
    }
    event->accept();
}

void MainWindow::setBusy(bool busy)
{
    for (auto* card : cards_)
        card->setButtonEnabled(!busy);
    for (auto* w : { static_cast<QWidget*>(runAllButton_), static_cast<QWidget*>(showButton_),
                     static_cast<QWidget*>(saveButton_), static_cast<QWidget*>(exitButton_),
                     static_cast<QWidget*>(waitSpin_) })
        w->setEnabled(!busy);
    stepButtons_[0]->setEnabled(!busy && waitSpin_->value() > waitSpin_->minimum());
    stepButtons_[1]->setEnabled(!busy && waitSpin_->value() < waitSpin_->maximum());
}

void MainWindow::setStatus(const QString& text)
{
    statusText_->setText(text);
}

void MainWindow::updateStats(const std::vector<ReportItem>& items)
{
    int counts[4] = {};
    for (const auto& item : items) {
        switch (item.result.status) {
        case CheckStatus::Ok:      ++counts[0]; break;
        case CheckStatus::Warning: ++counts[1]; break;
        case CheckStatus::Fail:    ++counts[2]; break;
        case CheckStatus::Error:   ++counts[3]; break;
        default: break;
        }
    }
    for (int i = 0; i < 4; ++i)
        statValues_[i]->setText(QString::number(counts[i]));
}

QString MainWindow::placeholderHtml() const
{
    return QString(R"(
<table width="100%" height="100%"><tr><td align="center" valign="middle" style="padding-top:110px;">
  <p style="font-family:'%1'; font-size:40px; color:#2A3245;">%2</p>
  <p style="font-size:15px; font-weight:600; color:#8B94A8;">Отчёт пока не сформирован</p>
  <p style="font-size:12px; color:#5F687C;">Запустите проверки и нажмите «Вывести результаты»<br>или воспользуйтесь кнопкой «Запустить все проверки».</p>
</td></tr></table>)")
        .arg(theme::kIconFont, QString(theme::glyph::Document));
}

QString MainWindow::reportHtml(const std::vector<ReportItem>& items, const ReportBuilder::SystemInfo& info) const
{
    const CheckStatus overall = ReportBuilder::overall(items);
    const QString overallColor = hex(theme::statusColor(overall));

    QString h;
    h += "<div style=\"font-size:13px;\">";
    h += "<p style=\"font-size:16px; font-weight:700; margin:2px 0 2px 0;\">Результаты проверки средств защиты</p>";
    h += QString("<p style=\"color:#8B94A8; font-size:12px; margin:0 0 4px 0;\">%1 · %2 · %3<br>%4 · %5</p>")
             .arg(QString::fromStdWString(info.dateTime).toHtmlEscaped(),
                  QString::fromStdWString(info.computer).toHtmlEscaped(),
                  QString::fromStdWString(info.user).toHtmlEscaped(),
                  QString::fromStdWString(info.os).toHtmlEscaped(),
                  info.admin ? "права администратора" : "обычный пользователь");

    // Общий вывод
    h += QString("<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin-top:8px;\"><tr>"
                 "<td width=\"4\" bgcolor=\"%1\"></td>"
                 "<td bgcolor=\"#1A2030\" style=\"padding:10px 12px;\">"
                 "<span style=\"color:%1; font-weight:700; font-size:12px;\">ОБЩИЙ ВЫВОД</span><br>"
                 "<span style=\"font-size:13px;\">%2</span></td></tr></table>")
             .arg(overallColor, QString::fromStdWString(ReportBuilder::conclusion(overall)).toHtmlEscaped());

    int n = 0;
    for (const auto& item : items) {
        const CheckResult& r = item.result;
        const QString color = hex(theme::statusColor(r.status));
        const QString title = QString::fromStdWString(item.title).toHtmlEscaped();

        h += QString("<table width=\"100%\" cellspacing=\"0\" cellpadding=\"0\" style=\"margin-top:10px;\"><tr>"
                     "<td width=\"4\" bgcolor=\"%1\"></td><td bgcolor=\"#171C28\" style=\"padding:10px 12px;\">")
                 .arg(color);
        h += QString("<span style=\"font-size:14px; font-weight:700;\">%1. %2</span><br>").arg(++n).arg(title);
        h += QString("<span style=\"color:%1; font-weight:700;\">● %2</span>")
                 .arg(color, QString::fromWCharArray(statusText(r.status)));

        if (r.status == CheckStatus::NotRun) {
            h += "<p style=\"color:#5F687C; margin:4px 0 0 0;\">Проверка не выполнялась.</p></td></tr></table>";
            continue;
        }
        h += QString("<span style=\"color:#5F687C;\"> &nbsp;·&nbsp; %1 с</span>").arg(r.durationSec, 0, 'f', 1);

        QString summary = QString::fromStdWString(r.summary).toHtmlEscaped();
        summary.replace('\n', "<br>");
        h += QString("<p style=\"margin:6px 0 0 0;\">%1</p>").arg(summary);

        if (!r.details.empty()) {
            h += "<p style=\"color:#8B94A8; font-size:12px; margin:8px 0 0 0;\">";
            for (size_t i = 0; i < r.details.size(); ++i)
                h += (i ? "<br>" : "") + htmlLine(r.details[i]);
            h += "</p>";
        }
        if (!r.recommendations.empty()) {
            h += QString("<p style=\"color:%1; font-size:12px; font-weight:700; margin:8px 0 2px 0;\">Рекомендации</p>")
                     .arg(hex(theme::kWarn));
            h += "<p style=\"font-size:12px; margin:0;\">";
            for (size_t i = 0; i < r.recommendations.size(); ++i)
                h += QString(i ? "<br>" : "") + "→ " +
                     QString::fromStdWString(r.recommendations[i]).toHtmlEscaped();
            h += "</p>";
        }
        h += "</td></tr></table>";
    }
    h += "</div>";
    return h;
}
