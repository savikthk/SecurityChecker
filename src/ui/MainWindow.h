#pragma once
#include <QFutureWatcher>
#include <QMainWindow>
#include <array>
#include "core/CheckResult.h"
#include "core/ReportBuilder.h"

class CheckCard;
class QLabel;
class QProgressBar;
class QPushButton;
class QSpinBox;
class QTextBrowser;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    enum Check { Internet, Products, Firewall, Antivirus, CheckCount };

    QWidget* buildHeader();
    QWidget* buildCards();
    QWidget* buildReportPanel();
    QWidget* buildFooter();

    void startCheck(int index);     // запуск проверки в фоновом потоке
    void onCheckFinished();
    void runAll();                  // все проверки по очереди + вывод результатов
    void showResults();             // модуль вывода результатов
    void saveResults();
    void relaunchAsAdmin();

    void setBusy(bool busy);
    void setStatus(const QString& text);
    void updateStats(const std::vector<ReportItem>& items);
    QString reportHtml(const std::vector<ReportItem>& items, const ReportBuilder::SystemInfo& info) const;
    QString placeholderHtml() const;

    std::array<CheckCard*, CheckCount> cards_{};
    std::array<CheckResult, CheckCount> results_{};
    std::array<QLabel*, 4> statValues_{};
    QFutureWatcher<CheckResult> watcher_;
    int running_ = -1;
    bool runAllMode_ = false;

    QPushButton* runAllButton_ = nullptr;
    QPushButton* showButton_ = nullptr;
    QPushButton* saveButton_ = nullptr;
    QPushButton* exitButton_ = nullptr;
    QTextBrowser* report_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QLabel* statusText_ = nullptr;
    QSpinBox* waitSpin_ = nullptr;
    std::array<QPushButton*, 2> stepButtons_{};   // "−" и "+" у времени ожидания
    std::wstring lastReport_;   // текст последнего отчёта для сохранения в файл
};
