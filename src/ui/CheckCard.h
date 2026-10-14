#pragma once
#include <QFrame>
#include "core/CheckResult.h"

class QLabel;
class QPushButton;
class QHBoxLayout;
class QVBoxLayout;
class Spinner;

// Карточка одной проверки: значок, название, описание, статус, итог и кнопка запуска
class CheckCard : public QFrame {
    Q_OBJECT
public:
    CheckCard(int number, QChar icon, const QString& title, const QString& description,
              QWidget* parent = nullptr);

    void setRunning();
    void setResult(const CheckResult& result);
    void reset();                         // вернуть в состояние "не выполнялась"
    void setButtonEnabled(bool enabled);
    void addOption(QWidget* widget);      // дополнительный элемент управления (например, время ожидания)

signals:
    void runRequested();

private:
    void applyStatus(const QString& key, const QString& pillText);

    QLabel* icon_;
    QLabel* pill_;
    QLabel* summary_;
    QLabel* time_;
    QPushButton* button_;
    Spinner* spinner_;
    QHBoxLayout* bottomRow_;
    QVBoxLayout* layout_;
};
