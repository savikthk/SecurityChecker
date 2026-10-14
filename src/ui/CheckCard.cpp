#include "CheckCard.h"
#include "Theme.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QStyle>
#include <QTimer>
#include <QVBoxLayout>

// Анимированный индикатор выполнения (вращающаяся дуга)
class Spinner : public QWidget {
public:
    explicit Spinner(QWidget* parent = nullptr) : QWidget(parent)
    {
        setFixedSize(18, 18);
        timer_.setInterval(16);
        connect(&timer_, &QTimer::timeout, this, [this] {
            angle_ = (angle_ + 8) % 360;
            update();
        });
        hide();
    }
    void start() { show(); timer_.start(); }
    void stop() { timer_.stop(); hide(); }

protected:
    void paintEvent(QPaintEvent*) override
    {
        QPainter p(this);
        p.setRenderHint(QPainter::Antialiasing);
        const QRectF r = QRectF(rect()).adjusted(2, 2, -2, -2);
        p.setPen(QPen(QColor(91, 140, 255, 50), 2.5));
        p.drawEllipse(r);
        p.setPen(QPen(theme::kAccent, 2.5, Qt::SolidLine, Qt::RoundCap));
        p.drawArc(r, -angle_ * 16, 100 * 16);
    }

private:
    QTimer timer_;
    int angle_ = 0;
};

CheckCard::CheckCard(int number, QChar icon, const QString& title, const QString& description,
                     QWidget* parent)
    : QFrame(parent)
{
    setObjectName("card");
    setAttribute(Qt::WA_StyledBackground);

    icon_ = new QLabel(QString(icon));
    icon_->setObjectName("cardIcon");
    icon_->setAlignment(Qt::AlignCenter);

    auto* numberLabel = new QLabel(QString("ПРОВЕРКА %1").arg(number, 2, 10, QChar('0')));
    numberLabel->setObjectName("cardNumber");
    auto* titleLabel = new QLabel(title);
    titleLabel->setObjectName("cardTitle");

    pill_ = new QLabel;
    pill_->setObjectName("pill");

    // Статус - в строке с номером, чтобы названию хватало ширины
    auto* numberRow = new QHBoxLayout;
    numberRow->setSpacing(8);
    numberRow->addWidget(numberLabel);
    numberRow->addStretch(1);
    numberRow->addWidget(pill_);

    auto* titleBox = new QVBoxLayout;
    titleBox->setSpacing(2);
    titleBox->addLayout(numberRow);
    titleBox->addWidget(titleLabel);

    auto* top = new QHBoxLayout;
    top->setSpacing(12);
    top->addWidget(icon_);
    top->addLayout(titleBox, 1);

    auto* desc = new QLabel(description);
    desc->setObjectName("cardDesc");
    desc->setWordWrap(true);

    summary_ = new QLabel;
    summary_->setObjectName("cardSummary");
    summary_->setWordWrap(true);
    summary_->setMinimumHeight(58);
    summary_->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

    button_ = new QPushButton("Проверить");
    button_->setObjectName("accent");
    button_->setIcon(theme::glyphIcon(theme::glyph::Play, QColor("#A9C1FF"), 14));
    button_->setCursor(Qt::PointingHandCursor);
    connect(button_, &QPushButton::clicked, this, &CheckCard::runRequested);

    spinner_ = new Spinner;
    time_ = new QLabel;
    time_->setObjectName("cardTime");

    bottomRow_ = new QHBoxLayout;
    bottomRow_->setSpacing(10);
    bottomRow_->addWidget(button_);
    bottomRow_->addWidget(spinner_);
    bottomRow_->addStretch(1);
    bottomRow_->addWidget(time_);

    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(18, 16, 18, 16);
    layout_->setSpacing(10);
    layout_->addLayout(top);
    layout_->addWidget(desc);
    layout_->addWidget(summary_, 1);
    layout_->addLayout(bottomRow_);

    // Ширину карточки задаёт сетка, а не длина текста - так колонки получаются одинаковыми
    setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    setMinimumWidth(270);

    reset();
}

void CheckCard::addOption(QWidget* widget)
{
    // Опция - отдельной строкой над кнопкой запуска
    layout_->insertWidget(layout_->count() - 1, widget);
}

void CheckCard::setButtonEnabled(bool enabled)
{
    button_->setEnabled(enabled);
}

void CheckCard::setRunning()
{
    applyStatus("run", "Выполняется");
    summary_->setText("Идёт проверка…");
    summary_->setToolTip({});
    time_->clear();
    spinner_->start();
}

void CheckCard::setResult(const CheckResult& result)
{
    spinner_->stop();
    applyStatus(theme::statusKey(result.status), QString::fromWCharArray(statusText(result.status)));
    summary_->setText(QString::fromStdWString(result.summary));
    time_->setText(QString::number(result.durationSec, 'f', 1) + " с");

    // Подробности - во всплывающей подсказке над итогом
    QStringList lines;
    for (const auto& d : result.details)
        lines << QString::fromStdWString(d);
    summary_->setToolTip(lines.join('\n'));
}

void CheckCard::reset()
{
    spinner_->stop();
    applyStatus("idle", "Не выполнялась");
    summary_->setText("Нажмите «Проверить», чтобы запустить эту проверку.");
    summary_->setToolTip({});
    time_->clear();
}

void CheckCard::applyStatus(const QString& key, const QString& pillText)
{
    pill_->setText(pillText);
    // После смены динамического свойства стиль нужно применить заново
    for (QWidget* w : { static_cast<QWidget*>(this), static_cast<QWidget*>(icon_),
                        static_cast<QWidget*>(pill_), static_cast<QWidget*>(summary_) }) {
        w->setProperty("status", key);
        w->style()->unpolish(w);
        w->style()->polish(w);
    }
}
