#ifndef PACKETPLAYER_H
#define PACKETPLAYER_H

#include <QThread>
#include <QWidget>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QCheckBox>
#include <pcapplusplus/PcapLiveDeviceList.h>
#include <pcapplusplus/PcapFileDevice.h>

class PlaybackThread : public QThread
{
    Q_OBJECT

public:
    PlaybackThread(const QString& filename, 
                   const QString& interface, 
                   bool useTimestamps, 
                   int interval, 
                   QObject* parent = nullptr);

signals:
    void playbackStatus(const QString& status);
    void playbackError(const QString& error);
    void packetSent(const QString& packetInfo);
    void playbackFinished();

protected:
    void run() override;

private:
    QString filename;
    QString interface;
    int interval;
    bool useTimestamps;
};

class PacketPlayer : public QWidget
{
    Q_OBJECT

public:
    PacketPlayer(QWidget *parent = nullptr);
    ~PacketPlayer();

private slots:
    void browseFile();
    void startPlayback();
    void stopPlayback();
    void onPlaybackStatus(const QString& status);
    void onPlaybackError(const QString& error);
    void onPacketSent(const QString& packetInfo);
    void onPlaybackFinished();

private:
    void setupUI();
    void populateInterfaces();

    PlaybackThread* playbackThread;
    bool isPlaying;

    // UI элементы
    QLineEdit* fileEdit;
    QComboBox* interfaceCombo;
    QSpinBox* intervalSpin;
    QCheckBox* useTimestampCheck;
    QPushButton* browseButton;
    QPushButton* playButton;
    QPushButton* stopButton;
    QTextEdit* logText;
    QLabel* statusLabel;
};

#endif // PACKETPLAYER_H