#ifndef PACKETPLAYER_H
#define PACKETPLAYER_H

#include <QWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QSpinBox>
#include <QLabel>
#include <QComboBox>
#include <QThread>

// Включения PcapPlusPlus
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"  // ДОБАВИТЬ эту строку!
#include "pcapplusplus/UdpLayer.h"            // ДОБАВИТЬ эту строку!
#include "pcapplusplus/Packet.h"              // ДОБАВИТЬ эту строку!

#include <chrono>

class PlaybackThread : public QThread
{
    Q_OBJECT
    
public:
    PlaybackThread(const QString& filename, const QString& interface, 
                   int interval, QObject* parent = nullptr);
    
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
    
    // UI Elements
    QLineEdit *fileEdit;
    QPushButton *browseButton;
    QComboBox *interfaceCombo;
    QSpinBox *intervalSpin;
    QPushButton *playButton;
    QPushButton *stopButton;
    QTextEdit *logText;
    QLabel *statusLabel;
    
    // Playback data
    PlaybackThread* playbackThread;
    bool isPlaying;
};

#endif // PACKETPLAYER_H