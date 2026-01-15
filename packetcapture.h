#ifndef PACKETCAPTURE_H
#define PACKETCAPTURE_H

#include <QWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QThread>
#include <QLineEdit>
#include <QSplitter>
#include <QTime>

// Включения PcapPlusPlus
#include "pcapplusplus/Packet.h"
#include "pcapplusplus/PcapLiveDevice.h"
#include "pcapplusplus/PcapFileDevice.h"
#include "pcapplusplus/PcapLiveDeviceList.h"
#include "pcapplusplus/SystemUtils.h"
#include "pcapplusplus/IPv4Layer.h"
#include "pcapplusplus/IPv6Layer.h"
#include "pcapplusplus/UdpLayer.h"
#include "pcapplusplus/EthLayer.h"
#include "pcapplusplus/PayloadLayer.h"
#include "pcapplusplus/TcpLayer.h"

#include <chrono> 
#include <atomic>
#include <vector>

class CaptureThread : public QThread
{
    Q_OBJECT
    
public:
    CaptureThread(pcpp::PcapLiveDevice* dev, const std::string& filter, 
                  std::atomic<bool>& stopFlag, QObject* parent = nullptr);
    
    // Статические методы для форматирования пакетов
    static QString formatPacketSummary(pcpp::Packet* packet);
    static QString formatPacketDetails(pcpp::Packet* packet);
    
signals:
    void packetCaptured(const QString& summary, const QString& details, 
                       const std::vector<uint8_t>& rawData);
    void captureError(const QString& error);
    
protected:
    void run() override;
    
private:
    pcpp::PcapLiveDevice* device;
    std::string filter;
    std::atomic<bool>& stopFlag;
    
    static void packetCallback(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie);
};

class PacketCapture : public QWidget
{
    Q_OBJECT

public:
    PacketCapture(QWidget *parent = nullptr);
    ~PacketCapture();

private slots:
    void startCapture();
    void stopCapture();
    void saveToFile();
    void onPacketCaptured(const QString& summary, const QString& details, 
                         const std::vector<uint8_t>& rawData);
    void onCaptureError(const QString& error);
    void onPacketSelected(int row, int column);

private:
    void setupUI();
    void populateInterfaces();
    QString formatPacketDetails(pcpp::Packet* packet);
    QString formatPacketSummary(pcpp::Packet* packet);
    
    // UI Elements
    QComboBox *interfaceCombo;
    QLineEdit *filterEdit;
    QCheckBox *promiscuousCheck;
    QPushButton *startButton;
    QPushButton *stopButton;
    QPushButton *saveButton;
    QTableWidget *packetTable;
    QTextEdit *detailText;
    QLabel *statusLabel;
    
    // Capture data
    std::vector<std::vector<uint8_t>> capturedPackets;
    pcpp::PcapLiveDevice* selectedDevice;
    CaptureThread* captureThread;
    std::atomic<bool> stopCaptureFlag;
    int packetCounter;
};

#endif // PACKETCAPTURE_H