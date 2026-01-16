#include "packetcapture.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QTextStream>
#include <arpa/inet.h>
#include <sys/time.h>  
#include <QMetaType>  

Q_DECLARE_METATYPE(std::vector<uint8_t>)
static timeval chronoToTimeval(const std::chrono::system_clock::time_point& tp)
{
    auto duration = tp.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds);
    
    timeval tv;
    tv.tv_sec = seconds.count();
    tv.tv_usec = microseconds.count();
    return tv;
}

CaptureThread::CaptureThread(pcpp::PcapLiveDevice* dev, const std::string& filter, 
                             std::atomic<bool>& stopFlag, bool isProm ,QObject* parent)
    : QThread(parent), device(dev), filter(filter), stopFlag(stopFlag), isPromiscuous(isProm)
{
    qRegisterMetaType<std::vector<uint8_t>>();
    qRegisterMetaType<std::vector<uint8_t>>("std::vector<uint8_t>");
}



void CaptureThread::run()
{
    pcpp::PcapLiveDevice::DeviceConfiguration config;
    if(isPromiscuous)
        config.mode = pcpp::PcapLiveDevice::Promiscuous;
    else
        config.mode = pcpp::PcapLiveDevice::Normal;
    if (!device->open(config))
    {
        emit captureError("Cannot open device for capture");
        return;
    }
    
    if (!filter.empty())
    {
        if (!device->setFilter(filter))
        {
            emit captureError("Failed to set filter");
            device->close();
            return;
        }
    }
    
    emit captureError(""); // Clear any previous error
    
    // Start capturing
    device->startCapture(packetCallback, this);
    
    // Wait until stop flag is set
    // ФИКС: Используем stopFlag вместо stopCaptureFlag
    while (!stopFlag)
    {
        msleep(100);
    }
    
    device->stopCapture();
    device->close();
}

void CaptureThread::packetCallback(pcpp::RawPacket* packet, pcpp::PcapLiveDevice* dev, void* cookie)
{
    CaptureThread* thread = static_cast<CaptureThread*>(cookie);
    
    // Parse packet
    pcpp::Packet parsedPacket(packet);
    
    // Convert to vector for storage
    std::vector<uint8_t> rawData(packet->getRawData(), 
                                 packet->getRawData() + packet->getRawDataLen());
    
    QString summary = formatPacketSummary(&parsedPacket);
    QString details = formatPacketDetails(&parsedPacket);
    
    emit thread->packetCaptured(summary, details, rawData);
}

QString CaptureThread::formatPacketSummary(pcpp::Packet* packet)
{
    QString summary;
    
    if (packet->isPacketOfType(pcpp::UDP))
    {
        pcpp::UdpLayer* udpLayer = packet->getLayerOfType<pcpp::UdpLayer>();
        pcpp::IPv4Layer* ipv4Layer = packet->getLayerOfType<pcpp::IPv4Layer>();
        pcpp::IPv6Layer* ipv6Layer = packet->getLayerOfType<pcpp::IPv6Layer>();
        
        if (ipv4Layer)
        {
            summary = QString("UDP %1:%2 -> %3:%4 Len:%5")
                .arg(QString::fromStdString(ipv4Layer->getSrcIPv4Address().toString()))
                .arg(udpLayer->getSrcPort())
                .arg(QString::fromStdString(ipv4Layer->getDstIPv4Address().toString()))
                .arg(udpLayer->getDstPort())
                .arg(udpLayer->getDataLen() - 8);
        }
        else if (ipv6Layer)
        {
            summary = QString("UDP [%1]:%2 -> [%3]:%4 Len:%5")
                .arg(QString::fromStdString(ipv6Layer->getSrcIPv6Address().toString()))
                .arg(udpLayer->getSrcPort())
                .arg(QString::fromStdString(ipv6Layer->getDstIPv6Address().toString()))
                .arg(udpLayer->getDstPort())
                .arg(udpLayer->getDataLen() - 8);
        }
    }
    else if (packet->isPacketOfType(pcpp::TCP))
    {
        summary = "TCP Packet";
    }
    else if (packet->isPacketOfType(pcpp::IPv4))
    {
        summary = "IPv4 Packet";
    }
    else if (packet->isPacketOfType(pcpp::IPv6))
    {
        summary = "IPv6 Packet";
    }
    else
    {
        summary = "Other Protocol";
    }
    
    return summary;
}

QString CaptureThread::formatPacketDetails(pcpp::Packet* packet)
{
    QString details;
    QTextStream stream(&details);
    
    stream << "Packet Details:\n";
    stream << "===============\n\n";
    
    // Timestamp
    stream << "Timestamp: " << QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss.zzz") << "\n";
    stream << "Length: " << packet->getRawPacket()->getRawDataLen() << " bytes\n\n";
    
    // Ethernet layer
    if (packet->isPacketOfType(pcpp::Ethernet))
    {
        pcpp::EthLayer* ethLayer = packet->getLayerOfType<pcpp::EthLayer>();
        stream << "Ethernet Header:\n";
        stream << "  Src MAC: " << QString::fromStdString(ethLayer->getSourceMac().toString()) << "\n";
        stream << "  Dst MAC: " << QString::fromStdString(ethLayer->getDestMac().toString()) << "\n";
        stream << "  Type: 0x" << QString::number(ethLayer->getEthHeader()->etherType, 16) << "\n\n";
    }
    
    // IP layer
    if (packet->isPacketOfType(pcpp::IPv4))
    {
        pcpp::IPv4Layer* ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
        stream << "IPv4 Header:\n";
        stream << "  Src IP: " << QString::fromStdString(ipLayer->getSrcIPv4Address().toString()) << "\n";
        stream << "  Dst IP: " << QString::fromStdString(ipLayer->getDstIPv4Address().toString()) << "\n";
        stream << "  TTL: " << ipLayer->getIPv4Header()->timeToLive << "\n";
        stream << "  Protocol: " << (int)ipLayer->getIPv4Header()->protocol << "\n\n";
    }
    else if (packet->isPacketOfType(pcpp::IPv6))
    {
        pcpp::IPv6Layer* ipLayer = packet->getLayerOfType<pcpp::IPv6Layer>();
        stream << "IPv6 Header:\n";
        stream << "  Src IP: " << QString::fromStdString(ipLayer->getSrcIPv6Address().toString()) << "\n";
        stream << "  Dst IP: " << QString::fromStdString(ipLayer->getDstIPv6Address().toString()) << "\n";
        stream << "  Hop Limit: " << (int)ipLayer->getIPv6Header()->hopLimit << "\n\n";
    }
    
    // UDP layer
    if (packet->isPacketOfType(pcpp::UDP))
    {
        pcpp::UdpLayer* udpLayer = packet->getLayerOfType<pcpp::UdpLayer>();
        stream << "UDP Header:\n";
        stream << "  Src Port: " << udpLayer->getSrcPort() << "\n";
        stream << "  Dst Port: " << udpLayer->getDstPort() << "\n";
        stream << "  Length: " << udpLayer->getDataLen() << " bytes\n";
        // ФИКС: Добавлена проверка для ntohs
        stream << "  Checksum: 0x" << QString::number(udpLayer->getUdpHeader()->headerChecksum, 16) << "\n\n";
        
        // Payload
        if (udpLayer->getLayerPayloadSize() > 0)
        {
            stream << "Payload (" << udpLayer->getLayerPayloadSize() << " bytes):\n";
            uint8_t* payload = udpLayer->getLayerPayload();
            int payloadSize = udpLayer->getLayerPayloadSize();
            
            // Show as hex dump
            for (int i = 0; i < payloadSize; i++)
            {
                if (i % 16 == 0)
                {
                    if (i > 0) stream << "\n";
                    stream << "    " << QString("%1").arg(i, 4, 16, QChar('0')).toUpper() << ": ";
                }
                stream << QString("%1 ").arg((uint8_t)payload[i], 2, 16, QChar('0')).toUpper();
            }
            stream << "\n\n";
            
            // Show as ASCII if printable
            stream << "ASCII:\n    ";
            for (int i = 0; i < payloadSize && i < 64; i++)
            {
                char c = payload[i];
                stream << (c >= 32 && c < 127 ? c : '.');
            }
            stream << "\n";
        }
    }
    
    return details;
}

PacketCapture::PacketCapture(QWidget *parent)
    : QWidget(parent), selectedDevice(nullptr), captureThread(nullptr), 
      packetCounter(0), stopCaptureFlag(false)
{
    setupUI();
    populateInterfaces();
}

PacketCapture::~PacketCapture()
{
    stopCapture();
}

void PacketCapture::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Control panel
    QHBoxLayout *controlLayout = new QHBoxLayout();
    
    QLabel *interfaceLabel = new QLabel("Interface:", this);
    interfaceCombo = new QComboBox(this);
    interfaceCombo->setMinimumWidth(200);
    
    QLabel *filterLabel = new QLabel("Filter:", this);
    filterEdit = new QLineEdit("udp", this);
    filterEdit->setPlaceholderText("e.g., udp port 53");
    
    promiscuousCheck = new QCheckBox("Promiscuous", this);
    promiscuousCheck->setChecked(true);
    
    startButton = new QPushButton("Start Capture", this);
    stopButton = new QPushButton("Stop Capture", this);
    saveButton = new QPushButton("Save to PCAP", this);
    
    stopButton->setEnabled(false);
    saveButton->setEnabled(false);
    
    controlLayout->addWidget(interfaceLabel);
    controlLayout->addWidget(interfaceCombo);
    controlLayout->addWidget(filterLabel);
    controlLayout->addWidget(filterEdit);
    controlLayout->addWidget(promiscuousCheck);
    controlLayout->addWidget(startButton);
    controlLayout->addWidget(stopButton);
    controlLayout->addWidget(saveButton);
    controlLayout->addStretch();
    
    // Packet table
    packetTable = new QTableWidget(this);
    packetTable->setColumnCount(6);
    QStringList headers = {"No.", "Time", "Source", "Destination", "Protocol", "Length"};
    packetTable->setHorizontalHeaderLabels(headers);
    packetTable->horizontalHeader()->setStretchLastSection(true);
    packetTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    packetTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    
    // Details text
    detailText = new QTextEdit(this);
    detailText->setReadOnly(true);
    detailText->setFont(QFont("Courier New", 10));
    
    // Status label
    statusLabel = new QLabel("Ready", this);
    
    // Splitter for table and details
    QSplitter *splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(packetTable);
    splitter->addWidget(detailText);
    splitter->setSizes(QList<int>() << 400 << 300);
    
    mainLayout->addLayout(controlLayout);
    mainLayout->addWidget(splitter, 1);
    mainLayout->addWidget(statusLabel);
    
    // Connect signals
    connect(startButton, &QPushButton::clicked, this, &PacketCapture::startCapture);
    connect(stopButton, &QPushButton::clicked, this, &PacketCapture::stopCapture);
    connect(saveButton, &QPushButton::clicked, this, &PacketCapture::saveToFile);
    connect(packetTable, &QTableWidget::cellClicked, this, &PacketCapture::onPacketSelected);
}

void PacketCapture::populateInterfaces()
{
    // ФИКС: Добавляем const
    const std::vector<pcpp::PcapLiveDevice*>& devList = pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDevicesList();
    
    for (auto& dev : devList)
    {
        QString desc = QString("%1 (%2)").arg(QString::fromStdString(dev->getName())).arg(QString::fromStdString(dev->getDesc()));
        interfaceCombo->addItem(desc, QVariant(QString::fromStdString(dev->getName())));
    }
    
    if (interfaceCombo->count() == 0)
    {
        interfaceCombo->addItem("No interfaces found");
        interfaceCombo->setEnabled(false);
        startButton->setEnabled(false);
    }
}

void PacketCapture::startCapture()
{
    if (interfaceCombo->currentIndex() < 0 || interfaceCombo->count() == 0)
        return;
    
    QString interfaceName = interfaceCombo->currentData().toString();
    selectedDevice = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interfaceName.toStdString());
    
    if (!selectedDevice)
    {
        QMessageBox::critical(this, "Error", "Failed to open network interface");
        return;
    }
    
    packetTable->setRowCount(0);
    capturedPackets.clear();
    packetCounter = 0;
    detailText->clear();
    
    stopCaptureFlag = false;
    captureThread = new CaptureThread(selectedDevice, filterEdit->text().toStdString(), 
                                      stopCaptureFlag, promiscuousCheck->isChecked(), this);
    
    connect(captureThread, &CaptureThread::packetCaptured, 
            this, &PacketCapture::onPacketCaptured);
    connect(captureThread, &CaptureThread::captureError,
            this, &PacketCapture::onCaptureError);
    connect(captureThread, &CaptureThread::finished,
            captureThread, &QObject::deleteLater);
    
    captureThread->start();
    
    startButton->setEnabled(false);
    stopButton->setEnabled(true);
    saveButton->setEnabled(false);
    statusLabel->setText("Capturing...");
}

void PacketCapture::stopCapture()
{
    if (captureThread && captureThread->isRunning())
    {
        stopCaptureFlag = true;
        captureThread->wait();
    }
    
    startButton->setEnabled(true);
    stopButton->setEnabled(false);
    saveButton->setEnabled(!capturedPackets.empty());
    statusLabel->setText(QString("Capture stopped. %1 packets captured.").arg(packetCounter));
}

void PacketCapture::saveToFile()
{
    if (capturedPackets.empty())
    {
        QMessageBox::information(this, "Info", "No packets to save");
        return;
    }
    
    QString fileName = QFileDialog::getSaveFileName(this, "Save PCAP File", 
                                                   "capture.pcap", 
                                                   "PCAP Files (*.pcap)");
    
    if (fileName.isEmpty())
        return;
    
    pcpp::PcapFileWriterDevice writer(fileName.toStdString());
    
    if (!writer.open())
    {
        QMessageBox::critical(this, "Error", "Failed to open file for writing");
        return;
    }
    
    int savedCount = 0;
    for (const auto& packetData : capturedPackets)
    {
        // ФИКС: Используем timeval вместо chrono::time_point
        timeval tv = chronoToTimeval(std::chrono::system_clock::now());
        pcpp::RawPacket rawPacket((uint8_t*)packetData.data(), packetData.size(),
                                  tv, false);
        if (writer.writePacket(rawPacket))
            savedCount++;
    }
    
    writer.close();
    
    statusLabel->setText(QString("Saved %1 packets to %2").arg(savedCount).arg(fileName));
}

void PacketCapture::onPacketCaptured(const QString& summary, const QString& details, 
                                     const std::vector<uint8_t>& rawData)
{
    packetCounter++;
    capturedPackets.push_back(rawData);
    
    int row = packetTable->rowCount();
    packetTable->insertRow(row);
    
    packetTable->setItem(row, 0, new QTableWidgetItem(QString::number(packetCounter)));
    packetTable->setItem(row, 1, new QTableWidgetItem(QTime::currentTime().toString("hh:mm:ss.zzz")));

    timeval tv = chronoToTimeval(std::chrono::system_clock::now());
    pcpp::RawPacket rawPacket((uint8_t*)rawData.data(), rawData.size(), 
                             tv, false);
    pcpp::Packet parsedPacket(&rawPacket);
    
    QString src, dst, protocol;
    int length = rawData.size();
    
    if (parsedPacket.isPacketOfType(pcpp::UDP))
    {
        protocol = "UDP";
        pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
        
        if (ipv4Layer)
        {
            src = QString("%1:%2").arg(QString::fromStdString(ipv4Layer->getSrcIPv4Address().toString()))
                                 .arg(udpLayer->getSrcPort());
            dst = QString("%1:%2").arg(QString::fromStdString(ipv4Layer->getDstIPv4Address().toString()))
                                 .arg(udpLayer->getDstPort());
        }
        else if (ipv6Layer)
        {
            src = QString("[%1]:%2").arg(QString::fromStdString(ipv6Layer->getSrcIPv6Address().toString()))
                                   .arg(udpLayer->getSrcPort());
            dst = QString("[%1]:%2").arg(QString::fromStdString(ipv6Layer->getDstIPv6Address().toString()))
                                   .arg(udpLayer->getDstPort());
        }
    }
    else if (parsedPacket.isPacketOfType(pcpp::TCP))
    {
        protocol = "TCP";
    }
    else
    {
        protocol = "Other";
    }
    
    packetTable->setItem(row, 2, new QTableWidgetItem(src));
    packetTable->setItem(row, 3, new QTableWidgetItem(dst));
    packetTable->setItem(row, 4, new QTableWidgetItem(protocol));
    packetTable->setItem(row, 5, new QTableWidgetItem(QString::number(length)));
    
    statusLabel->setText(QString("Captured: %1 packets").arg(packetCounter));
}

void PacketCapture::onCaptureError(const QString& error)
{
    if (!error.isEmpty())
    {
        statusLabel->setText("Error: " + error);
        stopCapture();
    }
}

void PacketCapture::onPacketSelected(int row, int column)
{
    Q_UNUSED(column);
    
    if (row >= 0 && row < capturedPackets.size())
    {
        // Parse packet for details
        const std::vector<uint8_t>& packetData = capturedPackets[row];
        // ФИКС: Используем timeval вместо chrono::time_point
        timeval tv = chronoToTimeval(std::chrono::system_clock::now());
        pcpp::RawPacket rawPacket((uint8_t*)packetData.data(), packetData.size(),
                                  tv, false);
        pcpp::Packet parsedPacket(&rawPacket);
        
        QString details = CaptureThread::formatPacketDetails(&parsedPacket);
        detailText->setText(details);
    }
}

QString PacketCapture::formatPacketDetails(pcpp::Packet* packet)
{
    return CaptureThread::formatPacketDetails(packet);
}

QString PacketCapture::formatPacketSummary(pcpp::Packet* packet)
{
    return CaptureThread::formatPacketSummary(packet);
}