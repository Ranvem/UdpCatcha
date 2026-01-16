#include "packetplayer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QTime>
#include <QDebug>
#include <sys/time.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/PcapLiveDevice.h>

PlaybackThread::PlaybackThread(const QString& filename, const QString& interface, 
                               bool useTimestamps, int interval, QObject* parent)
    : QThread(parent), filename(filename), interface(interface), 
      useTimestamps(useTimestamps), interval(interval)
{
}

void PlaybackThread::run()  
{
    pcpp::PcapFileReaderDevice reader(filename.toStdString());
    
    if (!reader.open())
    {
        emit playbackError("Failed to open PCAP file");
        return;
    }
    
    pcpp::PcapLiveDevice* outputDev = pcpp::PcapLiveDeviceList::getInstance().getDeviceByName(interface.toStdString());
    
    if (!outputDev)
    {
        emit playbackError("Failed to find network interface");
        reader.close();
        return;
    }
    
    pcpp::PcapLiveDevice::DeviceConfiguration config;
    config.mode = pcpp::PcapLiveDevice::Promiscuous;
    
    if (!outputDev->open(config))
    {
        emit playbackError("Failed to open network interface");
        reader.close();
        return;
    }
    
    emit playbackStatus("Playback started");
    
    pcpp::RawPacket rawPacket;
    int packetCount = 0;
    timespec prevTimestamp = {0, 0};
    bool firstPacket = true;
    
    while (reader.getNextPacket(rawPacket))
    {
        if (isInterruptionRequested())
            break;
        
        timespec currTimestamp = rawPacket.getPacketTimeStamp();
        
        // Вычисляем и применяем задержку ПЕРЕД отправкой пакета
        if (!firstPacket)
        {
            if (useTimestamps)
    {
        qDebug() << "Using timestamps for delay calculation";
        qDebug() << "Current Timestamp: " << currTimestamp.tv_sec << "s " << currTimestamp.tv_nsec << "ns";
        
        // Вычисляем разницу во времени корректно
        long deltaSeconds = currTimestamp.tv_sec - prevTimestamp.tv_sec;
        long deltaNanos = currTimestamp.tv_nsec - prevTimestamp.tv_nsec;
        
        // Корректируем, если наносекунды отрицательные
        if (deltaNanos < 0) {
            deltaSeconds--;
            deltaNanos += 1000000000L;
        }
        
        double totalDelay = deltaSeconds + (deltaNanos / 1e9);
        
        qDebug() << "Delaying for" << totalDelay << "seconds";
        
        if (totalDelay > 0) {
            // Используем микросекунды для точности
            long long delayUs = static_cast<long long>(totalDelay * 1000000); // микросекунды
            
            // Разделяем задержку на миллисекунды и микросекунды
            unsigned int ms = static_cast<unsigned int>(delayUs / 1000);
            unsigned int us = static_cast<unsigned int>(delayUs % 1000);
            
            qDebug() << "Delaying for" << delayUs << "microseconds (" 
                     << ms << "ms + " << us << "us)";
            
            if (ms > 0) {
                QThread::msleep(ms);
            }
            if (us > 0) {
                QThread::usleep(us); // микросекунды
            }
        } else {
            qDebug() << "No delay needed or negative delay";
        }
    }
    else if (interval >= 0)
    {
        qDebug() << "Delaying for" << interval << "milliseconds";
        QThread::msleep(interval);
    }
        }
        
        // Отправляем пакет
        if (outputDev->sendPacket(rawPacket))
        {
            packetCount++;
            
            // Parse packet for info
            pcpp::Packet parsedPacket(&rawPacket);
            QString packetInfo;
            
            if (parsedPacket.isPacketOfType(pcpp::UDP))
            {
                pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
                packetInfo = QString("UDP Packet %1 -> %2 (Len: %3)")
                    .arg(udpLayer->getSrcPort())
                    .arg(udpLayer->getDstPort())
                    .arg(rawPacket.getRawDataLen());
            }
            else
            {
                packetInfo = QString("Packet %1 (Len: %2)")
                    .arg(packetCount)
                    .arg(rawPacket.getRawDataLen());
            }
            
            emit packetSent(packetInfo);
        }
        else
        {
            emit playbackError(QString("Failed to send packet %1").arg(packetCount));
        }
        
        // Сохраняем временную метку для следующего пакета
        prevTimestamp = currTimestamp;
        firstPacket = false;
    }
    
    outputDev->close();
    reader.close();
    
    emit playbackStatus(QString("Playback finished. Sent %1 packets.").arg(packetCount));
    emit playbackFinished();
}

PacketPlayer::PacketPlayer(QWidget *parent)
    : QWidget(parent), playbackThread(nullptr), isPlaying(false)
{
    setupUI();
    populateInterfaces();
}

PacketPlayer::~PacketPlayer()
{
    if (playbackThread && playbackThread->isRunning())
    {
        playbackThread->requestInterruption();
        playbackThread->wait();
    }
}

void PacketPlayer::setupUI()
{
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    QHBoxLayout *fileLayout = new QHBoxLayout();
    
    QLabel *fileLabel = new QLabel("PCAP File:", this);
    fileEdit = new QLineEdit(this);
    browseButton = new QPushButton("Browse...", this);
    
    fileLayout->addWidget(fileLabel);
    fileLayout->addWidget(fileEdit, 1);
    fileLayout->addWidget(browseButton);
    
    QFormLayout *controlLayout = new QFormLayout();
    
    QLabel *interfaceLabel = new QLabel("Interface:", this);
    interfaceCombo = new QComboBox(this);
    
    QLabel *intervalLabel = new QLabel("Interval (ms):", this);
    intervalSpin = new QSpinBox(this);
    intervalSpin->setRange(0, 10000);
    intervalSpin->setValue(0);
    intervalSpin->setSuffix(" ms");

    useTimestampCheck = new QCheckBox("Use Timestamps", this);
    useTimestampCheck->setChecked(false);
    
    playButton = new QPushButton("Start Playback", this);
    stopButton = new QPushButton("Stop Playback", this);
    stopButton->setEnabled(false);
    
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(playButton);
    buttonLayout->addWidget(stopButton);
    buttonLayout->addStretch();
    
    controlLayout->addRow(interfaceLabel, interfaceCombo);
    controlLayout->addRow(useTimestampCheck);
    controlLayout->addRow(intervalLabel, intervalSpin);
    controlLayout->addRow("", buttonLayout);
    
    logText = new QTextEdit(this);
    logText->setReadOnly(true);
    logText->setFont(QFont("Courier New", 9));
    
    statusLabel = new QLabel("Ready", this);
    
    mainLayout->addLayout(fileLayout);
    mainLayout->addLayout(controlLayout);
    mainLayout->addWidget(logText, 1);
    mainLayout->addWidget(statusLabel);
    
    connect(browseButton, &QPushButton::clicked, this, &PacketPlayer::browseFile);
    connect(playButton, &QPushButton::clicked, this, &PacketPlayer::startPlayback);
    connect(stopButton, &QPushButton::clicked, this, &PacketPlayer::stopPlayback);
}

void PacketPlayer::populateInterfaces()
{
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
        playButton->setEnabled(false);
    }
}

void PacketPlayer::browseFile()
{
    QString fileName = QFileDialog::getOpenFileName(this, "Open PCAP File", 
                                                   "", 
                                                   "PCAP Files (*.pcap *.pcapng)");
    
    if (!fileName.isEmpty())
    {
        fileEdit->setText(fileName);
    }
}

void PacketPlayer::startPlayback()
{
    if (fileEdit->text().isEmpty())
    {
        QMessageBox::warning(this, "Warning", "Please select a PCAP file");
        return;
    }
    
    if (interfaceCombo->currentIndex() < 0)
    {
        QMessageBox::warning(this, "Warning", "Please select an interface");
        return;
    }
    
    logText->clear();
    
    playbackThread = new PlaybackThread(fileEdit->text(), 
                                    interfaceCombo->currentData().toString(),
                                    useTimestampCheck->isChecked(),
                                    intervalSpin->value(),
                                    this);
    
    connect(playbackThread, &PlaybackThread::playbackStatus,
            this, &PacketPlayer::onPlaybackStatus);
    connect(playbackThread, &PlaybackThread::playbackError,
            this, &PacketPlayer::onPlaybackError);
    connect(playbackThread, &PlaybackThread::packetSent,
            this, &PacketPlayer::onPacketSent);
    connect(playbackThread, &PlaybackThread::playbackFinished,
            this, &PacketPlayer::onPlaybackFinished);
    connect(playbackThread, &PlaybackThread::finished,
            playbackThread, &QObject::deleteLater);
    
    playbackThread->start();
    
    isPlaying = true;
    playButton->setEnabled(false);
    stopButton->setEnabled(true);
    statusLabel->setText("Playback in progress...");
}

void PacketPlayer::stopPlayback()
{
    if (playbackThread && playbackThread->isRunning())
    {
        playbackThread->requestInterruption();
        playbackThread->wait();
    }
    
    isPlaying = false;
    playButton->setEnabled(true);
    stopButton->setEnabled(false);
    statusLabel->setText("Playback stopped");
}

void PacketPlayer::onPlaybackStatus(const QString& status)
{
    logText->append(QString("[%1] %2").arg(QTime::currentTime().toString("hh:mm:ss.zzz")).arg(status));
    statusLabel->setText(status);
}

void PacketPlayer::onPlaybackError(const QString& error)
{
    logText->append(QString("[%1] ERROR: %2").arg(QTime::currentTime().toString("hh:mm:ss.zzz")).arg(error));
    statusLabel->setText("Error: " + error);
}

void PacketPlayer::onPacketSent(const QString& packetInfo)
{
    logText->append(QString("[%1] Sent: %2").arg(QTime::currentTime().toString("hh:mm:ss.zzz")).arg(packetInfo));
}

void PacketPlayer::onPlaybackFinished()
{
    isPlaying = false;
    playButton->setEnabled(true);
    stopButton->setEnabled(false);
    statusLabel->setText("Playback finished");
}