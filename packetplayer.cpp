#include "packetplayer.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>

#include <sys/time.h>

PlaybackThread::PlaybackThread(const QString& filename, const QString& interface, 
                               int interval, QObject* parent)
    : QThread(parent), filename(filename), interface(interface), interval(interval)
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
    
    while (reader.getNextPacket(rawPacket))
    {
        if (isInterruptionRequested())
            break;
        
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
            
            if (interval > 0)
                msleep(interval);
        }
        else
        {
            emit playbackError(QString("Failed to send packet %1").arg(packetCount));
        }
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
    
    playButton = new QPushButton("Start Playback", this);
    stopButton = new QPushButton("Stop Playback", this);
    stopButton->setEnabled(false);
    
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(playButton);
    buttonLayout->addWidget(stopButton);
    buttonLayout->addStretch();
    
    controlLayout->addRow(interfaceLabel, interfaceCombo);
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
    
    // Clear log
    logText->clear();
    
    // Start playback thread
    playbackThread = new PlaybackThread(fileEdit->text(), 
                                        interfaceCombo->currentData().toString(),
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