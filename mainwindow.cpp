#include "mainwindow.h"
#include <QVBoxLayout>
#include <QWidget>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setWindowTitle("UDP Packet Analyzer");
    setGeometry(100, 100, 1200, 800);

    // Create central widget
    QWidget *centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    
    // Create tab widget
    tabWidget = new QTabWidget(this);
    
    // Create pages
    capturePage = new PacketCapture(this);
    playerPage = new PacketPlayer(this);
    
    // Add tabs
    tabWidget->addTab(capturePage, "Capture");
    tabWidget->addTab(playerPage, "Playback");
    
    mainLayout->addWidget(tabWidget);
    
    // Create status bar
    statusBar = new QStatusBar(this);
    setStatusBar(statusBar);
    statusBar->showMessage("Ready");
}

MainWindow::~MainWindow()
{
}