#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QStatusBar>

// Прямые включения
#include "packetcapture.h"
#include "packetplayer.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    QTabWidget *tabWidget;
    PacketCapture *capturePage;
    PacketPlayer *playerPage;
    QStatusBar *statusBar;
};

#endif // MAINWINDOW_H