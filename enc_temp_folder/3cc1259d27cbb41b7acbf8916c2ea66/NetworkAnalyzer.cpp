#include "NetworkAnalyzer.h"
#include <QDebug>
#include <QIcon>

NetworkAnalyzer::NetworkAnalyzer(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);

    ui.StartSniffingButton->setIcon(QIcon("./Assets/Icons/play.png"));

    ui.StopSniffingButton->setIcon(QIcon("/Users/Qureshi - Octdaily/Desktop/NED/DSA FINAL PROJECT/FINAL FINAL/network-analyzer/Assets/Icons/Stop.png"));
 
}

NetworkAnalyzer::~NetworkAnalyzer()
{}

void NetworkAnalyzer::on_StartSniffingButton_clicked()
{
    qDebug() << "Start";
}


void NetworkAnalyzer::on_StopSniffingButton_clicked()
{
    qDebug() << "Stop";
}


void NetworkAnalyzer::on_AnalysisButton_clicked()
{
    qDebug() << "Analysis";
}


void NetworkAnalyzer::on_SaveButton_clicked()
{
    qDebug() << "Save as Pcap";
}

