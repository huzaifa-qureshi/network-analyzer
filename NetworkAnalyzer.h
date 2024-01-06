#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_NetworkAnalyzer.h"

class NetworkAnalyzer : public QMainWindow
{
    Q_OBJECT

public:
    NetworkAnalyzer(QWidget *parent = nullptr);
    ~NetworkAnalyzer();

private slots:
    void on_StartSniffingButton_clicked();

    void on_StopSniffingButton_clicked();

    void on_AnalysisButton_clicked();

    void on_SaveButton_clicked();

private:
    Ui::NetworkAnalyzerClass ui;
};
