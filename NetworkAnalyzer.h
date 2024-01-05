#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_NetworkAnalyzer.h"

class NetworkAnalyzer : public QMainWindow
{
    Q_OBJECT

public:
    NetworkAnalyzer(QWidget *parent = nullptr);
    ~NetworkAnalyzer();

private:
    Ui::NetworkAnalyzerClass ui;
};
