#include "NetworkAnalyzer.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetworkAnalyzer w;
    w.show();
    return a.exec();
}
