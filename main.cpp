#include "NetworkAnalyzer.h"
#include "PacketSniffer.h"
#include <QtWidgets/QApplication>
#include <thread>

void start(int argc, char* argv[]) {
	Analyzer analyzer;
	//EventHandler handler(&analyzer);

	// Utilizing threading to run the functions simultaneously.
	std::thread snifferThread(&Analyzer::Start, &analyzer);
	//std::thread eventListenerThread(&EventHandler::EventListener, &handler);

	// Wait for both threads to end
	snifferThread.join();
	//eventListenerThread.join();
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetworkAnalyzer w;
    w.show();
    return a.exec();
}
