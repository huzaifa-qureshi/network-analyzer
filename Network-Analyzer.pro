#-------------------------------------------------
#
# Project created by QtCreator 2021-02-10T10:04:29
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 5): QT += widgets

TARGET = NetworkAnalyzer
TEMPLATE = app


SOURCES += main.cpp\
   NetworkAnalyzer.cpp\
   PacketSniffer.cpp

HEADERS  += \
   NetworkAnalyzer.h\
   PacketSniffer.h

FORMS    += \
   NetworkAnalyzer.ui

RESOURCES +=
   NetworkAnalyzer.qrc

DISTFILES += \
   Network-Analyzer.vcxproj
