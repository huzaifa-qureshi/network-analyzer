#pragma once  

#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H
#include <string>
#include <Tins/tins.h>
#include <queue>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <thread>


class OUIResolver {
public:
    OUIResolver(const std::string& filename);
    std::string GetNameForOUI(const std::string& inputMAC) const;

private:
    void LoadOUIFile(const std::string& filename);
    std::map<std::string, std::string> ouiMap;
};

class LayerFilter {
public:
    std::string FilterDataLinkLayer(const Tins::PDU& pdu);
    std::string FilterNetworkLayer(const Tins::PDU& pdu);
    std::string FilterTransportLayer(const Tins::PDU& pdu);
};

class Analyzer {
public:
    Analyzer();
    void Start();
    bool Callback(Tins::PDU& pdu);
    void DisplayPacket(Tins::PDU& pdu);
    void UpdateFilter();
    void StartSniffing();
    void StopSniffing();
    void SavetoPCAP();

private:
    std::queue<Tins::IP> packets;
    std::string filter;
    bool isSniffing;
    OUIResolver ouiResolver;
};

#endif // PACKET_SNIFFER_H