#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>
#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <cmath>

using namespace std;

//       --- Ethernet Section ---

// Function to calculate CRC32
uint32_t calculateCRC(const vector<uint8_t>& data) {
    uint32_t crc = 0x00000000;
    const uint32_t polynomial = 0x814141AB;
    size_t totalBits = data.size() * 8;

    for (size_t i = 0; i < totalBits + 32; i++) {
        uint8_t currentBit = (i < totalBits) ? ((data[i / 8] >> (7 - (i % 8))) & 1) : 0;

        crc = (crc & 0x80000000) ? (crc << 1) ^ polynomial : crc << 1;
        crc ^= currentBit;
    }

    return crc;
}

// Function to convert a Hexadecimal String to Byte Array
vector<uint8_t> convertHexToBytes(const string& hex) 
{
    vector<uint8_t> byteArray;
    byteArray.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        byteArray.push_back(static_cast<uint8_t>(strtol(hex.substr(i, 2).c_str(), nullptr, 16)));
    }

    return byteArray;
}
// Function to print Frame Data in Groups of 4 Bytes
void printFrameInGroupsOf4(const vector<uint8_t>& data, size_t groupSize = 4) {
    for (size_t i = 0; i < data.size(); i++) {
        cout << hex << setfill('0') << setw(2) << (int)data[i] << " ";
        if ((i + 1) % groupSize == 0) cout << endl;
    }
    cout << endl;
}

// Function to build and show Ethernet frame
void buildAndShowFrame(const vector<uint8_t>& preamble,
    const uint8_t sfd,
    const vector<uint8_t>& destMac,
    const vector<uint8_t>& srcMac,
    const vector<uint8_t>& etherType,
    const vector<uint8_t>& payload) {
  
  vector<uint8_t> ethernetFrame;

 // Frame Construction
    ethernetFrame.insert(ethernetFrame.end(), preamble.begin(), preamble.end());
    ethernetFrame.push_back(sfd);
    ethernetFrame.insert(ethernetFrame.end(), destMac.begin(), destMac.end());
    ethernetFrame.insert(ethernetFrame.end(), srcMac.begin(), srcMac.end());
    ethernetFrame.insert(ethernetFrame.end(), etherType.begin(), etherType.end());
    ethernetFrame.insert(ethernetFrame.end(), payload.begin(), payload.end());

    // Compute and append CRC of the payload
    uint32_t payloadCRC = calculateCRC(payload);
    for (int i = 3; i >= 0; --i) {
        ethernetFrame.push_back((payloadCRC >> (8 * i)) & 0xFF);
    }

    //  Append Inter Frame Gap (IFG) bytes and padding
    const vector<uint8_t> interFrameGap (12, 0x07);
    ethernetFrame.insert(ethernetFrame.end(), interFrameGap.begin(), interFrameGap.end());

    // Padding to align to 4-byte boundaries
    while (ethernetFrame.size() % 4 != 0) {
        ethernetFrame.push_back(0x07);
    }
    // Display the frame
     cout << "Ethernet frame (Grouped by 4 bytes) (with IFG padding):" << endl;
    printFrameInGroupsOf4(ethernetFrame);
}

// Function to transmit Inter Frame Gap (IFG) Bytes 
void transmitIFGs(size_t totalIFGs) {
    const vector<uint8_t> ifgBytes = {0x07, 0x07, 0x07, 0x07};
    size_t transmitted = 0;

    for (size_t i = 0; i < totalIFGs; ++i) {
        cout << hex << setfill('0') << setw(2) << (int)ifgBytes[transmitted++ % 4] << " ";
        if (transmitted % 4 == 0) cout << endl;
    }

    if (transmitted % 4 != 0) cout << endl;  // Print remaining bytes
}

//       --- eCPRI Section ---

// Function to form structure and generate eCPRI header

struct EcpriHeader {
    uint8_t version_reserved_concat; // 4 bits version, 3 bits reserved, 1 bit concatenation
    uint8_t message_type;                   // 1 byte 
    uint16_t payload_size;                  // 2 bytes 
    uint16_t rtc_pc;                        // 2 bytes RTC_PC (fixed as 0x0000)
    uint16_t seq_id;                        // 2 bytes
};

// Function to create eCPRI header with given message type, payload size, and sequence ID

EcpriHeader createEcpriHeader(uint8_t messageType, uint16_t payloadSize, uint16_t seqID) {
    return {
        0x00,         // version_reserved_concat (4 bits version set to 0x1, others reserved)
        messageType,  // Set the message type
        payloadSize,  // Set the payload size
        0x0000,       // rtc_pc is fixed to 0x0000
        seqID         // Sequence ID
    };
}

// Function to generate eCPRI packets

vector<vector<uint8_t>> generateEcpriPackets(const vector<uint8_t>& payload, uint16_t maxPayloadSize) {
    vector<vector<uint8_t>> allPackets;  // Store all generated packets
    uint16_t seqID = 0;                  
    size_t totalPayloadSize = payload.size();   // Total size of the payload
    size_t offset = 0; 

    while (offset < totalPayloadSize) {
        size_t currentPayloadSize = min(static_cast<size_t>(maxPayloadSize), totalPayloadSize - offset);
        EcpriHeader header = createEcpriHeader(0x00, currentPayloadSize, seqID);
// Build packet with header and current payload 
       vector<uint8_t> packet = {
            header.version_reserved_concat,
            header.message_type,
            static_cast<uint8_t>(header.payload_size >> 8), static_cast<uint8_t>(header.payload_size & 0xFF),
            static_cast<uint8_t>(header.rtc_pc >> 8), static_cast<uint8_t>(header.rtc_pc & 0xFF),
            static_cast<uint8_t>(header.seq_id >> 8), static_cast<uint8_t>(header.seq_id & 0xFF)
        };

        packet.insert(packet.end(), payload.begin() + offset, payload.begin() + offset + currentPayloadSize);
        allPackets.push_back(packet);    
        offset += currentPayloadSize;            

        seqID = (seqID + 1) % 256;       
    }

    return allPackets;  // Return all generated packets
}

// Function to display the contents of each packet (header and payload)

void displayPackets(const vector<vector<uint8_t>>& packets) {
    for (size_t i = 0; i < packets.size(); ++i) {
        const vector<uint8_t>& packet = packets[i];

        // Display packet number
        cout << "eCPRI Packet " << dec << (i + 1) << ":\n";

        cout << "Header: ";
        for (size_t j = 0; j < 8; ++j) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(packet[j]) << " ";
        }
        cout << "\nPayload: ";

        // Display remaining bytes of payload
        cout << "Payload: ";
        for (size_t j = 8; j < packet.size(); ++j) {
            cout << hex << setw(2) << setfill('0') << static_cast<int>(packet[j]) << " ";
        }
        cout << "\n\n";
    }
}

// Function to flatten packet list into a single continuous vector
vector<uint8_t> flattenPackets(const vector<vector<uint8_t>>& packets) {
    vector<uint8_t> flatData;
    for (const auto& packet : packets) {
        flatData.insert(flatData.end(), packet.begin(), packet.end());
    }
    return flatData;
}

//       --- ORAN Section ---

// Function to  Calculate no of packets per symbol

int calculatePacketsPerSymbol(uint16_t MaxNrb, uint16_t NrbPerPacket) {
   double ratio = static_cast<double>(MaxNrb) / NrbPerPacket;
    return ceil(ratio);
}
// Function to  Calculate no of slots per frame

int calculateSlotsPerFrame(uint8_t SCS) {
     if (SCS == 15) return 10;
    if (SCS == 30) return 20;
    if (SCS == 60) return 40;
    return 0; 
}
// Function to generate ORAN User Plane Header

   vector<uint8_t> generateORANHeader(uint8_t frameID, uint8_t subframeID, uint8_t slotID, uint8_t symbolID, uint16_t MaxNrb) {
       vector<uint8_t> header(8, 0x00); 

    header[0] = 0x00;
    header[1] = ((frameID & 0x0F) << 4) | (subframeID & 0x0F);
    header[2] = (slotID & 0x3F);   
    header[3] = ((symbolID & 0x3F) << 2); 
    header[4] = 0x00; 
    header[5] = 0x10; 
    header[6] = 0x08; 
    header[7] = (MaxNrb == 273) ? 0 : (MaxNrb & 0xFF);

    return header;
}
// Function to read the IQ file 

   vector<uint8_t> readPayloadFromFile(const string &filename, int payloadSize) {
        vector<uint8_t> payload;
        ifstream file(filename);
        string line;
    int value;
    
       if (!file.is_open()) {
        std::cerr << "Unable to open file: " << filename << "\n";
        return payload;
    }

    while (getline(file, line) && payload.size() < payloadSize) {
        std::istringstream iss(line);
        while (iss >> value && payload.size() < payloadSize) {
            if (value < -128 || value > 127) {
                std::cerr << "Invalid value in file: " << value << "\n";
                continue;
            }
            payload.push_back(static_cast<uint8_t>(value));
        }
    }
    file.close();
    
    return payload;
}

//Function to Read input Configration file

void readConfigValues(ifstream& inputFile, double& LineRate, int& CaptureSize_ms, int& MinNumOfIFGsPerPacket, string& DestAddress, string& SourceAddress, size_t& MaxPacketSize, uint16_t& SC, uint16_t& MaxNrb, uint16_t& NrbPerPacket) {
    string line;
    if (getline(inputFile, line)) istringstream(line) >> LineRate;
    if (getline(inputFile, line)) istringstream(line) >> CaptureSize_ms;
    if (getline(inputFile, line)) istringstream(line) >> MinNumOfIFGsPerPacket;

    getline(inputFile, DestAddress);
    getline(inputFile, SourceAddress);

    if (getline(inputFile, line)) istringstream(line) >> MaxPacketSize;
    if (getline(inputFile, line)) istringstream(line) >> SC;
    if (getline(inputFile, line)) istringstream(line) >> MaxNrb;
    if (getline(inputFile, line)) istringstream(line) >> NrbPerPacket;
}

//Function to generate ORAN Packets
void generateORANPackets(int totalPackets, int totalPayloadBytesPerFrame, int totalPacketsPerFrame, const vector<uint8_t>& totalPayload, int CaptureSize_ms, uint16_t MaxNrb, uint8_t slotsPerFrame, int packetPayloadSize, vector<uint8_t>& ORAN_Concatinating_Packets) {
    int frameID = 0;
    uint8_t subframeID = 0, slotID = 0, symbolID = 0;
    int currentPayloadIndex = 0, counter = 0;
    
    cout << "Generating frame no " << dec << frameID << ":\n\n";
    for (int i = 0; i < totalPackets; ++i) {
        vector<uint8_t> header = generateORANHeader(frameID, subframeID, slotID, symbolID, MaxNrb);

        cout << "ORAN packet " << dec << i + 1 << ":\n";
        cout << "Header:\n  First Byte: 0x" << setw(2) << setfill('0') << hex << (int)header[0] << "\n";
        cout << "  Frame ID: " << dec << ((header[1] >> 4) & 0x0F) << "\n";
        cout << "  Subframe ID: " << dec << (header[1] & 0x0F) << "\n";
        cout << "  Slot ID: " << dec << (int)header[2] << "\n";
        cout << "  Symbol ID: " << dec << ((header[3] >> 2) & 0x3F) << "\n";
        cout << "  Section ID: " << dec << 1 << "\n";  // Section ID is always 1
        /* Note that RB is always 0
         symbInc is always 0
         startPrbu is always 1
        numPrbu is MaxNrb we already entered */

        cout << "Payload: ";
        for (int j = currentPayloadIndex; j < currentPayloadIndex + packetPayloadSize && j < totalPayload.size(); ++j) {
            cout << "0x" << setw(2) << setfill('0') << hex << (int)totalPayload[j] << " ";
        }
        cout << dec << "\n\n";
    
        ORAN_Concatinating_Packets.insert(ORAN_Concatinating_Packets.end(), header.begin(), header.end());
        ORAN_Concatinating_Packets.insert(ORAN_Concatinating_Packets.end(), totalPayload.begin() + currentPayloadIndex, totalPayload.begin() + currentPayloadIndex + packetPayloadSize);

        currentPayloadIndex += packetPayloadSize;
        counter++;
        if (counter == calculatePacketsPerSymbol(MaxNrb, 0)) {  // Reset per symbol
            symbolID++;
            counter = 0;
        }
        if (symbolID == 14) {  // After all symbols in slot
            symbolID = 0;
            slotID++;
            if (slotID == slotsPerFrame / 10) {  // After all slots in subframe
                slotID = 0;
                subframeID++;
                if (subframeID == 10) {  // After all subframes in frame
                    subframeID = 0;
                    frameID++;
                    if (frameID < CaptureSize_ms / 10) {
                        cout << "Generating frame no " << dec << frameID << ":\n\n";
                    }
                }
            }
        }
    }
}

void generateEthernetPackets(int totalPackets, const vector<uint8_t>& eCPRI_Concatinating_Packets, const vector<uint8_t>& preamble, uint8_t sfd, const vector<uint8_t>& destMacBytes, const vector<uint8_t>& srcMacBytes, const vector<uint8_t>& etherTypeBytes, int packetSize, size_t ifgsBytesTotal) {
    int index = 0, packetCount = 0;

    while (packetCount < totalPackets) {
        vector<uint8_t> packetBytes(eCPRI_Concatinating_Packets.begin() + index, eCPRI_Concatinating_Packets.begin() + index + packetSize);
        cout << "Constructing and displaying Packet " << (packetCount + 1) << ":\n\n";
        buildAndShowFrame(preamble, sfd, destMacBytes, srcMacBytes, etherTypeBytes, packetBytes);

        index += packetSize;
        ++packetCount;
    }

    // Simulate sending IFG bytes for the remaining capture time
    cout << "\nSending IFG bytes for the rest of capture size\n";
    transmitIFGs(ifgsBytesTotal);
}

//       --- Main Section ---
int main() {
    double LineRate;
    int MinNumOfIFGsPerPacket, CaptureSize_ms;
    size_t MaxPacketSize;
    string DestAddress, SourceAddress;
    uint16_t SC, MaxNrb, NrbPerPacket;

    ifstream inputFile("configrationfile.txt");
    if (!inputFile.is_open()) {
        cerr << "Error: Unable to open configuration file." << endl;
        return -1;
    }

    readConfigValues(inputFile, LineRate, CaptureSize_ms, MinNumOfIFGsPerPacket, DestAddress, SourceAddress, MaxPacketSize, SC, MaxNrb, NrbPerPacket);
    inputFile.close();

    vector<uint8_t> destMacBytes = convertHexToBytes(DestAddress);
    vector<uint8_t> srcMacBytes = convertHexToBytes(SourceAddress);
    const vector<uint8_t> etherTypeBytes = {0xDD, 0xDD};
    const vector<uint8_t> preamble = {0xFB, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    const uint8_t sfd = 0xD5;

    ofstream outFile("Outputfile_M2.txt");
    if (!outFile.is_open()) {
        cerr << "Failed to open output file!" << endl;
        return 1;
    }
    streambuf* coutbuf = cout.rdbuf();  // Save original cout buffer
    cout.rdbuf(outFile.rdbuf());  // Redirect cout to file

    // Processing Packets
    int packetsPerSlot = calculatePacketsPerSymbol(MaxNrb, NrbPerPacket) * 14;
    int slotsPerFrame = calculateSlotsPerFrame(SC);
    if (slotsPerFrame == 0) {
        cout << "Invalid Subcarrier Spacing\n";
        return 5;
    }
    
    int totalPackets_perFrame = packetsPerSlot * slotsPerFrame;
    int totalPackets = totalPackets_perFrame * (CaptureSize_ms / 10);
    int totalPayloadBytes_perFrame = ((2 * 16 * 12 * NrbPerPacket * totalPackets_perFrame) - totalPackets_perFrame * 64) / 8;
    
    string filename = "iq_file.txt";
    vector<uint8_t> totalPayload = readPayloadFromFile(filename, totalPayloadBytes_perFrame * (CaptureSize_ms / 10));

    // ORAN Packet Generation
    vector<uint8_t> ORAN_Concatinating_Packets;
    generateORANPackets(totalPackets, totalPayloadBytes_perFrame, totalPackets_perFrame, totalPayload, CaptureSize_ms, MaxNrb, slotsPerFrame, totalPayloadBytes_perFrame / totalPackets_perFrame, ORAN_Concatinating_Packets);

    // eCPRI Packet Generation
    cout << dec << "\n";
    cout << " Generating eCPRI Packets " << "\n";
    cout << dec << "\n";
    vector<vector<uint8_t>> ecpriPackets = generateEcpriPackets(ORAN_Concatinating_Packets, totalPayloadBytes_perFrame / totalPackets_perFrame);
    displayPackets(ecpriPackets);
    vector<uint8_t> eCPRI_Concatinating_Packets = flattenPackets(ecpriPackets);
 
    //Summary of the eCPRI Packets
    cout << "\n Summary of the eCPRI Packets \n";
    cout << "eCPRI TotalPackets: " << dec << totalPackets<< "\n";
    cout << "eCPRI Total Packets Size (bytes): " << eCPRI_Concatinating_Packets.size() << "\n";

    // Ethernet Packet Generation
    float CaptureSize_us = CaptureSize_ms * 1000;
    size_t CaptureSize_totalBytes = ceil((CaptureSize_us * (LineRate / 1000000)) / 8);
    size_t ifgsBytesTotal = ceil(CaptureSize_totalBytes - (eCPRI_Concatinating_Packets.size() + totalPackets * 26 + MinNumOfIFGsPerPacket));
    generateEthernetPackets(totalPackets, eCPRI_Concatinating_Packets, preamble, sfd, destMacBytes, srcMacBytes, etherTypeBytes, eCPRI_Concatinating_Packets.size() / totalPackets, ifgsBytesTotal);

    // Ethernet Packet Summary
    cout << "\nSummary of the Ethernet Packets\n";
    cout << "Total Bytes in the Capture Size: " << dec << CaptureSize_totalBytes << endl;
    cout << "Total Bytes of The Ethernet Packets sent in Capture Size: " << dec << (CaptureSize_totalBytes - ifgsBytesTotal) << endl;
    cout << "Total IFG Bytes sent for the rest of Capture Size: " << dec << ifgsBytesTotal << endl;
    cout << "Total Ethernet Packets Sent: " << totalPackets << endl;

    cout.rdbuf(coutbuf);  // Restore original cout buffer
    outFile.close();
    return 0;
}