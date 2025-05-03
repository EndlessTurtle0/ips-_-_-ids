#pragma once
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

// Global pointer to hold extracted blocks of data
string* Fblock;

// Define the DataPacket struct
// This struct is used to represent the details of a network packet.
struct DataPacket {
    string sourceIP;    // Source IP address of the packet
    string sourcePort;  // Source port of the packet
    string destIP;      // Destination IP address of the packet
    string destPort;    // Destination port of the packet
    string protocol;    // Protocol used by the packet (e.g., TCP, UDP)
    string data;        // Data carried by the packet
};

// Function to extract details of a DataPacket from a given string
// The input string should follow the format "SRC:<source IP>:<source port>;DST:<destination IP>:<destination port>;PRO:<protocol>;DATA:<data>"
DataPacket extractDataPacket(const string& dataPacket) {
    DataPacket dp;

    try {
        // Extract Source IP
        size_t srcStart = dataPacket.find("SRC:") + 4;
        size_t srcEnd = dataPacket.find(":", srcStart);
        dp.sourceIP = dataPacket.substr(srcStart, srcEnd - srcStart);

        // Extract Source Port
        size_t srcPortStart = srcEnd + 1;
        size_t srcPortEnd = dataPacket.find(";", srcPortStart);
        dp.sourcePort = dataPacket.substr(srcPortStart, srcPortEnd - srcPortStart);

        // Extract Destination IP
        size_t destStart = dataPacket.find("DST:") + 4;
        size_t destEnd = dataPacket.find(":", destStart);
        dp.destIP = dataPacket.substr(destStart, destEnd - destStart);

        // Extract Destination Port
        size_t destPortStart = destEnd + 1;
        size_t destPortEnd = dataPacket.find(";", destPortStart);
        dp.destPort = dataPacket.substr(destPortStart, destPortEnd - destPortStart);

        // Extract Protocol
        size_t protocolStart = dataPacket.find("PRO:") + 4;
        size_t protocolEnd = dataPacket.find(";", protocolStart);
        dp.protocol = dataPacket.substr(protocolStart, protocolEnd - protocolStart);

        // Extract Data
        size_t dataStart = dataPacket.find("DATA:") + 5;
        dp.data = dataPacket.substr(dataStart);

    } catch (const exception& e) {
        // Handle errors during parsing
        cerr << "Error extracting DataPacket: " << e.what() << endl;
    }

    return dp;
}

// Function to count the number of blocks in the traffic data file
// Blocks are enclosed in square brackets [ ]
int countblocks() {
    int blocks = 0;
    ifstream inputFile("traffic.txt"); // Open the file "traffic.txt"

    if (!inputFile.is_open()) {
        cerr << "Error: Could not open file " << endl;
        return 0; // Return 0 if the file cannot be opened
    }

    string currentBlock;
    char ch;

    while (inputFile.get(ch)) {
        if (ch == '[') {
            currentBlock.clear(); // Start a new block
        } else if (ch == ']') {
            // If block is not empty, increment the block counter
            if (!currentBlock.empty()) {
                blocks++;
                currentBlock.clear();
            }
        } else {
            currentBlock += ch;
        }
    }

    inputFile.close(); // Close the file
    return blocks; // Return the total number of blocks
}

// Function to read and store data packets from the traffic data file
void readDataPacket() {
    int lineCount = countblocks(); // Count the number of blocks in the file

    if (lineCount == 0) {
        return; // Exit if no blocks are found
    }

    ifstream inputFile("traffic.txt"); // Open the file "traffic.txt"

    if (!inputFile.is_open()) {
        cerr << "Error: Could not open file " << endl;
        return; // Exit if the file cannot be opened
    }

    string currentBlock;
    char ch;
    Fblock = new string[lineCount]; // Allocate memory to store blocks
    int move = 0;

    while (inputFile.get(ch)) {
        if (ch == '[') {
            currentBlock.clear(); // Start a new block
        } else if (ch == ']') {
            // Store the block if it is not empty
            if (!currentBlock.empty()) {
                Fblock[move] = currentBlock;
                move++;
                currentBlock.clear();
            }
        } else {
            currentBlock += ch;
        }
    }

    inputFile.close(); // Close the file
}

// Function to extract a DataPacket from a specific block index
// The index i corresponds to the block to process
DataPacket finaldatapacket(int i) {
    DataPacket dp = extractDataPacket(Fblock[i]); // Extract DataPacket details from the block
    return dp;
}
