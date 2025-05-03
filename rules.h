#pragma once
#include <iostream>
#include <fstream>
#include <string>

using namespace std;

// Global pointer to hold extracted rules
string* rules;

// Define the Rule struct
// This struct is used to represent the details of a network rule.
struct Rule {
    string action;       // The action to take (e.g., alert, drop)
    string protocol;     // The protocol to match (e.g., TCP, UDP)
    string sourceIP;     // The source IP address
    string sourcePort;   // The source port
    string destIP;       // The destination IP address
    string destPort;     // The destination port
    string msg;          // A descriptive message for the rule
    string sid;          // The unique rule identifier (SID)
};

// Function to extract details of a Rule from a given string
// The input string should follow a format typical for rule definitions
Rule extractRule(const string& rule) {
    Rule r;

    try {
        size_t pos = 0;

        // Extract Action
        size_t actionEnd = rule.find(" ");
        r.action = rule.substr(0, actionEnd);

        // Extract Protocol
        size_t protocolStart = actionEnd + 1;
        size_t protocolEnd = rule.find(" ", protocolStart);
        r.protocol = rule.substr(protocolStart, protocolEnd - protocolStart);

        // Extract Source IP
        size_t srcIPStart = protocolEnd + 1;
        size_t srcIPEnd = rule.find(" ", srcIPStart);
        r.sourceIP = rule.substr(srcIPStart, srcIPEnd - srcIPStart);

        // Extract Source Port
        size_t srcPortStart = srcIPEnd + 1;
        size_t srcPortEnd = rule.find(" ", srcPortStart);
        r.sourcePort = rule.substr(srcPortStart, srcPortEnd - srcPortStart);

        // Extract Destination IP
        size_t destIPStart = srcPortEnd + 4; // Skip "-> "
        size_t destIPEnd = rule.find(" ", destIPStart);
        r.destIP = rule.substr(destIPStart, destIPEnd - destIPStart);

        // Extract Destination Port
        size_t destPortStart = destIPEnd + 1;
        size_t destPortEnd = rule.find(" ", destPortStart);
        r.destPort = rule.substr(destPortStart, destPortEnd - destPortStart);

        // Extract Message
        size_t msgStart = rule.find("msg:") + 5;
        size_t msgEnd = rule.find(";", msgStart);
        r.msg = rule.substr(msgStart, msgEnd - msgStart);

        // Extract SID
        size_t sidStart = rule.find("sid:") + 4;
        size_t sidEnd = rule.find(";", sidStart);
        r.sid = rule.substr(sidStart, sidEnd - sidStart);

    } catch (const exception& e) {
        // Handle errors during parsing
        cerr << "Error parsing rule: " << e.what() << "\n";
    }

    return r;
}

// Function to count the number of lines in the rules file
// Each line corresponds to a rule
int linecounts() {
    int lc = 0; // Line count
    string temp;
    ifstream inputFile("rules.txt"); // Open the file "rules.txt"

    if (!inputFile) {
        cerr << "Error: Could not open the file.\n";
        return 1; // Return 1 if the file cannot be opened
    }

    // Count lines in the file
    while (getline(inputFile, temp)) {
        lc++;
    }

    inputFile.close(); // Close the file
    return lc; // Return the line count
}

// Function to read and process rules from the file
// The rules are stored in the global "rules" array
int readRule(int pos = 0) {
    ifstream inputFile("rules.txt"); // Open the file "rules.txt"

    if (!inputFile) {
        cerr << "Error: Could not open the file.\n";
        return 1; // Return 1 if the file cannot be opened
    }

    int lineCount = linecounts(); // Get the number of lines (rules)

    // Allocate memory to store rules
    rules = new string[lineCount];

    // Read each line into the "rules" array
    for (int i = 0; i < lineCount; i++) {
        getline(inputFile, rules[i]);
    }

    inputFile.close(); // Close the file

    return 0; // Return 0 on success
}

// Function to extract a Rule from a specific line index
// The index i corresponds to the rule to process
Rule finalrule(int i) {
    Rule r = extractRule(rules[i]); // Extract Rule details from the line
    return r;
}
