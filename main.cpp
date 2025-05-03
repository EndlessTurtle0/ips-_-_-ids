#include "rules.h"   
#include "traffic.h" 
#include <fstream>
#include <sstream>
#include <iostream>

using namespace std;

int main() {

    int Rline = 0;       // Variable to store the number of rules
    int dpblocks = 0;    // Variable to store the number of data packet blocks

    // Read all rules from the file
    readRule();
    Rline = linecounts(); // Get the number of rules

    // Array to store all the rules
    Rule r[Rline];
    for (int i = 0; i < Rline; i++) {
        r[i] = finalrule(i); // Extract each rule
    }

    // Print all extracted rules
    for (int i = 0; i < Rline; i++) {
        cout << "Rule FINAL " << i + 1 << ":\n";
        cout << "  Action: " << r[i].action << '\n';
        cout << "  Protocol: " << r[i].protocol << '\n';
        cout << "  Source IP: " << r[i].sourceIP << '\n';
        cout << "  Source Port: " << r[i].sourcePort << '\n';
        cout << "  Destination IP: " << r[i].destIP << '\n';
        cout << "  Destination Port: " << r[i].destPort << '\n';
        cout << "  Message: " << r[i].msg << '\n';
        cout << "  SID: " << r[i].sid << '\n';
        cout << "--------------------------------\n";
    }

    // Read all data packets from the file
    readDataPacket();
    dpblocks = countblocks(); // Get the number of data packet blocks

    // Array to store all data packets
    DataPacket dp[dpblocks];
    for (int i = 0; i < dpblocks; i++) {
        dp[i] = finaldatapacket(i); // Extract each data packet
    }

    // Print all extracted data packets
    for (int i = 0; i < dpblocks; i++) {
        cout << "Source IP Final: " << dp[i].sourceIP << endl;
        cout << "Source Port: " << dp[i].sourcePort << endl;
        cout << "Destination IP: " << dp[i].destIP << endl;
        cout << "Destination Port: " << dp[i].destPort << endl;
        cout << "Protocol: " << dp[i].protocol << endl;
        cout << "Data: " << dp[i].data << endl;
        cout << "----------------------------------" << endl;
    }

    // Open a log file to write results
    ofstream outputFile("result.log");
    if (!outputFile.is_open()) {
        cerr << "Error: Could not open result.log for writing.\n";
        return 1;
    }

    // Compare data packets against rules and log matches
    for (int i = 0; i < dpblocks; i++) {
        for (int j = 0; j < Rline; j++) {
            // Skip if any attribute in the rule is set to "any"
            if (dp[i].destIP == "any" || dp[i].destPort == "any" || dp[i].protocol == "any" || 
                dp[i].sourceIP == "any" || dp[i].sourcePort == "any") {
                break;
            }
            // Check for matches between data packets and rules
            else if (dp[i].sourceIP == r[j].sourceIP || dp[i].destIP == r[j].destIP || 
                     dp[i].sourcePort == r[j].sourcePort || dp[i].destPort == r[j].destPort) {

                // Print the matched rule and data packet
                cout << "SRC:" << dp[i].sourceIP << ":" << dp[i].sourcePort
                     << " DST:" << dp[i].destIP << ":" << dp[i].destPort
                     << " PRO:" << dp[i].protocol
                     << " ACTION:" << r[j].action
                     << " MSG:\"" << r[j].msg << "\""
                     << " SID:" << r[j].sid << endl;

                // Log the matched rule and data packet
                outputFile << "SRC:" << dp[i].sourceIP << ":" << dp[i].sourcePort
                           << " DST:" << dp[i].destIP << ":" << dp[i].destPort
                           << " PRO:" << dp[i].protocol
                           << " ACTION:" << r[j].action
                           << " MSG:\"" << r[j].msg << "\""
                           << " SID:" << r[j].sid << endl;

                break;
            }
        }
    }

    outputFile.close(); // Close the log file

    return 0;
}
