🛡️ Basic IPS/IDS Script Guide

This script is designed for basic Intrusion Detection/Prevention operations. 
You can define custom rules and packets to generate meaningful alerts and simulate network monitoring behavior.

==============================================================================
                                    How to Use
==============================================================================

✅ Define Rules

You can add specific rules to customize detection based on your needs.

Rule Format:
<action> <protocol> <source_ip> <source_port> -> <destination_ip> <destination_port> (<rule_options>)

Rule Components Explained:
| Component               | Description                                                  | Example             |
|------------------------|--------------------------------------------------------------|---------------------|
| alert                  | Action to take (e.g., alert, log, pass, drop)                | alert               |
| tcp                    | Protocol (e.g., tcp, udp, icmp, ip)                          | tcp                 |
| 192.168.1.18           | Source IP address (or any for all sources)                   | any                 |
| any                    | Source port (or specific port)                               | 80                  |
| ->                     | Traffic direction indicator                                  | ->                  |
| any                    | Destination IP address                                       | any                 |
| 80                     | Destination port                                             | 443                 |
| (msg:"..."; sid:...;)  | Rule options block (e.g., message, rule ID, etc.)            | msg:"Alert!"; sid:10001; |

==============================================================================

📦 Define Packets

You can also add specific packets to test and simulate the detection system.

Packet Format:
[SRC:<SRC_IP>:<SRC_PORT>; DST:<DST_IP>:<DST_PORT>; PRO:<PROTOCOL>; DATA:<PAYLOAD>]

Packet Fields Explained:
| Field       | Description                                  | Example             |
|-------------|----------------------------------------------|---------------------|
| SRC_IP      | Source IP address or any                     | 192.168.1.100       |
| SRC_PORT    | Source port number or any                    | 80                  |
| DST_IP      | Destination IP address                       | 192.168.1.1         |
| DST_PORT    | Destination port number                      | 60                  |
| PROTOCOL    | Protocol (TCP, UDP, ICMP, or any)            | TCP                 |
| PAYLOAD     | Payload content (hex, keywords, etc.)        | F34A2D2EF0, TRAVERSAL |
