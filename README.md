# Computer-Network_181_125
# CS331 – Computer Networks Assignment 1  
## Task-1: DNS Resolver  

### 📌 Project Overview
This project implements a **custom DNS resolver** using a client-server model.  

The resolver workflow:
1. **Client**
   - Parses DNS queries from a `.pcap` file.
   - Creates a **custom header (HHMMSSID)** containing timestamp and query sequence ID.
   - Sends DNS queries with the custom header to the server.  
2. **Server**
   - Extracts the custom header from incoming queries.
   - Applies **predefined IP mapping rules** (`rules.json`) to resolve the domain.
   - Returns the resolved IP address back to the client.
3. Pcap file we use for our group is "6.pcap".(As mention in the report according to the X = (Your last 3-digit of roll no + your teammate's last 3-digit of roll no)%10.)
    
4. **Result**
   - Both PCAP-based and live queries are logged.
   - Results are presented in a **report table** containing header, domain, and resolved IP.
  
---

### 📂 Repository Structure
├── client.py # Client implementation
├── server.py # Server implementation
├── rules.json # IP mapping rules
├── README.md # Project documentation
└── report.pdf # Final report with results


Libraries used:
*scapy
*socket
*argparse
*json
*datetime


**How to Run**
1. Start the Server
Run the DNS resolver server with IP, port, and rules file:
Command: python server.py --ip 127.0.0.1 --port 53531 --rules rules.json

2. Run the Client (Process PCAP File)
Command : python client.py --server-ip 127.0.0.1 --server-port 53531 --pcap X.pcap

3. Run the Client (Live DNS Query)
Command : python client.py --server-ip 127.0.0.1 --server-port 53531 --query google.com


Task 2 : Traceroute Protocol Behavior
The Answer of the task 2 is in the "Report.pdf" with the screenshots. 


   
