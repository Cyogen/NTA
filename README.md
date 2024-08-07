# Network Traffic Analysis

## Objective

Gain a deep understanding of network traffic examination.   This will make it possible to determine anomalies.

### Skills Learned

- Collecting real-time traffic.
- Baseline setting for day-to-day communications
- Identification and analysis of non-standard or suspicious hosts, networking protocols, TCP issues, and network misconfigurations.
- Detecting malware on the wire (ransomware, exploits, non-standard interactions, etc)
- TCP/IP Stack & OSI Model

### Tools Used

- TcpDump
- Wireshark
- Tshark
- NGrep
- tcpick
- Network taps (Gigamon, Niagra-taps)
- Span Ports
- Elastic Stack
- SIEM (Splunk)
  
## Steps

Many of the tools mentioned above use various syntax and commands, but they all support Berkeley Packet Filter (BPF) syntax, which we will primarily use. BPF allows raw access to read and write at the Data-Link layer, providing valuable filtering and decoding capabilities. This [reference](https://www.ibm.com/docs/en/qsip/7.5?topic=queries-berkeley-packet-filters) will assist in learning, understanding and building more complicated queries.

# Identify TLS Handshake Via HTTPS

![TLSHandShake](https://github.com/user-attachments/assets/ceca8e07-112b-42e7-b48b-d319a630e33f)

The blue shows the client establishing a session to the server using port 443.  
The session is initiated using TCP, and a TLS ClientHello is sent to start the TLS Handshake. 
During the handshake the parameters are agreed on.  (Session ID, peer x509 cert, compression algorithm, cipher spec, session resumable, and the 48-byte master secret shared between client and server to validate the session. 

All data and methods will be sent through the TLS connection and appear as TLS Application Data (red box).
