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

- [Tcpdump](#tcpdump)
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

# TLS Handshake (RFC:2246)
1. Client and server excahnge hello messages to agree on connection parameters.
2. Client and server exchange necessary cryptographic parameters to establish a premaster secret.
3. Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
4. Generate a master secret from the premaster secret and exchanged random values.
5. Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
6. Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.

# FTP (RFC:959)
![ftp-example](https://github.com/user-attachments/assets/12ca390a-dd51-490f-8778-a3263561dc90)

Green arrows are requests issued to the FTP server, the responses sent back from the FTP server are blue arrows.

FTP Commands:
USER, PASS, PORT, PASV, LIST, CWD, PWD, SIZE, RETR, QUIT.

# Effective Analysis

1.  Know your environment.
2.  Host placement for capturing traffic is critical.
3.  Persistence

# Analysis Approach

Standard protocols first then work into specific only to the org. HTTP/S, FTP, E-mail, and basic TCP uDP traffic will be the most common things seen coming from around the world.
Start with these and clear out anything that is not necessary.  then checo for stanard protocls that allow for communications between networks, such as SSH, RDP, or Telnet. 
(Be mindful of your network sec policy).

- Look for patterns.
- Check for host to host connections.
- Look for unique events:
  Host visiting a specific site multiple times a day and changing its pattern only once. Random port being bound once or twice on a host.

### Tcpdump
  A command line packet sniffer that can directly capture and interpret data frames from a file or network interface. 
Built for use on any Unix-like OS.   Ports to Windows (WinDump) have ceased to be supported. 

List available interfaces: <br>
  `sudo tcpdump -D`<br>
Choosing an interface to capture from:<br>
  `sudo tcpdump -i eth0`<br>
Display Ethernet Header:<br>
  `sudo tcpdump -i eth0 -e`<br>
Include ASCII and Hex Output:<br>
  `sudo tcpdump -i eth0 -X`<br><br>
  
Craft a custom tcpdump:<br>
  `sudo tcpdump -i eth0 -nnvXX`<br><br>
![image](https://github.com/user-attachments/assets/5a4c56d7-b5ea-473c-bb15-25c491c5fdf7)
<br><br><br>
The following are other examples of filters:<br>
`sudo tcpdump -i eth0 portrange 0-1024`<br>
`sudo tcpdump -i eth0 less 64` <br>
`sudo tcpdump -i eth0 host 192.168.0.1 and port 23` <br>

### WireShark
Below is a screenshot of Wireshark:
<br>
![image](https://github.com/user-attachments/assets/869828bb-1b86-43b0-b3b7-5348c1e6ff8d)
<br>
1.  Packet List: <br>
  The top section is the packet list, shows a summary line of each packet that invludes default fields.<br>
2.  Packet Details: <br>
  The packet details, on the bottom left of the window, allows deep packet inspection of protocols with deeper details. <br>
  The packet is broken down into chunks that follow the typical OSI Model reference.<br>
  Wireshark will show the encapsulation in reverse order with lower layer at the top of the window and higher levels at the bottom.<br>
3.  Packet Bytes:<br>
  Bottom right of the winodw shows the packet contents in ASCII or hex.  Selecting a field from other windows will highlight in the packet Bytes window.<br>
   Each line in the output contains the data offset, sixteen hexadecimal bytes, and sixteen ASCII bytes. Non-printable bytes are replaced with a period in the ASCII format.
 
