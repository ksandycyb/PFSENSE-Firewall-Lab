# pfSense Firewall Lab: Attack Simulation & Defense

A hands-on lab environment demonstrating the capabilities of pfSense as a perimeter firewall. This project simulates real-world network attack scenarios from a Kali Linux machine and implements defensive firewall policies on pfSense to protect a target Ubuntu server.

## Table of Contents
- [Project Overview](#project-overview)
- [Network Topology](#network-topology)
- [Lab Components](#lab-components)
- [Setup and Configuration](#setup-and-configuration)
- [Attack Scenarios & Defense Rules](#attack-scenarios--defense-rules)
- [Results and Verification](#results-and-verification)
- [Conclusion & Key Learnings](#conclusion--key-learnings)

<br>
<br>

## Project Overview

The primary objective of this project is to build a segmented virtual network to practice and demonstrate fundamental network security principles. By placing an Ubuntu server behind a pfSense firewall, we can safely simulate attacks from a Kali Linux machine on the "internet" (WAN side) and observe the effectiveness of firewall rules in real-time.

This lab covers:
* Installation and configuration of pfSense.
* Creation of separate WAN and LAN network segments[cite: 28].
* Simulation of common network attacks using tools like Nmap and hping3.
* Implementation of firewall policies on both WAN and LAN interfaces to mitigate threats.
* Analysis of firewall logs to verify rule effectiveness.

<br>
<br>

## Network Topology

The lab is designed with a clear separation between the external (untrusted) network and the internal (trusted) network, with the pfSense firewall acting as the gateway.
```

      +-------------------------+
      |      Your Router        | (e.g., 192.168.1.1/24)
      +-----------+-------------+
                  |
     (Bridged Adapter / WAN Network)
                  |----------------------------------|
                  |                                  |
 +-----------------+---------------+     +--------------------------+
 |      Kali Linux (Attacker)      |     |  pfSense Firewall (WAN)  |
 |      (DHCP from Router)         |     |  (DHCP from Router)      |
 +---------------------------------+     +-----------+--------------+
                                                     |
                                           (Internal Network / LAN)
                                            (e.g., 191.168.1.0/24)
                                                     |
                                       +-------------+--------------+
                                       |  pfSense Firewall (LAN)    |
                                       |   (Gateway: 192.198.1.1)   |
                                       +-------------+--------------+
                                                     |
                                       +-------------+------------- +
                                       |   Ubuntu Server (Target)   |
                                       | (Static IP: 192.168.1.100) |
                                       +----------------------------+

```

<br>
<br>

## Lab Components

### Software & Tools
* **Virtualization Software:** VMware Workstation / VirtualBox
* **Firewall:** pfSense CE (Community Edition)
* **Attacker Machine:** Kali Linux
* **Target Machine:** Ubuntu Server/Desktop
* **Attack Tools:** Nmap, Metasploit, Hydra, hping3

### Virtual Machine Configuration
> **Note:** You can add a table here detailing the vCPU, RAM, and Network Adapter settings for each VM.

| VM      |  Operating System  |        Network Adapter 1            | Network Adapter 2           | Purpose           |
|---------|--------------------|-------------------------------------|-----------------------------|-------------------|
| **VM1** |  **Kali Linux**    | Bridged (Connected to physical NIC) |               -             |     Attacker      |
| **VM2** |  **pfSense CE**    | Bridged (Connected to physical NIC) | Internal Network (`intnet`) | Firewall / Router |
| **VM3** | **Ubuntu Desktop** |     Internal Network (`intnet`)     |               -             | Target / Victim   |

<br>
<br>

## Setup and Configuration

### 1. pfSense Firewall Setup
The pfSense VM was configured to manage both the external and internal networks:
* **WAN (External Network)**: The WAN interface was set to be a DHCP client. This allows it to automatically receive an IP address (e.g., `192.168.116.9`) from the main network router, simulating how a firewall would connect to an ISP.
* **LAN (Internal Network)**: The LAN interface was configured with a static IP address of `192.168.1.1` to serve as a consistent gateway for the internal network. A DHCP server was enabled on this interface to provide IP addresses to devices on the protected LAN.

### 2. Ubuntu Desktop Setup (LAN)
* Configured the network interface to use a static IP address: `192.168.1.101`.
* Set the Gateway to `192.168.1.1` (The pfSense LAN IP).

### 3. Kali Linux Setup (WAN)
* The Bridged network adapter automatically received an IP address (e.g., `192.168.116.x`) from the home router's DHCP server.

<br>

### Initial Configuration & Security

The pfSense WAN interface employs a **"default-deny"** policy, blocking all inbound traffic. The following steps were required to establish and secure administrative access.

#### Gaining and Securing WebGUI Access

1.  **Gaining Temporary Access:** Access to the WebGUI was initially blocked. The packet filter was temporarily disabled via the console (Option 8 - Shell):

    ```sh
    pfctl -d
    ```
2.  **Securing Access:** Logged into the WebGUI (e.g., `https://192.168.116.9`) using default credentials (`admin` / `pfsense`). The default password was immediately changed.
3.  **Creating Permanent Administrative Rules:** To restore security and maintain access, two rules were added to the `Firewall > Rules > WAN` tab:
    * **Pass TCP:** Allows WebGUI access from the local WAN subnet (`192.168.116.0/24`) to the pfSense WAN IP.
    * **Pass ICMP:** Allows `ping` traffic for diagnostics.
4.  **Re-enabling Firewall:** After saving and applying the rules, the packet filter was re-enabled from the console:
    ```sh
    pfctl -e
    ```

<br>

### Establishing Cross-Network Routing

Since the WAN devices did not know the path to the `192.168.1.0/24` LAN, static routes were manually added to direct traffic for the LAN subnet through the pfSense WAN IP (`192.168.116.9`). This was done on the Kali Linux attacker machine and the Windows Host PC.

<br>

### Initial Connectivity Verification

Connectivity was verified across all segments, confirming the static routes and permissive firewall rules were functional. A `ping` from the WAN-side Kali machine to the LAN-side Ubuntu host (`192.168.1.101`) was successful.

<br>
<br>

## Attack Scenarios & Defense Rules

This section details the simulated attacks and the corresponding firewall rules implemented to block them.

### Scenario 1: External Port Scanning
* **Objective:** Prevent an attacker from discovering open ports on our WAN interface.
* **Attack Simulation:** An Nmap scan was run against the pfSense WAN IP address.
* **Defense Rule (Default):** No new rule is needed. By default, pfSense is a stateful firewall and blocks all unsolicited inbound traffic on the WAN interface.

<br>

### Scenario 2: Blocking a Specific Malicious IP
* **Objective:** Block all traffic from a known malicious IP address trying to access a web server hosted behind the firewall.
* **Setup:** A Port Forwarding (NAT) rule was created to forward traffic from WAN port `80` to the Ubuntu server's IP `192.168.1.100` on port `80`.
* **Attack Simulation:** A `curl http://[pfsense_wan_ip]` command from the Kali machine was initially successful.
* **Defense Rule:** A `Block` rule was created on the `WAN` interface targeting the Kali IP as the `Source`.
* **Verification:** The `curl` command timed out, and firewall logs showed the traffic being dropped.

<br>

![Block Rule Screenshot](path/to/your/block-rule-screenshot.png)

### Scenario 3: LAN Egress Filtering
* **Objective:** Prevent internal machines (if compromised) from communicating with known malicious external command-and-control (C2) servers.
* **Attack Simulation:** From the Ubuntu machine, a `ping` to a fictitious C2 server IP (`45.33.32.156`) was successful by default.
* **Defense Rule:** A `Block` rule was created on the `LAN` interface targeting the malicious IP as the `Destination`.
* **Verification:** The `ping` command from Ubuntu failed.

<br>

### Scenario 4: Implementing GeoIP Blocking
> **Note:** This section is a placeholder for the future implementation of installing and configuring GeoIP blocking. 

<br>

### Scenario 5: Blocking a Targeted DoS Attack (SYN Flood)
* **Objective:** Mitigate an application-layer Denial of Service (DoS) attack originating from a specific attacker IP.
* **Attack Simulation:** The Kali attacker used `hping3` to flood the target Ubuntu host with SYN packets.
* **Defense Rule:** A specific `Reject` rule was created on the `WAN` interface to actively deny all traffic from the malicious source IP.
    * **Action:** `Reject`
    * **Interface:** `WAN`
    * **Protocol:** `IPv4 *`
    * **Source:** `192.168.116.102` (Kali Attacker's IP)
    * **Destination:** `LAN subnets`
* **Verification:** Re-running a Wireshark capture on the Ubuntu host showed a clean network trace, confirming the `Reject` rule successfully stopped the SYN flood.

<br>
<br>

## Results and Verification

The lab successfully demonstrated the core functionality of a stateful firewall. By implementing specific rules on both the WAN and LAN interfaces, I was able to:
* Effectively block external scans and targeted attacks from a specific IP.
* Control outbound (egress) traffic from the internal network.
* Successfully mitigate a targeted SYN Flood attack using a `Reject` rule.
* Utilize firewall logs to confirm that malicious traffic was being dropped/rejected as intended.

![Firewall Log Screenshot](path/to/your/firewall-log-screenshot.png)


<br>
<br>

## Conclusion & Key Learnings

This project was a valuable exercise in practical network security, reinforcing the importance of a defense-in-depth strategy where the firewall serves as the first line of defense.

Key takeaways include:
* Understanding the default-deny policy of pfSense on the WAN.
* The importance of rule order in firewall policies.
* The necessity of static routing in multi-segment lab environments.
* The ability to control traffic flow in both directions (ingress and egress).

Future improvements could include setting up a DMZ, configuring an Intrusion Prevention System (IPS) like Snort or Suricata, and implementing a VPN.

