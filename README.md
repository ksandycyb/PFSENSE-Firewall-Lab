# pfSense Firewall Lab: Attack Simulation & Defense

![Project Banner](/Banner.png) A hands-on lab environment demonstrating the capabilities of pfSense as a perimeter firewall. This project simulates real-world network attack scenarios from a Kali Linux machine and implements defensive firewall policies on pfSense to protect a target Ubuntu server.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Network Topology](#network-topology)
- [Lab Components](#lab-components)
  - [Software & Tools](#software--tools)
  - [Virtual Machine Configuration](#virtual-machine-configuration)
- [Setup and Configuration](#setup-and-configuration)
  - [1. pfSense Firewall Setup](#1-pfsense-firewall-setup)
  - [2. Ubuntu Server Setup (LAN)](#2-ubuntu-server-setup-lan)
  - [3. Kali Linux Setup (WAN)](#3-kali-linux-setup-wan)
- [Attack Scenarios & Defense Rules](#attack-scenarios--defense-rules)
  - [Scenario 1: External Port Scanning](#scenario-1-external-port-scanning)
  - [Scenario 2: Blocking Unwanted Services (e.g., SSH Brute-Force)](#scenario-2-blocking-unwanted-services-eg-ssh-brute-force)
  - [Scenario 3: Implementing GeoIP Blocking](#scenario-3-implementing-geoip-blocking)
  - [Scenario 4: LAN Egress Filtering](#scenario-4-lan-egress-filtering)
- [Results and Verification](#results-and-verification)
- [Conclusion & Key Learnings](#conclusion--key-learnings)
- [Author](#author)
- [License](#license)

---

## Project Overview

The primary objective of this project is to build a segmented virtual network to practice and demonstrate fundamental network security principles. By placing an Ubuntu server behind a pfSense firewall, we can safely simulate attacks from a Kali Linux machine on the "internet" (WAN side) and observe the effectiveness of firewall rules in real-time.

This lab covers:
-   Installation and configuration of pfSense.
-   Creation of separate WAN and LAN network segments.
-   Simulation of common network attacks using tools like Nmap.
-   Implementation of firewall policies on both WAN and LAN interfaces to mitigate threats.
-   Analysis of firewall logs to verify rule effectiveness.

## Network Topology

The lab is designed with a clear separation between the external (untrusted) network and the internal (trusted) network, with the pfSense firewall acting as the gateway.

```
      +-------------------------+
      |      Your Router        | (e.g., 192.168.1.1/24)
      +-----------+-------------+
                  |
     (Bridged Adapter / WAN Network)
                  |---------------------------------
                  |                                |
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
*You can create a more visual diagram using a tool like [draw.io](https://app.diagrams.net/) and embed the image here.*

---

## Lab Components

### Software & Tools
* **Virtualization Software:** [e.g., VMware Workstation, VirtualBox]
* **Firewall:** pfSense CE (Community Edition)
* **Attacker Machine:** Kali Linux
* **Target Machine:** Ubuntu Server
* **Attack Tools:** Nmap, Metasploit, Hydra (or other tools you used)

### Virtual Machine Configuration

| VM Name   | Operating System | Network Adapter 1                 | Network Adapter 2          | Purpose           |
|-----------|------------------|-----------------------------------|----------------------------|-------------------|
| **Kali** | Kali Linux       | Bridged (Connected to physical NIC) | -                          | Attacker          |
| **pfSense**| pfSense CE       | Bridged (Connected to physical NIC) | Internal Network (`LAN-NET`) | Firewall / Router |
| **Ubuntu** | Ubuntu Server    | Internal Network (`LAN-NET`)        | -                          | Target / Victim   |

---

## Setup and Configuration

### 1. pfSense Firewall Setup
-   Installed pfSense from the ISO image.
-   During setup, assigned the **Bridged adapter as the WAN interface** (e.g., `em0`).
-   Assigned the **Internal Network adapter as the LAN interface** (e.g., `em1`).
-   Configured the LAN interface with a static IP address: `10.10.10.1` with a subnet mask of `/24`.
-   Enabled the DHCP server on the LAN interface to serve addresses from `10.10.10.100` to `10.10.10.200`.

### 2. Ubuntu Server Setup (LAN)
-   Installed Ubuntu Server.
-   Configured the network interface to use a static IP address:
    -   **IP Address:** `10.10.10.100`
    -   **Subnet Mask:** `255.255.255.0`
    -   **Gateway:** `10.10.10.1` (The pfSense LAN IP)
    -   **DNS Server:** `10.10.10.1` (or a public DNS like `8.8.8.8`)
-   Verified connectivity by pinging the gateway (`ping 10.10.10.1`) and an external address (`ping google.com`).

### 3. Kali Linux Setup (WAN)
-   Installed Kali Linux.
-   The Bridged network adapter automatically received an IP address from my home router's DHCP server, placing it on the same network segment as the pfSense WAN interface.

---

## Attack Scenarios & Defense Rules

This section details the simulated attacks and the corresponding firewall rules implemented to block them.

### Scenario 1: External Port Scanning
**Objective:** Prevent an attacker from discovering open ports on our WAN interface.

* **Attack Simulation:**
    From the Kali Linux machine, I ran an Nmap scan against the pfSense WAN IP address.
    ```bash
    sudo nmap -sV -p- [pfsense_wan_ip]
    ```

* **Default Behavior:**
    By default, pfSense blocks all unsolicited inbound traffic on the WAN interface. The Nmap scan should show all ports as `filtered` or `closed`.

* **Defense Rule (Default):**
    No rule is needed as this is the default state-full firewall behavior.

### Scenario 2: Blocking a Specific Malicious IP
**Objective:** Block all traffic from a known malicious IP address trying to access a web server hosted behind the firewall.

* **Setup:**
    1.  Create a Port Forwarding rule (NAT) to forward traffic from WAN port `80` to the Ubuntu server's IP `10.10.10.100` on port `80`.
    2.  This NAT rule automatically creates an associated firewall rule on the WAN interface allowing this traffic.

* **Attack Simulation:**
    From Kali, I attempted to access the web server.
    ```bash
    curl http://[pfsense_wan_ip]
    ```
    This connection was successful.

* **Defense Rule:**
    On the **WAN interface rules**, I created a **Block** rule at the top of the list:
    -   **Action:** `Block`
    -   **Interface:** `WAN`
    -   **Protocol:** `Any`
    -   **Source:** `Single host or alias` -> `[Kali_Linux_IP]`
    -   **Destination:** `Any`
    -   **Description:** `Block known malicious actor`

* **Verification:**
    I re-ran the `curl` command from Kali, which now timed out. The pfSense firewall logs showed the traffic being dropped by my new rule.

![Block Rule Screenshot](https://i.imgur.com/your-screenshot-url.png)

---
### Scenario 3: LAN Egress Filtering
**Objective:** Prevent internal machines (if compromised) from communicating with known malicious external command-and-control (C2) servers.

* **Attack Simulation:**
    From the Ubuntu machine, I tried to ping a fictitious C2 server IP address `[e.g., 45.33.32.156]`.
    ```bash
    ping 45.33.32.156
    ```
    The ping was successful by default.

* **Defense Rule:**
    On the **LAN interface rules**, I created a **Block** rule:
    -   **Action:** `Block`
    -   **Interface:** `LAN`
    -   **Protocol:** `Any`
    -   **Source:** `Any`
    -   **Destination:** `Single host or alias` -> `45.33.32.156`
    -   **Description:** `Block outbound C2 traffic`

* **Verification:**
    I re-ran the `ping` command from Ubuntu, which now failed.

---

## Results and Verification
The lab successfully demonstrated the core functionality of a stateful firewall. By implementing specific rules on both the WAN and LAN interfaces, I was able to:
-   Effectively block external scans and targeted attacks from a specific IP.
-   Control outbound traffic from the internal network.
-   Utilize firewall logs to confirm that malicious traffic was being dropped as intended.

![Firewall Log Screenshot](https://i.imgur.com/your-logs-screenshot.png)

## Conclusion & Key Learnings
This project was a valuable exercise in practical network security. It reinforced the importance of a defense-in-depth strategy, where the firewall serves as the first line of defense. Key takeaways include understanding the default-deny policy of pfSense on the WAN, the importance of rule order, and the ability to control traffic flow in both directions (ingress and egress).

Future improvements could include setting up a DMZ, configuring an Intrusion Prevention System (IPS) like Snort or Suricata, and implementing a VPN.

## Author
* **[Your Name]** - [Your LinkedIn/GitHub/Portfolio URL]

## License
This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.
