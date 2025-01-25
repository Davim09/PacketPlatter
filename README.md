# PacketPlatter
PacketPlatter is an exploit for network systems, focusing on restaurant ordering platforms. These often use insecure HTTP over Wi-Fi, making them prone to ARP spoofing. PacketPlatter intercepts device traffic via ARP Spoofing, exposing unencrypted data like login credentials and cookies for analysis.

[Exploit of this Article](https://medium.com/@davimouar/from-order-to-exploit-a-deep-dive-into-restaurant-network-security-64aeaf3a6f64)

## Requirements

- Python 3.x
- Scapy

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Davim09/PacketPlatter.git
    cd PacketPlatter
    ```

2. Install the dependencies:
    ```bash
    pip install scapy
    ```
    Enable IP Forwarding in root, although the exploit itself already does this, it is what ensures that traffic continues
flowing:
    ```bash
    echo 1 > /proc/sys/net/ipv4/ip_forward
    ```

## Usage

1. Run the script as root:
    ```bash
    sudo python3 packetplatter.py
    ```

2. Follow the instructions in the terminal to enter the network interface, target IPs and MACs, and the output pcap file name.

## Example Execution
<img src="/example1.png" width="5800"/>

<img src="/example2.png" width="5800"/>
