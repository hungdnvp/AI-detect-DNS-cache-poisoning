from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    # Tạo gói ARP request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Gửi gói và nhận phản hồi
    result = srp(packet, timeout=2, verbose=False)[0]

    # Lưu danh sách các IP
    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

if __name__ == "__main__":
    ip_range = "192.168.0.1/24"  # Thay đổi dải IP phù hợp với mạng của bạn
    devices = scan_network(ip_range)
    print("Các thiết bị trong mạng:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}")

