from scapy.all import ARP, Ether, srp
import time, subprocess
def scan_network(ip_range):
    # Tạo gói ARP request
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Gửi gói và nhận phản hồi
    result = srp(packet, timeout=3, verbose=False)[0]

    # Lưu danh sách các IP
    devices = []
    for sent, received in result:
        #devices.append({'ip': received.psrc})
        devices.append(received.psrc)

    return devices

def get_ip_local():
    result=subprocess.run('ipconfig',stdout=subprocess.PIPE,text=True).stdout.lower()
    scan=0
    for i in result.split('\n'):
        if 'localdomain' in i: #use "wireless" or wireless adapters and "ethernet" for wired connections
            scan=1
        if scan:
            if 'ipv4' in i:
                return i.split(':')[1].strip()
            
if __name__ == "__main__":
    ip_range = "192.168.148.0/24"  # Thay đổi dải IP phù hợp với mạng của bạn
    devices = scan_network(ip_range)
    print(devices)
    #print("Các thiết bị trong mạng:")
    #for device in devices:
        #print(f"IP: {device['ip']}")

