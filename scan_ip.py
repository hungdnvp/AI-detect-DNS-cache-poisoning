from scapy.all import ARP, Ether, srp
import subprocess
def scan_ipLocal():
    # Lay ip cua may hien tai
    myIp = get_myIpLocal()
    # Tạo gói ARP request
    ip_range = '192.168.17.0/24'
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
    if myIp in devices:
        devices.remove(myIp)
    return myIp, devices

def get_myIpLocal():
    result=subprocess.run('ipconfig',stdout=subprocess.PIPE,text=True).stdout.lower()
    scan=0
    for i in result.split('\n'):
        if 'localdomain' in i: #use "wireless" or wireless adapters and "ethernet" for wired connections
            scan=1
        if scan:
            if 'ipv4' in i:
                return i.split(':')[1].strip()
            
if __name__ == "__main__":
    
    myIp, devices = scan_ipLocal()
    print(devices)
    #print("Các thiết bị trong mạng:")
    #for device in devices:
        #print(f"IP: {device['ip']}")

