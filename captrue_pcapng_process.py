import pyshark
import os
import time
import requests

def capture_packets(targets, ipMyDns):
    """
    Hàm này sẽ liên tục bắt gói tin và lưu vào các file pcapng trong thư mục chỉ định.
    """
    interface = '\\Device\\NPF_{4E81E876-F471-4253-86AB-D1D5E64A0EB5}'
    capture_duration = 45
    # if not os.path.exists('captures'):
    # # Nếu chưa tồn tại, tạo thư mục mới
    #     os.makedirs('captures')
    while True:
        timestamp = int(time.time())
        output_file = os.path.join('captures', f"capture_{timestamp}.pcapng")
        # output_file_done = os.path.join(output_folder, f"capture_{timestamp}_done.pcapng")

        capture = pyshark.LiveCapture(interface=interface, output_file=output_file)

        print(f"Bắt đầu bắt gói tin trên giao diện {interface} trong {capture_duration} giây...")
        capture.sniff(timeout=capture_duration)

        requests.post("http://localhost:5000/analyze",
                  json={"file_path": output_file, "ipdns": ipMyDns, "targets": targets})