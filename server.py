from flask import Flask, jsonify, request, render_template
import multiprocessing
from captrue_pcapng_process import capture_packets
from predict_attack_dns import predict
import subprocess, os
from flask_socketio import SocketIO
app = Flask(__name__)
socketio = SocketIO(app)
# Biến toàn cục để điều khiển việc bắt gói tin

capture_process = None
def wlan_ip():
    result=subprocess.run('ipconfig',stdout=subprocess.PIPE,text=True).stdout.lower()
    scan=0
    for i in result.split('\n'):
        if 'wireless lan adapter wi-fi' in i: #use "wireless" or wireless adapters and "ethernet" for wired connections
            scan=1
        if scan:
            if 'ipv4' in i:
                return i.split(':')[1].strip()
ipMyDns = wlan_ip()  
def scanIpClient():
    pass
ipTargets = ['192.168.10.1','192.168.10.40']          
@app.route('/')
def index():
    return render_template('index.html',ipDNS = ipMyDns, ipTargets = ipTargets)


#-----------------------START CAPTURE PCAPNG--------------------
@app.route('/start_capture', methods=['POST'])                                                                                                                                                                                                                                                                                  
def start_capture():
    global capture_process

    if capture_process and capture_process.is_alive():
        return jsonify({"status": "Capture is already running!"}), 400

    selected_ips = request.form.getlist('ip_list[]')

    # Tạo tiến trình mới để bắt gói tin
    capture_process = multiprocessing.Process(target=capture_packets, args=(selected_ips, ipMyDns))
    capture_process.start()

    return jsonify({"status": "Capture & detection started successfully!"}), 200


#--------------------------STOP CAPTURE PCAPNG-----------------------
@app.route('/stop_capture', methods=['GET'])
def stop_capture():
    global capture_process

    if capture_process and capture_process.is_alive():
        capture_process.terminate()
        capture_process.join()
        return jsonify({"status": "Capture stopped!"}), 200
    else:
        return jsonify({"status": "No capture process is running!"}), 400
    
#-------------------------------ANALYZE PCAPNG FILE --------------------
@app.route('/analyze', methods=['POST'])                                                                                                                                                                                                                                                                                  
def analyze():
    data = request.json
    targets = data.get('targets')
    ipdns = data.get('ipdns')
    filepath = data.get('file_path')
    # detection_thread = threading.Thread(target=predict, args=(filepath, ipdns,targets))
    # detection_thread.start()
    result = ''
    predicted = predict(filepath, ipdns,targets)
    for ip in predicted:
        if predicted[ip]:
            for acc in predicted[ip]:
                result += str(ip) + '---- Đã tấn công DNS Cache ('+ str(acc) +'%)\n'

    if result:
        socketio.emit('update', {'result': result})
    else:
        socketio.emit('update', {'result': 'Không có tấn công DNS Cache\n'})
    # AI_detection(file_path,target)
    return '', 204

@app.route('/analyze-file', methods=['POST'])
def analyzeFile():
    # Lấy dữ liệu từ form
    target = request.form.get('target')
    ipdns = request.form.get('ipdns')
    
    # Xử lý file tải lên
    file = request.files.get('pcap_file')
    result = 'Không phát hiện tấn công DNS cache poisoning\n'
    if file:
      # Lưu file tải lên vào thư mục tạm thời
        upload_folder = 'uploads/'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
      
      # Lưu file vào thư mục uploads
        filepath = os.path.join(upload_folder, file.filename)
        file.save(filepath)
        predicted = predict(filepath, ipdns,[target])
        if predicted[target]:
            result = ''
            for acc in predicted[target]:
                result += str(target) + '---- Đã tấn công dns cache ('+ str(acc) +'%)\n'
        return jsonify({"predicted": result}), 200
    else:
        return jsonify({"error": "Không có file tải lên"}), 400
        
    
if __name__ == '__main__':
    app.run(debug=True)
