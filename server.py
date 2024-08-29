from flask import Flask, jsonify, request, render_template
import multiprocessing, threading
from captrue_pcapng_process import capture_packets
from predict_attack_dns import predict
import subprocess, os
from flask_socketio import SocketIO
from scan_ip import scan_ipLocal

app = Flask(__name__)
socketio = SocketIO(app)
# Biến toàn cục để điều khiển việc bắt gói tin

capture_process = None

ipMyDns, ipTargets = scan_ipLocal()        
@app.route('/')
def index():
    ipMyDns, ipTargets = scan_ipLocal()
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
    result = 'Kết quả phân tích từ cập nhật mới nhất ' + filepath + '\n'
    predicted = predict(filepath, ipdns,targets)
    nonAttack = 1
    for ip in predicted:
        if predicted[ip]:
            nonAttack = 0
            for acc in predicted[ip]:
                result += 'Phát hiện tấn công DNS Cache Poisoning ->session client'+ str(ip) + '('+ str(acc) +'%)\n'

    if nonAttack :
        result += 'Không có tấn công DNS Cache Poisoning\n'
    socketio.emit('update', {'result': result})
    # AI_detection(file_path,target)
    return '', 204

@app.route('/analyze-file', methods=['POST'])
def analyzeFile():
    # Lấy dữ liệu từ form
    target = request.form.get('target')
    ipdns = request.form.get('ipdns')
    
    # Xử lý file tải lên
    file = request.files.get('pcap_file')
    if file:
      # Lưu file tải lên vào thư mục tạm thời
        upload_folder = 'uploads/'
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)
      
      # Lưu file vào thư mục uploads
        filepath = os.path.join(upload_folder, file.filename)
        file.save(filepath)
        detection_thread = threading.Thread(target=sub_predictFile, args=(filepath, ipdns,target))
        detection_thread.start()
    return '', 204
def sub_predictFile(file_path, ipdns, target):
    result = 'Không phát hiện tấn công DNS cache poisoning\n'
    predicted = predict(file_path,ipdns,[target])
    if predicted[target]:
            result = ''
            for acc in predicted[target]:
                result += 'Phát hiện tấn công DNS Cache Poisoning - session of ip ' + str(target) +' ('+ str(acc) +'%)\n'
    socketio.emit('updateFile', {'result': result})
    return 1
if __name__ == '__main__':
    app.run(debug=True)
