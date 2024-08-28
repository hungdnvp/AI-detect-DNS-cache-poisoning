from iteration_utilities import deepflatten
import numpy as np
import tensorflow as tf
from tensorflow_addons.metrics import F1Score
import asyncio   
from pyshark import FileCapture
import os
def int2bin(num,padding=False,pad_to=8):    # chuyển int -> bin 8 bit, có đệm bit 0 vào trc hoặc không
    lst=[]
    while num>1:
        lst.insert(0,num%2)
        num=num//2
    lst.insert(0,num)
    if padding:
        while len(lst)<pad_to:
            lst.insert(0,0)
    return lst


def prep(xList, window_size, window_step):
    #chia mỗi session thành các đoạn nhỏ cùng kích thước windowsize
    X = []
    for i in range(len(xList)):
        line = xList[i]
        n = len(line)
        # segment
        for j in range(0, n-window_size+1, window_step):
            if j+window_size <= len(line):
                X.append(line[j:j+window_size])
            else:
                X.append(line[n-window_size:n])
    return np.array(X)


def worker(data,window_size):
    bin_data=[]
    N_data=len(data)
    for i in range(N_data):
        x=data[i]
        tmp=list(deepflatten(x))     # làm phẳng phần tử
        tmp=[int2bin(ele,padding=True) for ele in tmp]  # [ [0,1,0,1,..],[1,0,0,1,..],....]
        bin_data.append(tmp)
    bin_data=np.array(bin_data,dtype=int)
    bin_data=bin_data.reshape((bin_data.shape[0],window_size,32,8))  # xong data 3 chiều giông ảnh có kích thước w_s x 32 với số kênh = 8
    # print(" set shape: "+str(bin_data.shape))
    
    return bin_data

def analyse_pacpng_to_bytesList(target,capture_raw, capture):
    data_bytes=list()
    j=-1
    query = None
    query_before = None
    try:
        while True: 
            pkt=capture_raw.next()
            pkt2 = capture.next()
            package_query = pkt2.dns.qry_name
            if package_query != query:
                if pkt.ip.src_host == target:
                    query_before = query    #save query before
                    query = package_query
                    data_bytes.append([])
                    j+=1
                    data_bytes[j].append(np.array(list(int(ele) for ele in pkt.get_raw_packet()[14:26]+pkt.get_raw_packet()[34:54])))
                elif package_query == query_before:
                    data_bytes[j-1].append(np.array(list(int(ele) for ele in pkt.get_raw_packet()[14:26]+pkt.get_raw_packet()[34:54])))
            else:
                data_bytes[j].append(np.array(list(int(ele) for ele in pkt.get_raw_packet()[14:26]+pkt.get_raw_packet()[34:54])))
    except StopIteration:
        pass
    return data_bytes

def predict(file_path, ipdns, targets):
    """
    Hàm gọi main_prediction
    """
    asyncio.set_event_loop(asyncio.new_event_loop())
    # loop = asyncio.get_event_loop()
    filter_analys = 'dns and not tcp and not icmp and ip.addr == '+ ipdns
    print(f"Đang xử lý file: {file_path}")
    capture_raw= FileCapture(file_path,display_filter=filter_analys,use_json=True,include_raw=True)
    capture=  FileCapture(file_path,display_filter=filter_analys)
    dict_result = {}
    for target in targets:
        data_bytes = analyse_pacpng_to_bytesList(target,capture_raw,capture)
        result = 0
        if len(data_bytes) >0:
            result = AIprediction(data_bytes)
        dict_result[target] = result
    capture_raw.close()
    capture.close()
    #---------- xoa file------
    # print('file --- path',file_path)
    # os.remove(file_path)
    return dict_result
    

# --------------------------------sub prediction ----------
def AIprediction(data_bytes):
    window_size = 6
    window_step= 1
    attack_session_number = []
    X_tmp=prep(data_bytes,window_size,window_step)
    tmp = []
    for ele in X_tmp:
        tmp.append(tuple(ele.reshape((window_size*32,)).tolist()))
    X_tmp = np.array(list(set(tmp)),dtype=np.uint8).reshape((len(tmp),window_size,32))
    X = X_tmp.reshape(X_tmp.shape[0], X_tmp.shape[1],X_tmp.shape[2], 1)
    X_predict = worker(X,window_size)
    model=tf.keras.models.load_model("model/classifier-CNN.h5",custom_objects={"metric":F1Score(num_classes=2)})
    predictions = model.predict(X_predict)
    for i in predictions:
        if(i[1]>0.5):
          attack_session_number.append(round(i[1],2)*100)
    return attack_session_number

if __name__ == "__main__":
    print('a')
