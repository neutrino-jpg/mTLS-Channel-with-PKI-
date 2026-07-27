import struct

#шлем json 
def send_json(ssl_sock, json_str):
    data = json_str.encode('utf-8')
    length_prefix = struct.pack('!I', len(data))
    ssl_sock.sendall(length_prefix + data) 

#получаем json / none усли закрыто соединение
def recv_json(ssl_sock):
    rawlen = ssl_sock.recv(4) #ччитаем 4 байта
    if not rawlen:
        return None
    length = struct.unpack('!I', rawlen)[0]
    
    data=b''
    while len(data) < length:
        chunk = ssl_sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return data.decode('utf-8')
