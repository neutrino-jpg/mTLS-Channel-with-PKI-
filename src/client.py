import ssl
import socket
import logging
import json
import argparse
import sys
import datetime
import os
import struct
from colorama import init, Fore
from cryptography import x509
from crypto_utils import sign_message, verify_message
from network_utils import send_json, recv_json

#создание контекста сокета
def create_context(cert, key, cafile_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile=cert, keyfile=key)
    ctx.load_verify_locations(cafile=cafile_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

def msg_send_decor(payload, time):
    print("\nВЫ |", time)
    print("----------------------------")
    print(f"Текст сообщения: {payload}\n")
    print("*  Сообщение отправлено") #первая звездочка
 
#цветастый вывод
def printblue(str):
    print(Fore.CYAN + str)
    
parser = argparse.ArgumentParser(description="Отправляем пакеты и свой сертификат серваку. Все фигачим в лог")
parser.add_argument("--host", type=str, default="192.168.100.10", help="IP сервака")
parser.add_argument("--port", type=int, default="8443", help="Порт сервака")
parser.add_argument("--cert", type=str, default="pki/client/alice.crt", help="Сертификат клиента")
parser.add_argument("--key", type=str, default="pki/client/alice.key", help="Ключ клиента")
parser.add_argument("--cafile", type=str, default="pki/ca/ca.crt", help="Сертификат СА")
parser.add_argument("--log", type=str, default="audit_cli.log", help="Путь к файлу лога")
parser.add_argument("-v", "--version", help="Версия КЛИЕНТ//альфа 1.0")
args = parser.parse_args()

#логгер
logger = logging.getLogger("client")
logger.setLevel(logging.INFO)
fh = logging.FileHandler('audit_cli.log')
logger.addHandler(fh)

#контектс
ctx = create_context(args.cert, args.key, args.cafile)

#========================
#	ПРОГРАММА
#========================

init(autoreset=True)
os.system('clear')

print("====================================================")
printblue(" _______  ___      ___   _______  __    _  _______ ")
printblue("|       ||   |    |   | |       ||  |  | ||       |")
printblue("|       ||   |    |   | |    ___||   |_| ||_     _|")
printblue("|       ||   |    |   | |   |___ |       |  |   |  ")
printblue("|      _||   |___ |   | |    ___||  _    |  |   |  ")
printblue("|     |_ |       ||   | |   |___ | | |   |  |   |  ")
printblue("|_______||_______||___| |_______||_|  |__|  |___|  \n")
print("====================================================\n")
print("Стучимся к серверу...\n")

#пытаемся соединиться 
try:
    #сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.host, args.port))
    
    logger.info(json.dumps({     #успешное создание сокета
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "tcp_connection_established",
        "server_ip": args.host,
        "server_port": args.port,
    }, ensure_ascii=False))
    
    print("Соединение установлено!")

except OSError as e:
    logger.info(json.dumps({ #не удалось создать сокет
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "connection_failed",
        "server": f"{args.host}:{args.port}",
        "reason": str(e)
    }, ensure_ascii=False))
    
    print("Ошибка соединения! Сервер недоступен")
    print("Завершение...")
    sys.exit(1)

#оборачиваем сокет    
try:
    ssl_sock = ctx.wrap_socket(sock, server_hostname=args.host)#проверяем и предъявляемсертификаты 
        
    peer_der = ssl_sock.getpeercert(binary_form=True)#бинарник серверного сертификата
    cert = x509.load_der_x509_certificate(peer_der)
    #извлекаем поля
    c = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
    st = cert.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
    l = cert.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
    o = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    serial_hex = format(cert.serial_number, 'X')
    subj_str = cert.subject.rfc4514_string()
       
    logger.info(json.dumps({ #успешное соединение
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "tls_handshake_success",
        "server_ip": args.host,
        "server_port": args.port,
        "cert_server": subj_str,
        "cert_serial": serial_hex,
    }, ensure_ascii=False))
       
    print(f"Получилось! Мы соединились с сервером по адресу {args.host} и порту {args.port}\n")    
    print("----------------------------------")
    print("   Данные сертификата сервера")
    print("----------------------------------")
    print("C:   ", c)
    print("ST:  ", st)
    print("L:   ", l)
    print("O:   ", o)
    print("CN:  ", cn, "\n")
    
#=================================== ОБМЕН СООБЩЕНИЯМИ =====================================
    client_seq = 0
    while True:
        client_seq +=1              
        payload = input("\nВведите сообщение (пустая строка - выход): ") #ввод текста сообщения
        if payload == "": 
            print("Прекращение сенаса связи по запросу пользователя (пустой ввод)")
            break
        msg_json = sign_message(payload, args.key, client_seq)#подпись
        send_json(ssl_sock, msg_json)#отправка             
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        msg_send_decor(payload, timestamp)#вывод на экран отправленного сообщения
        resp_json = recv_json(ssl_sock)#ловим подтверждение
        
        logger.info(json.dumps({        #сообщение успешно отправлено (*)
        	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        	"event_type": "message_sent",
       	        "server_ip": args.host,
       	        "server_port": args.port,
       	        "cert_server": subj_str,
       	        "direction": "out",
       	        "sequence": client_seq,
       	        "payload_prewiew": payload [:50]
    	    }, ensure_ascii=False)) 
        
        if not resp_json:
            logger.info(json.dumps({    #подтверждение (**) не дошло
        	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        	"event_type": "message_acknowledgement_not_received",
       	        "server_ip": args.host,
       	        "server_port": args.port,
       	        "cert_server": subj_str,
       	        "reason": "server_not_responding"
    	    }, ensure_ascii=False)) 
            break
        verify_flag, inc_payload, timestamp, message_seq = verify_message(resp_json, peer_der)#проверяем подпись сервера на ответе
        if not verify_flag:  #некорректная попдись
            logger.info(json.dumps({
        	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        	"event_type": "message_signature_invalid",
       	        "server_ip": args.host,
       	        "server_port": args.port,
       	        "cert_server": subj_str,
       	        "reason": result
    	    }, ensure_ascii=False)) 
            print(Fore.RED + "[!] Не удалось подтвердить подпись сервера\n")
            break
        else: #подпись подтверждена
            print(inc_payload)
            print(Fore.GREEN + "[*] Подпись сервера подтверждена\n")
            logger.info(json.dumps({
        	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        	"event_type": "message_signature_verified",
       	        "server_ip": args.host,
       	        "server_port": args.port,
       	        "cert_server": subj_str,
       	        "direction": "in",
       	        "sequence": message_seq,
       	        "payload_prewiew": inc_payload [:50]
    	    }, ensure_ascii=False)) 
    	    
#=========================================================================================================
    
except ssl.SSLError as e:
    
    logger.info(json.dumps({ #ошибка установки соединения
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "tls_handshake_failed",
        "server_ip": args.host,
        "server_port": args.port,
        "reason": str(e)
    }, ensure_ascii=False))
             
    print("Ошибка! Что-то случилось...")
    print(str(e))
    



