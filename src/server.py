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
from cryptography.hazmat.backends import default_backend
from crypto_utils import isrevoke, sign_message, verify_message
from network_utils import recv_json, send_json

#функция создания и настройки контекста для сервра
def create_context(cert, key, cafile_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=cert, keyfile=key)#загружаем серверный серт и ключик
    ctx.load_verify_locations(cafile=cafile_path)#загружаем сертификат СА чтобы верить только выданным им сертификатам
    ctx.verify_mode = ssl.CERT_REQUIRED#требуем в обяз сертификат
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx

#обертка
def incoming_msg_decor(incoming_msg, autor, time, flag):
    print(autor, '|' ,time)
    if not flag:
        print(Fore.RED + "[!] Не удалось подтвердить подпись сообщения")
    else: print(Fore.GREEN + "[*] Подпись сообщения подтверждена")
    print("--------------------------------------------")
    print(incoming_msg+'\n')
    
#color print ЗАСТАВКА
def printblue(str):
    print(Fore.CYAN + str)

#парсер аргументов
parser = argparse.ArgumentParser(description="Ловим пакеты клиента и проверяем его сертификат. Все фигачим в лог")

parser.add_argument("--host", type=str, default="0.0.0.0", help="IP-адрес, на котором сервер принимает соединения")
parser.add_argument("--port", type=int, default=8443, help="Порт, который слушает сервер")
parser.add_argument("--cert", type=str, default="pki/server/server.crt", help="Путь к файлу сертификата сервера")
parser.add_argument("--key", type=str, default="pki/server/server.key", help="Путь к приватному ключу сервера")
parser.add_argument("--cafile", type=str, default="pki/ca/ca.crt", help="Путь к файлу CA")
parser.add_argument("--log", type= str, default="audit.log", help="Путь к файлу для аудита")
parser.add_argument("--crl", type=str, default="pki/crl/crl.pem", help="Путь к файлу CRL")
parser.add_argument("-v", "--version", help="Версия Сервер//альфа 1.0")
args = parser.parse_args()

#логгер
logger = logging.getLogger("server")
logger.setLevel(logging.INFO)
fh = logging.FileHandler('audit.log')
logger.addHandler(fh)

#мутим контекст
ctx = create_context(args.cert, args.key, args.cafile)

#мутим сокет
serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serv_sock.bind((args.host, args.port))
serv_sock.listen(5)

#сервак запустился
logger.info(json.dumps({
	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
	"event_type": "server_started",
	"host": args.host,
	"port": args.port,
	"details": "mTLS server started"
}, ensure_ascii=False))

#=================================
#           ПРОГРАММА
#=================================

init(autoreset=True)
os.system('clear')

print("========================================================")
printblue(" _______  _______  ______    __   __  _______  ______   ")
printblue("|       ||       ||    _ |  |  | |  ||       ||    _ |  ")
printblue("|  _____||    ___||   | ||  |  |_|  ||    ___||   | ||  ")
printblue("| |_____ |   |___ |   |_||_ |       ||   |___ |   |_||_ ")
printblue("|_____  ||    ___||    __  ||       ||    ___||    __  |")
printblue(" _____| ||   |___ |   |  | | |     | |   |___ |   |  | |")
printblue("|_______||_______||___|  |_|  |___|  |_______||___|  |_|\n")
print("========================================================\n")
print("Открываем соединение на порту: ", args.port)
print("Начинаем слушать...\n")
print(Fore.RED + "                               !ВНИМАНИЕ!")
print(Fore.RED + "       В случае появления сообщения о неподтверждении подлинности ")
print(Fore.RED + "подписи соединение с клиентом автоматически прервется в целях безопасности\n")

try:
    while True:
        client_sock, client_addr = serv_sock.accept() #ловим соединение. получаем сокет клиента и адрес клиента
        try:
            ssl_sock = ctx.wrap_socket(client_sock, server_side=True) #пытаемся обернуть сокет в SSL
        
            peer_der = ssl_sock.getpeercert(binary_form=True)#получаем бинарник сертификата
            cert = x509.load_der_x509_certificate(peer_der)
            #извлекаем поля
            c = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COUNTRY_NAME)[0].value
            st = cert.subject.get_attributes_for_oid(x509.oid.NameOID.STATE_OR_PROVINCE_NAME)[0].value
            l = cert.subject.get_attributes_for_oid(x509.oid.NameOID.LOCALITY_NAME)[0].value
            o = cert.subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)[0].value
            cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
            serial_hex = format(cert.serial_number, 'X') #получаем серийник как hex строку

            subject_str = cert.subject.rfc4514_string()      
            logger.info(json.dumps({                    #успешное рукопожатие
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event_type": "tls_handshake_success",
	        "client_ip": client_addr[0],
	        "client_port": client_addr[1],
	        "cert_subject": subject_str,
	        "cert_serial": serial_hex
            }, ensure_ascii=False))

            print("Соединение успешно установлено!") #вывод данных сертификата
            print("IP-адресс клиента: ", client_addr[0])
            print("Порт клиента:      ", client_addr[1])
            print("---------------------------------")
            print("   Данные сертификата клиента:")
            print("---------------------------------")
            print("C:  ", c)
            print("ST: ",st)
            print("L:  ", l)
            print("O:  ", o)
            print("CN: ", cn, "\n")
            print("Статус сертификата:", end=' ')
            
            if isrevoke(cert, args.crl, args.cafile): #проверяем, не отозван ли сертификат
                print(Fore.RED + "отозван\n")
                continue
            else: print(Fore.GREEN + "действующий\n")
            
            
#================================ ОБМЕН СООБЩЕНИЯМИ ==========================================
            server_seq = 0
            while True:
                json_str = recv_json(ssl_sock)
                print("")
                if not json_str:
                    print("Клиент отключился")
                    break #клиент отключился 
                try: 
                    verify_flag, incoming_payload, timestamp, message_seq = verify_message(json_str, peer_der)#проверяем подпись
                except Exception as e:
                    verify_flag, result = False, f"Ошибка верификации: {type(e).__name__}: {e}"
                    
                if verify_flag:
                    incoming_msg_decor(incoming_payload, cn, timestamp, verify_flag) #вывод сообщения на экран                                          
                    logger.info(json.dumps({	 #логгируем доставку сообщения
             	    	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               		"event_type": "message_received",
               		"client_ip": client_addr[0],
               		"client_port": client_addr[1],
               		"cert_subject": subject_str,
               		"direction": "in",
               		"sequence": message_seq,
               		"payload_preview": incoming_payload[:50]
       	            }, ensure_ascii=False))
                else: 
                    incoming_msg_decor(incoming_payload, cn, timestamp, verify_flag)
                    logger.info(json.dumps({	#логгируем некорректную подпись
             	    	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               		"event_type": "message_signature_invalid",
               		"client_ip": client_addr[0],
               		"client_port": client_addr[1],
               		"cert_subject": subject_str,
               		"reason": result
       	            }, ensure_ascii=False))
       	            break                

                #отправляем вторую звездочку (подтверждение доставки)
                server_seq +=1
                responce_payload = "** Сообщение получено"
                responce_json = sign_message(responce_payload, args.key, server_seq)
                send_json(ssl_sock, responce_json)
                
                logger.info(json.dumps({	
             	    	"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               		"event_type": "message_acknowlegement_sent", #логгируем отсылку подтверждения доставки
               		"client_ip": client_addr[0],
               		"client_port": client_addr[1],
               		"cert_subject": subject_str,
               		"direction": "out",
               		"sequence": message_seq,
               		"payload_preview": responce_payload[:50]
       	        }, ensure_ascii=False))
#============================================================================================    

          
            try:
                ssl_sock.shutdown(socket.SHUT_RDWR)
            except (OSError, ssl.SSLError):
                pass
            ssl_sock.close()#закрываем ssl сокет
    
        except ssl.SSLError as e:
            logger.info(json.dumps({  #ошибка рукопожатия
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event_type": "tls_handshake_failed",
                "client_ip": client_addr[0],
        	"client_port": client_addr[1],
        	"reason": str(e)
            }, ensure_ascii=False))
    	
            print("Ошибка! Что-то случилось...")
            print(str(e))
    	
            client_sock.close()
            continue
except KeyboardInterrupt:    #стоп без вывода трейсбэка
    print("\nОстановка сервера по запросу пользователя")
finally:
    serv_sock.close()
    logger.info(json.dumps({            #логгируем остановку
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": "server_stopped",
        "details": "Server shut down gracefuly"
    }, ensure_ascii=False))
    for handler in logger.handlers:
        handler.close()
        logger.removeHandler(handler) 	
