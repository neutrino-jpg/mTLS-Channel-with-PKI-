#crypto_utils.py
import datetime
import json
import base64
import traceback
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, utils as asym_utils
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec as ec_types
from cryptography.exceptions import InvalidSignature

#функция проверки сертификата в CRL
def isrevoke(cli_crt_b, crl_path, ca_path):
    with open(crl_path, 'rb') as f:#load crl
        crl_data = f.read()
    crl = x509.load_pem_x509_crl(crl_data, default_backend())
    with open(ca_path, 'rb') as f:#load ca
        ca_crt = x509.load_pem_x509_certificate(f.read())
    
    if not crl.is_signature_valid(ca_crt.public_key()):#proverka podpisi i time
            raise ValueError("Подпись CRL недействительна")
    from datetime import datetime
    now = datetime.now() #!!naive time
    if crl.next_update < now:
        raise ValueError("Срок действия CRL истек")    
   
    revoked = crl.get_revoked_certificate_by_serial_number(cli_crt_b.serial_number)
    return revoked is not None

#извлекает приватный ключ
def load_privkey(keypath, password=None):
    with open(keypath, "rb") as f:
        key_data = f.read()
    return serialization.load_pem_private_key(
        key_data,
        password=password,
        backend=default_backend()
    )
    
#извлекает публичный ключ из der представления сертфикиата
def load_pubkey_from_cert(cert_der_bytes):
    cert = x509.load_der_x509_certificate(cert_der_bytes, default_backend())
    return cert.public_key()
    
#подпись сообщения приватным ключом
def sign_message(payload, private_keypath, sequence):
    privkey = load_privkey(private_keypath)
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    message_to_sign = f"{payload}{timestamp}{sequence}".encode("utf-8")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message_to_sign)
    hash_bytes = digest.finalize()
    
    if isinstance(privkey, rsa.RSAPrivateKey):
        signature = privkey.sign(
            hash_bytes, padding.PSS(
                mgf = padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            asym_utils.Prehashed(hashes.SHA256())   
        )
    elif isinstance(privkey, ec_types.EllipticCurvePrivateKey):
        signature = privkey.sign(hash_bytes, ecECDSA(hashes.SHA256()))
    else:
        raise TypeError("Неподдерживаемый тип ключа")
        
    signature_b64=base64.b64encode(signature).decode("ascii")
    message = {				#сообщкние
        "payload": payload,
        "timestamp": timestamp,
        "sequence": sequence,
        "signature": signature_b64
    }
    
    return json.dumps(message)

#верификация
def verify_message(json_str, cert_der_bytes):
    try:#пытаемся грузануть json
        message = json.loads(json_str)
    except json.JSONDecodeError as e:
        return False, f"Сломаный JSON: {e}"
        
    required_fields = ["payload", "timestamp", "sequence", "signature"]
    for field in required_fields:
        if field not in message:
            return False, f"Поле пропущено: {field}"
    
    payload = message["payload"]
    timestamp = message["timestamp"]
    sequence = message["sequence"]
    signature_b64 = message["signature"]
    
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exceptions as e:
        return False, f"Сбой при декодировании из base64: {e}"
    
    public_key = load_pubkey_from_cert(cert_der_bytes)
    message_to_verify = f"{payload}{timestamp}{sequence}".encode("utf-8")
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message_to_verify)
    hash_bytes = digest.finalize()
    
    try: #проверяем тип ключа
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature_bytes,
                hash_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                asym_utils.Prehashed(hashes.SHA256())
            )
        elif isinstance(public_key, ec_types.EllipticCurvePublicKey):
            public_key.verify(
                signature_bytes,
                hash_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            return False, "Неподдерживаемый тип ключа"
        return True, payload, timestamp, sequence

    except InvalidSignature:
        return False, "Не удалось подтвердить подпись"
    except Exception as e:
        return False, traceback.format_exc()
        
        
        
