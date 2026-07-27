#!/bin/bash

set -e 

#директории
PKI_ROOT="./pki"
CA_DIR="${PKI_ROOT}/ca"
SERVER_DIR="${PKI_ROOT}/server"
CLIENT_DIR="${PKI_ROOT}/client"
CRL_DIR="${PKI_ROOT}/crl"

#сколько действует
CA_DAYS=3650 #центра сертификации
CERT_DAYS=365 #выданных сертификатов
CRL_DAYS=30 #черный список

KEY_SIZE=4096

#субъекты
DN="/C=RU/ST=Ryazan_Oblast/L=Ryazan/O=RSREU/OU=None"
DN_CA="${DN}/CN=MyCA"
DN_SERVER="${DN}/CN=server.local"
DN_ALICE="${DN}/CN=alice"
DN_MALLORY="${DN}/CN=mallory"

ENCRYPT_KEYS=0

mkdir -p "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}" "${CRL_DIR}"
chmod 700 "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}" "${CRL_DIR}"

#генерация ключей
openssl genrsa -out "${CA_DIR}/ca.key" ${KEY_SIZE}
chmod 600 "${CA_DIR}/ca.key"
openssl req -new -x509 -key "${CA_DIR}/ca.key" -subj "${DN_CA}" -days ${CA_DAYS} -sha512 -out "${CA_DIR}/ca.crt"

#======================== СЕРВАК ========================
openssl genrsa -out "${SERVER_DIR}/server.key" ${KEY_SIZE}
chmod 600 "${SERVER_DIR}/server.key"
openssl req -new -key "${SERVER_DIR}/server.key" -subj "${DN_SERVER}" -out "${SERVER_DIR}/server.csr"

# Временный ext-файл для SAN
cat > "${SERVER_DIR}/san.ext" <<EOF
subjectAltName = IP:192.168.100.10, DNS:server.local
EOF

openssl x509 -req -in "${SERVER_DIR}/server.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -days ${CERT_DAYS} -sha512 \
    -set_serial 01 \
    -extfile "${SERVER_DIR}/san.ext" \
    -out "${SERVER_DIR}/server.crt"
rm "${SERVER_DIR}/server.csr" "${SERVER_DIR}/san.ext"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVER_DIR}/server.crt"

#======================== Алиса ========================
openssl genrsa -out "${CLIENT_DIR}/alice.key" ${KEY_SIZE}
chmod 600 "${CLIENT_DIR}/alice.key"
openssl req -new -key "${CLIENT_DIR}/alice.key" -subj "${DN_ALICE}" -out "${CLIENT_DIR}/alice.csr"

cat > "${CLIENT_DIR}/client.ext" <<EOF
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "${CLIENT_DIR}/alice.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -days ${CERT_DAYS} -sha512 \
    -set_serial 02 \
    -extfile "${CLIENT_DIR}/client.ext" \
    -out "${CLIENT_DIR}/alice.crt"
rm "${CLIENT_DIR}/alice.csr"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${CLIENT_DIR}/alice.crt"

#======================== Мэллори ========================
openssl genrsa -out "${CLIENT_DIR}/mallory.key" ${KEY_SIZE}
chmod 600 "${CLIENT_DIR}/mallory.key"
openssl req -new -key "${CLIENT_DIR}/mallory.key" -subj "${DN_MALLORY}" -out "${CLIENT_DIR}/mallory.csr"

openssl x509 -req -in "${CLIENT_DIR}/mallory.csr" \
    -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
    -days ${CERT_DAYS} -sha512 \
    -set_serial 03 \
    -extfile "${CLIENT_DIR}/client.ext" \
    -out "${CLIENT_DIR}/mallory.crt"
rm "${CLIENT_DIR}/mallory.csr" "${CLIENT_DIR}/client.ext"
openssl verify -CAfile "${CA_DIR}/ca.crt" "${CLIENT_DIR}/mallory.crt"


#======================== ОСТАЛЬНОЕ ========================
#мутим crl
touch "${CA_DIR}/index.txt"
echo "03" > "${CA_DIR}/serial"     # последний выданный серийный номер
echo "01" > "${CA_DIR}/crlnumber"

# Функция для добавления записи в index.txt
add_to_index() {
    local cert="$1"
    local serial="$2"
    local dn="$3"
    local enddate
    enddate=$(openssl x509 -in "${cert}" -noout -enddate | cut -d= -f2)
    local end_utc
    end_utc=$(date -d "${enddate}" +%y%m%d%H%M%SZ)
    echo -e "V\t${end_utc}\t\t${serial}\tunknown\t${dn}" >> "${CA_DIR}/index.txt"
}

add_to_index "${SERVER_DIR}/server.crt" "01" "${DN_SERVER}"
add_to_index "${CLIENT_DIR}/alice.crt" "02" "${DN_ALICE}"
add_to_index "${CLIENT_DIR}/mallory.crt" "03" "${DN_MALLORY}"

# конфиг
cat > "${CA_DIR}/openssl.cnf" <<EOF
[ ca ]
default_ca = my_ca

[ my_ca ]
dir            = ${CA_DIR}
database       = \$dir/index.txt
serial         = \$dir/serial
certificate    = \$dir/ca.crt
private_key    = \$dir/ca.key
crl_dir        = \$dir
crlnumber      = \$dir/crlnumber
crl_extensions = crl_ext

[ crl_ext ]
authorityKeyIdentifier = keyid:always
EOF

#добавляем сертификат мэллори в журнал СА
MALLORY_SERIAL=$(openssl x509 -in "${CLIENT_DIR}/mallory.crt" -noout -serial | cut -d= -f2) #достаем серийник
MALLORY_ENDDATE=$(openssl x509 -in "${CLIENT_DIR}/mallory.crt" -noout -enddate | cut -d= -f2) #достаем дату
MALLORY_END_UTC=$(date -d "${MALLORY_ENDDATE}" +%y%m%d%H%M%SZ) #perevod v nuzhniy format vremyani
echo "V	${MALLORY_END_UTC}	${MALLORY_SERIAL}	unknown ${DN}/CN=mallory" >> "${CA_DIR}/index.txt"

echo "Готово! База СА обновлена, все сертификаты выпущены!"

