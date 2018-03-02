#!/bin/sh

input=$1
seckey=$2

if [ "$input" = "" ]; then
    echo "No input file"
    exit 1
fi;

if [ "$seckey" = "" ]; then
    echo "No secret key file"
    exit 1
fi;

data=""
while IFS='' read -r line || [[ -n "$line" ]]; do
    if  [[ $line == Key* ]] ; then
        enc_key=${line:5}
    elif [[ $line == Comment* ]] ; then
        comment=${line:9}
    else
        data+=$line
    fi
done < "$input"

pre_key=`echo $enc_key | openssl base64 -d -A | openssl rsautl -decrypt -inkey $seckey`

IFS=' ' read -ra ADDR <<< `echo -n $comment | openssl dgst -sha256 -hex -hmac $pre_key`
for i in "${ADDR[@]}"; do
    if [ ${#i} -eq 64 ]; then
        dek=$i
    fi
done

echo $data | openssl enc -d -aes256 -K $dek -iv 00 -a -A
