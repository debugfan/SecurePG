#!/bin/sh

input=$1
pubkey=$2

if [ "$input" = "" ]; then
    echo "No input file"
    exit 1
fi;

if [ "$pubkey" = "" ]; then
    echo "No public key file"
    exit 1
fi;

output=$input.spg

pre_key=`openssl rand -hex 32`

read -p "Input comment: " comment

IFS=' ' read -ra ADDR <<< `echo -n $comment | openssl dgst -sha256 -hex -hmac $pre_key`
for i in "${ADDR[@]}"; do
    if [ ${#i} -eq 64 ]; then
        dek=$i
    fi
done

enc_key=`echo -n $pre_key | openssl rsautl -encrypt -pubin -inkey $pubkey | openssl base64 -e -A`

echo "Key: $enc_key" > $output
echo "Comment: $comment" >> $output
echo "" >> $output

openssl enc -aes256 -K $dek -iv 00 -in $input -a >> $output
