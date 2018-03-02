#!/bin/sh

name=$1

if [ "$name" = "" ]; then 
    name="test" 
fi;

echo "Generate RSA key......"
openssl genrsa -aes256 -out $name.key 2048

echo "Output RSA public key......"
openssl rsa -in $name.key -pubout -out $name.pub
