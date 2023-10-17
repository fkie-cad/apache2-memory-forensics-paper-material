#!/usr/bin/bash

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -days 1 -subj /CN=localhost
  #-subj "/C=DE/ST=NRW/L=Berlin/O=My Inc/OU=DevOps/CN=www.example.com/emailAddress=dev@www.example.com"