FROM ubuntu:latest

RUN apt update && \
    apt install -y gdb tcpdump software-properties-common libssl-dev build-essential && \
    add-apt-repository ppa:deadsnakes/ppa && \
    DEBIAN_FRONTEND=noninteractive apt install -y python3.9
