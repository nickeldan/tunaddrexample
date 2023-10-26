FROM ubuntu:22.04

RUN apt -y update && \
    apt -y install build-essential iptables tcpdump

COPY ./emit.c start.sh /app/

WORKDIR /app

RUN gcc emit.c -o emit

ENTRYPOINT ["./start.sh"]
