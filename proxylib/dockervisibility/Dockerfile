FROM linuxkit/kernel:4.9.125 as ksrc-4.9.125

FROM linuxkit/kernel:4.15 as ksrc-4.15.0

FROM ubuntu:18.04

RUN apt-get update && apt-get install -y bpfcc-tools dirmngr python-pip lsb-release linux-headers-4.15.0-43-generic curl

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
RUN echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/iovisor.list
RUN apt-get update && apt-get install -y bcc-tools libbcc-examples && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN pip install docker
RUN pip install requests-unixsocket

COPY --from=ksrc-4.9.125 /kernel-dev.tar /kernel-4.9.125-dev.tar
RUN tar xf kernel-4.9.125-dev.tar
RUN mkdir /lib/modules/4.9.125-linuxkit
RUN ln -s /usr/src/linux-headers-4.9.125-linuxkit/ /lib/modules/4.9.125-linuxkit/build

COPY --from=ksrc-4.15.0 /kernel-dev.tar /kernel-4.15.0-dev.tar
RUN tar xf kernel-4.15.0-dev.tar
RUN mkdir /lib/modules/4.15.0
RUN ln -s /usr/src/linux-headers-4.15.0-linuxkit/ /lib/modules/4.15.0/build

COPY dockerVisibilityDaemon.py /root/dockerVisibilityDaemon.py

CMD ["/usr/bin/python", "/root/dockerVisibilityDaemon.py"]
