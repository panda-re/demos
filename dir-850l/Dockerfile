FROM pandare/panda:latest
ENV DEBIAN_FRONTEND=noninteractive
ENV PROMPT_COMMAND=""

RUN apt-get update && apt-get install -y \
    bridge-utils \
    netcat-openbsd \
    qemu-utils \
    python3 \
    ipython3 \
    gnupg2 \
    telnet \
    vim \
    less \
    iproute2 \
    socat \
    iputils-ping

RUN python3 -m pip install \
    capstone \
    setuptools \
    telnetlib3 \
    pyelftools \
    psutil && \
    git clone -q https://github.com/panda-re/pypanda-plugins.git /panda/pyplugins && \
    cd /panda/pyplugins && python3 setup.py develop --no-deps

# Install Metasploit
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /root/msfinstall &&\
    chmod 755 /root/msfinstall && \ 
    cd /root && ./msfinstall

WORKDIR /demo

#Batteries not included: you need to supply the run.py and image.qcow for the
#rehosting
COPY . /demo
