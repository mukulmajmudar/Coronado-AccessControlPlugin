FROM centos:7

RUN echo "timeout=5" >> /etc/yum.conf && \
    yum update -y && \
    yum install -y epel-release

RUN yum install -y \
    gcc \
    make \
    openssl \
    openssl-devel \
    zlib-devel && \
        curl -O https://www.python.org/ftp/python/3.5.0/Python-3.5.0.tar.xz && \
        tar xf Python-3.5.0.tar.xz && \
        cd Python-3.5.0 && \
        ./configure && \
        make && \
        make install

# Install Coronado dependencies first so they can be cached
RUN pip3 install \
    argcomplete \
    argh \
    argparse \
    python-dateutil \
    tornado>=4.3

RUN pip3 install pylint>=1.5.0

# Install plugin dependencies
RUN pip3 install PyMySQL

# Install Coronado
COPY ./Coronado-2.0-py3.5.egg /root/Coronado-2.0-py3.5.egg
RUN easy_install-3.5 /root/Coronado-2.0-py3.5.egg
COPY ./MySQLPlugin-1.0-py3.5.egg /root/eggs/MySQLPlugin-1.0-py3.5.egg
RUN easy_install-3.5 /root/eggs/MySQLPlugin-1.0-py3.5.egg

WORKDIR /root/AccessControlPlugin
ENTRYPOINT ["./entrypoint.sh"]
COPY . /root/AccessControlPlugin