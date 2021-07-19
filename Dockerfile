FROM centos:7
RUN  yum -y install wget tree gcc-c++ flex bison cmake python2 libpcap clang make zlib pkgconfig vim libpcap-devel && \
     mkdir -p /home/gopath && \
     mkdir -p /usr/local/include/hs && \
     mkdir -p /usr/local/lib64/pkgconfig
COPY libhs.pc /usr/local/lib64/pkgconfig/	 
COPY ragel-6.9.tar.gz boost_1_60_0.tar.gz hyperscan.tar.gz /usr/local/include/
RUN  cd /usr/local/include/ && \
     tar -zxvf ragel-6.9.tar.gz && \
     tar -zxvf boost_1_60_0.tar.gz && \
     tar -zxvf hyperscan.tar.gz && \
     cd ragel-6.9/ && ./configure && make && make install && \
     ln -s /usr/local/include/boost_1_60_0/boost /usr/local/include/hyperscan/include/boost && \
     cd /usr/local/include/hs/ && cmake ../hyperscan && cmake -build . && make install
RUN  cd /home/ && \
     wget https://dl.google.com/go/go1.14.4.linux-amd64.tar.gz && \
     tar zxvf go1.14.4.linux-amd64.tar.gz -C /usr/local/ && \
     echo "export PATH=$PATH:/usr/local/go/bin/" >> /etc/profile && \
     echo "export GOPATH=/home/gopath" >> /etc/profile && \
     echo "export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig" >> /etc/profile
RUN  source /etc/profile
