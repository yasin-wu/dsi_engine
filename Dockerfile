FROM centos:7
RUN  yum -y install tree pkgconfig gcc-c++ make cmake && \
     mkdir -p /home/gopath /usr/local/include/hs /usr/local/lib64/pkgconfig
COPY libhs.pc /usr/local/lib64/pkgconfig/	 
COPY ragel-6.9.tar.gz boost_1_60_0.tar.gz hyperscan.tar.gz /usr/local/include/
COPY go.tar.gz /home/
RUN  cd /usr/local/include/ && \
     for tar in *.tar.gz; do tar -zxvf $tar; done && \
     cd ragel-6.9/ && ./configure && make && make install && \
     ln -s /usr/local/include/boost_1_60_0/boost /usr/local/include/hyperscan/include/boost && \
     cd /usr/local/include/hs/ && cmake ../hyperscan && cmake -build . && make install
RUN  cd /home/ && \
     tar zxvf go.tar.gz -C /usr/local/ && \
     echo "export GOPATH=/home/gopath" >> /etc/profile && \
     echo "export PATH=$PATH:/usr/local/go/bin/" >> /etc/profile && \
     echo "export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig" >> /etc/profile
RUN  cd /usr/local/include/ && rm -rf *.tar.gz  hyperscan/ boost_1_60_0/ ragel-6.9/ &&\
     cd /home/ && rm -rf *.tar.gz && \
     yum clean all -y