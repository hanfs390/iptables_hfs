#/usr/bash!
cd libnftnl
./autogen.sh
./configure
make
sudo make install

cd ../iptables-1.4.21
./configure
make
sudo make install

sudo iptables -nvL
