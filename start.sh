#/usr/bash!
cd libnftnl
./autogen.sh
./configure
make
sudo make install

cd ../iptables
./configure
make
sudo make install

