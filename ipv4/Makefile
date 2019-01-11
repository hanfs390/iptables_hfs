hfs_iptables:main.o hfs_iptables.o
	gcc main.o hfs_iptables.o -o hfs_iptables -l ip4tc
main.o:main.c hfs_iptables.h
	gcc -c main.c -o main.o
hfs_iptables.o:hfs_iptables.c hfs_iptables.h
	gcc -c hfs_iptables.c -o hfs_iptables.o -l ip4tc
clean:
	rm *.o hfs_iptables
