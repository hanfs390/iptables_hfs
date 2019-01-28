hfs_iptables:main.o ip6tables_hfs.o iptables_hfs.o
	gcc main.o hfs_iptables.o -o hfs_iptables -l ip4tc -l ip6tc#must be install libiptc 
main.o:main.c ip6tables_hfs.h iptables_hfs.h
	gcc -c main.c -o main.o
iptables_hfs.o:iptables_hfs.c iptables_hfs.h
	gcc -c iptables_hfs.c -o iptables_hfs.o -l ip4tc
ip6tables_hfs.o:ip6tables_hfs.c ip6tables_hfs.h
	gcc -c ip6tables_hfs.c -o ip6tables_hfs.o -l ip4tc
clean:
	rm *.o hfs_iptables
