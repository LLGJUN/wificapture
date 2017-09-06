wificap:packetcap.o radiotap.o ConfigMgr.o
	gcc packetcap.o radiotap.o ConfigMgr.o -o wificap -lpthread
packetcap.o:packetcap.c my_parse_radio.h
	gcc -c packetcap.c
ConfigMgr.o:ConfigMgr.c ConfigMgr.h
	gcc -c ConfigMgr.c 
radiotap.o:radiotap.h radiotap.c radiotap_iter.h
	gcc -c radiotap.c