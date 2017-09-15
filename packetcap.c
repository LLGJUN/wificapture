#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <linux/if.h>   //wirenetwork headfile
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <ctype.h>
#include <linux/wireless.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>

#include "my_parse_radio.h"
#include "ConfigMgr.h"

#define USER_CFG_FILE   "CAPTURE.COF"
#define USERINFO_HEADER "[ConfigInfo]"

#define BUFFER_SIZE 1024
#define TIMEHEADSIZE 8
#define GIGA 1e6         //1e6=10^6

int channel2_4G[13]={2412,2417,2422,2427,2432,2437,2442,2447,2452,2457,2462,2467,2472};
int channel5G[18]={5200,5210,5220,5230,5240,5250,5260,5270,5280,5290,5230,5231,5232,5500,5510,5520,5530,5540}; 
// wireshark filehead  d4c3 b2a1 0200 0400 0000 0000 0000 0000 0000 0400 7f00 0000
char capfilehead_buf[24] = {0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00,
							0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
							0x04, 0x00, 0x7f, 0x00, 0x00, 0x00};
typedef struct _captureInfo
{
	char ip[16];
	char port[8];
	char channel[8];
	char interface[8];

}CapInfo;

char *ifname="wlan1";          //interface name 
struct hostent *host;          //host name
char *chan_flag="auto";  	   //channel flag = auto or channel frequency index
char *port_num="3000";
char *filename="FILE";

struct wlan_frame{
	uint16_t fc;
	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq;
	uint8_t tag_num;      // new add 
	uint8_t tag_len;     // new add 
	uint8_t *ap_name;    // new add 
	union              // different from, struct it takes up memory of one of items
	{
		uint16_t qos;
		uint8_t addr4[6];
		struct
		{
			uint16_t qos;
			uint32_t ht;
		}__attribute__ ((packed)) ht;
		struct
		{
			uint8_t addr4[6];
			uint16_t qos;
			uint32_t ht;
		}__attribute__ ((packed)) addr4_qos_ht;
	}u;
}__attribute__ ((packed));
/*
void  intohexchar(uint8_t *ra) // turn int mac address to string mac address
{
	char hex_char[16]={'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
	char hexstring[10]={0};
	char char1;
	char char2;
	char char3=':';
	int i=0;
	for(i=0;i<6;i++)
	{
		char1=hex_char[*(ra+i)/16];
		char2=hex_char[*(ra+i)%16];
		//sprintf(hexstring," %c,%c  ",char1,char2);
		//if(i!=5)
			//hexstring=strncat(hexstring,&char3,1);
	}
	//return hexstring[10];
}*/
int parse_wifi_packet(char *buffer,int len)
{
	int radiotap_len;  //the length of raditaphead of the wifi packet 
	uint16_t fc=0;
	uint8_t* ra=NULL;
	uint8_t* ta=NULL;
	uint8_t* bssid=NULL;
	int i;
	char macaddress[18]={0};
	char *mymac="20:82:c0:1e:c2:3d";
	
	struct ieee80211_radiotap_header* radiotap_header=NULL;
	struct wlan_frame* wfram_head =NULL;
	if(buffer==NULL)
		return -1;
	radiotap_header =(struct ieee80211_radiotap_header*)buffer;
	radiotap_len=radiotap_header->it_len;  //default is 18 bytes
	/*
	char radiotap_buffer[radiotap_len];
	//radiotap_buffer = strncpy(radiotap_buffer,buffer,radiotap_len); //get radiotap bytes
	memcpy(radiotap_buffer,buffer,radiotap_len); //get radiotap bytes
	radiotap_buffer[radiotap_len]='\0';

	for(i=0;i<radiotap_len;i++)
	{
		printf("%02x ",radiotap_buffer[i]);
		if((i+1)%40==0 && i!=0)
		printf("\n");
	}
	printf("%s",radiotap_header);
	printf("the size of radio_buff is %d\n",sizeof(radiotap_header));
	*/

	parse_radiotap_message(radiotap_header,radiotap_len);
	
	wfram_head=(struct wlan_frame*)(buffer+radiotap_len);  // the first address of wlan frame head
	fc=le16toh(wfram_head->fc);  //fc :2 byte
	int wlan_type=(fc&0xfc);   // 2-7 bit   0xFC 11111100
	int type=(fc&0xc)>>2;        //0xC 1100
	int subtype=(fc&0xf0)>>4;  //0xF0 11110000
	if(type==0x02)
	{
		printf("data frame   \n");
		/*
		ra=wfram_head->addr1;
		ta=wfram_head->addr2;
		bssid=wfram_head->addr3;
		if(ta)
			printf("Src MAC:%02x:%02x:%02x:%02x:%02x:%02x     ",*ta,*(ta+1),*(ta+2),*(ta+3),*(ta+4),*(ta+5));
		if(ra)
		{
			printf("Dst MAC:%02x:%02x:%02x:%02x:%02x:%02x      ",*ra,*(ra+1),*(ra+2),*(ra+3),*(ra+4),*(ra+5));
		}
		if(bssid)
		{
			printf("BSSID MAC:%02x:%02x:%02x:%02x:%02x:%02x    ",*bssid,*(bssid+1),*(bssid+2),*(bssid+3),*(bssid+4),*(bssid+5));
		}
		printf("\n");
		*/
		return 1;
	}
	else if(type==0x01)
	{
		printf("control frame  \n");
		return 2;
	}
	else if(type==0x00)
	{
		printf("manage frame----");
		if(subtype==0x04)
		{
			ra=wfram_head->addr1;
			ta=wfram_head->addr2;
			bssid=wfram_head->addr3;
			printf("probe request frame   ");

			if(ta)
			{
				printf("Src MAC:%02x:%02x:%02x:%02x:%02x:%02x     ",*ta,*(ta+1),*(ta+2),*(ta+3),*(ta+4),*(ta+5));
				sprintf(macaddress,"%02x:%02x:%02x:%02x:%02x:%02x",*ta,*(ta+1),*(ta+2),*(ta+3),*(ta+4),*(ta+5));
				//intohexchar(ra);
				if(strcasecmp(macaddress,mymac)==0)
					return 3;
				else 
					return	-1;
			}
			/*
			if(ra)
			{
				printf("Dst MAC:%02x:%02x:%02x:%02x:%02x:%02x      ",*ra,*(ra+1),*(ra+2),*(ra+3),*(ra+4),*(ra+5));
			}
			if(bssid)
			{
				printf("BSSID MAC:%02x:%02x:%02x:%02x:%02x:%02x    ",*bssid,*(bssid+1),*(bssid+2),*(bssid+3),*(bssid+4),*(bssid+5));
			}

			if(wfram_head->tag_len>0)
			{				
				//printf("data is coming %d ===================",wfram_head->tag_len);
				char ap[100];
				memcpy(ap,&wfram_head->ap_name,wfram_head->tag_len);
				ap[wfram_head->tag_len]='\0';
				printf("%s",ap);
				//getchar();			
			}
			printf("\n");	
			*/	
			return 3;
		}
		else if(subtype==0x08)
		{
			printf("beacon frame   \n");
			/*
			ra=wfram_head->addr1;
			ta=wfram_head->addr2;
			bssid=wfram_head->addr3;
			//printf("probe request frame   ");
			if(ta)
				printf("Src MAC:%02x:%02x:%02x:%02x:%02x:%02x     ",*ta,*(ta+1),*(ta+2),*(ta+3),*(ta+4),*(ta+5));
			if(ra)
			{
				printf("Dst MAC:%02x:%02x:%02x:%02x:%02x:%02x      ",*ra,*(ra+1),*(ra+2),*(ra+3),*(ra+4),*(ra+5));
			}
			if(bssid)
			{
				printf("BSSID MAC:%02x:%02x:%02x:%02x:%02x:%02x    ",*bssid,*(bssid+1),*(bssid+2),*(bssid+3),*(bssid+4),*(bssid+5));
			}
			printf("\n");
			*/
			return 4;
		}	
	}
	else	
	{
		printf("unkonwn frame   \n");
		return -1;
	}
}

int init_send_socket()    //init data-send socket
{
	int sockfd;
	struct hostent *serverhost;
	struct sockaddr_in serv_addr;
	serverhost=host;
	if((sockfd=socket(AF_INET,SOCK_STREAM,0))==-1)
	{
		perror("socket");
		return 0;
	}
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(atoi(port_num));
	serv_addr.sin_addr=*((struct in_addr *)serverhost->h_addr);
	bzero(&(serv_addr.sin_zero),8);
	//add a connect timeout
	if(connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(struct sockaddr))==-1)
	{
		perror("connect!");
		return 0;
	}
	return sockfd;
}

int send_data_to_server(int sockfd, char *buffer,int len)
{
	if(send(sockfd,buffer,len,0)==-1)
	{
		perror("send!");
		return 0;
	}
	printf("data send successed!\n");
	return 1;
}

/*
int set_promisc_mode(const char* eth, int promisc)
{
	int org_errno = 0;
	int fd;
	struct ifreq ifreq;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
		return 0;
	memset(&ifreq, 0, sizeof(ifreq));
	strncpy(ifreq.ifr_name, eth, IF_NAMESIZE - 1);
	ioctl(fd, SIOCGIFFLAGS, &ifreq);   //SIOCGIFFLAGS means get the flag of interface
	// check if eth is up
	if (!(ifreq.ifr_flags & IFF_UP))
		{
			printf("%s is not up yet.\n", eth);
			return 0;
		}
	if(promisc)
		ifreq.ifr_flags |= IFF_PROMISC;
	else
		ifreq.ifr_flags &= ~IFF_PROMISC;
	ioctl(fd, SIOCSIFFLAGS, &ifreq);  //SIOCSIFFLAGS means set the flag of interface
	printf("Promisc mode works!\n");
	if (close(fd))
		return 0;
	return 1;
}
*/

// sudo ifconfig wlan1 up
int get_if_up()
{
	int fd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("Socket!");
		exit(1);
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,strlen(ifname));
	ifr.ifr_flags |=(IFF_UP | IFF_RUNNING);
	if(ioctl(fd,SIOCSIFFLAGS,&ifr)<0)
	{
		perror("SIOCSIFFLAGS!");
		exit(1);
		return -1;
	}
	//printf("......the interface is up!\n");
	return 0;
}

// sudo ifconfig wlan1 up
int get_if_down()
{
	int fd;
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("Socket!");
		exit(1);
		return -1;
	}
	strncpy(ifr.ifr_name,ifname,strlen(ifname));
	ifr.ifr_flags &=~IFF_UP;
	if(ioctl(fd,SIOCSIFFLAGS,&ifr)<0)
	{
		perror("SIOCSIFFLAGS");
		exit(1);
		return -1;
	}
	//printf("......the interface is down!\n");
	return 0;
}

void iw_float2iw_freq(double in,struct iw_freq* out)   
{
	out->e=0;
	while(in>1e9)
	{
		in /=10;
		(out->e)++;
	}
	out->m=(long)in;
}

int set_iface_channel(int skfd,struct iwreq wreq,int channel_freq)
{
	//struct iwreq wreq;
	double frequency;
	//memset(&wreq, 0, sizeof(struct iwreq));
	//strncpy(wreq.ifr_name,ifname,strlen(ifname));
	frequency = (double)channel_freq*GIGA;
	iw_float2iw_freq(frequency,&(wreq.u.freq));
	wreq.u.freq.flags=0;
	if(ioctl(skfd,SIOCSIWFREQ,&wreq)==-1)    
	{
		perror("SET FREQUENCY,ERROR");
		return -1;
	}
	else
	{
		printf("Channel set OK ! the current channel freq is %d\n",channel_freq);
	}
	return 0;
}

int set_if_channel(int channel_freq)
{
	int skfd = -1;
	if((skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))==-1)
	{
		perror("Socket ERROR!");
		return -1;
	}
	struct iwreq wreq;
	double frequency;
	memset(&wreq, 0, sizeof(struct iwreq));
	strncpy(wreq.ifr_name,ifname,strlen(ifname));
	frequency = (double)channel_freq*GIGA;
	iw_float2iw_freq(frequency,&(wreq.u.freq));
	wreq.u.freq.flags=0;
	if(ioctl(skfd,SIOCSIWFREQ,&wreq)==-1)    
	{
		perror("SET FREQUENCY,ERROR");
		exit(1);
		return -1;
	}
	else
	{
		printf("Channel set OK ! the current channel freq is %d\n",channel_freq);
	}
	return 0;
}

//Start monitor mode for packet capture
int set_monitor_mode()
{
	int fd;
	int i;
	struct iwreq wreq;
	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		perror("Socket!");
		return -1;
	}
	memset(&wreq, 0, sizeof(struct iwreq));
	strncpy(wreq.ifr_name,ifname,strlen(ifname));
	wreq.u.mode=IW_MODE_MONITOR;
	get_if_down();
	if(ioctl(fd,SIOCSIWMODE, &wreq)==-1)    //SIOCGIFFLAGS means get the mode of interface
	{
		perror("IOCTL SIOCSIWMODE FAIL,ERROR");
	}
	else
	{
		printf("Monitor mode set successfully!\n");
		/*
		if(ioctl(fd,SIOCGIWMODE,&wreq)==-1)    
		{
			perror("IOCTL SIOCSIWMODE FAIL,ERROR");
		}
		else
			printf("\tthe interface mode is %d\n",wreq.u.mode);
		*/
	}
	get_if_up();
	//set_if_channel(fd,wreq,channel2_4G[3]);
	if (close(fd))
		return -1;
	return 0;
}


//turn on monitor model，and create a socket
int init_raw_socket()
{
	int ret = 0;
	int fd = -1;
	//set_monitor_mode();
	if((fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))==-1)
	{
		perror("Raw Socket ERROR!");
		return -1;
	}
	struct ifreq req;
	strcpy(req.ifr_name,ifname);
	if((ioctl(fd, SIOCGIFINDEX, &req))==-1)
	{
		perror("SIOCGIFINDEX");
		return -1;
	}
	struct sockaddr_ll addr;
	addr.sll_family = PF_PACKET;
	addr.sll_ifindex = req.ifr_ifindex;
	addr.sll_protocol = htons(ETH_P_ALL);
	if((bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_ll)))==-1)
	{
		perror("Raw socket bind error:");
		return -1;
	}
	return fd;
}

int get_hwinfo(int fd, unsigned char* macaddr)
{
	struct ifreq ifr;
	int s;
	memset(&ifr, 0, sizeof(ifr));
	s=socket(AF_INET,SOCK_DGRAM,0);
	strcpy(ifr.ifr_name, ifname);
	//strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	//ifr.ifr_name[IFNAMSIZ - 1] = '\0';  // make sure the ifr_ifrname string end with '\0'
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
	{
		printf("Could not get arptype\n");
		return -1;
	} 
	printf("ARPTYPE %d\n", ifr.ifr_hwaddr.sa_family);
	memcpy(macaddr, ifr.ifr_hwaddr.sa_data, 6);
	printf("MAC ADDRESS:%02x:%02x:%02x:%02x:%02x:%02x\n",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
	return ifr.ifr_hwaddr.sa_family;   //return proctol content
}

struct cap_packet
{
	long int time_s;
	long int time_ms;
	long int log_packet_len;
	long int tran_packet_len;
	char buffer[BUFFER_SIZE];
};

void num_to_char(unsigned long num)
{
	int i;
	char *ptr;
	ptr=(char*)(&num);
	for(i=0;i<4;i++)
		printf("%02x ",ptr[i]);
}

struct cap_packet getcaptime(struct cap_packet packet)
{
	struct timeval t_time;
	gettimeofday(&t_time,NULL);
	packet.time_s=t_time.tv_sec;
	packet.time_ms=t_time.tv_usec;
	//printf("\nthe second value is %ld\n",t_time.tv_sec);
	//printf("the mrosecond value is %ld\n",t_time.tv_usec);
	//num_to_char(t_time.tv_sec);
	//num_to_char(t_time.tv_usec);
	return packet;
}

char *get_current_time()  
{
	static char timestr[40];
	time_t t;
	struct tm *nowtime;
	time(&t);
	nowtime = localtime(&t);
	strftime(timestr,sizeof(timestr),"%Y%m%d-%H:%M:%S",nowtime);
	return timestr;
}

void receive_packet(int capt_socket,int send_socket)
{
	int ret = 0;
	int count=0;
	int i;
	struct cap_packet packet;
	struct timeval tv;
	static fd_set read_fds;
	tv.tv_sec = 0;
	tv.tv_usec = 100;

	FILE *fd;
	// char *filetime=NULL;

	while(1)
	{
		FD_ZERO(&read_fds);
		FD_SET(capt_socket, &read_fds);
		ret = select(capt_socket+1, &read_fds, NULL, NULL, NULL);
		if(ret<=0)
			continue;
		if (FD_ISSET(capt_socket, &read_fds))
		{
			memset(packet.buffer, '\0', BUFFER_SIZE);
			ret = recv(capt_socket, packet.buffer, BUFFER_SIZE, MSG_DONTWAIT);
			if (ret <= 0)
				continue;
			
			if(count%100000==0)
			{
				filename=strcat(filename,get_current_time());
				filename=strcat(filename,".cap");
				fd=fopen(filename,"ab");
				fwrite(capfilehead_buf,24,1,fd);
				fclose(fd);
			}

			count++;
			printf("%d  ", count);
			packet=getcaptime(packet);
			packet.log_packet_len=ret;
			packet.tran_packet_len=ret;
				
			if(parse_wifi_packet(packet.buffer,ret)==3)  //probe request frame 
			{
				
				fd=fopen(filename,"ab");
				i=fwrite((char *)(&packet),ret+16,1,fd);
				fclose(fd);	
			/*	
				//data transmission error maybe server is down , create a new thread to detect the server status ,
				if(send_data_to_server(send_socket,(char *)(&packet),ret+16)==0)
				{
					if((send_socket=init_send_socket())==0)
						printf(".............Server reconnect failed!\n");
					else
						printf(".............Server reconnect successfully!\n");
				}	
				*/
			}							
		}
	}
}

void change_channel_thread()
{
	int i=0;
	//printf("thread: auto change channel\n");
	if(!strcasecmp(chan_flag,"auto"))
	{
		while(1)
		{
			set_if_channel(channel2_4G[i]);
			sleep(1);i++;
			if(i==13)
				i=0;
		}
	}
	else
	{
		//printf("-------------------------------------%d\n",atoi(chan_flag));
		set_if_channel(channel2_4G[atoi(chan_flag)-1]);
	}
}

void wifi_cap_thread()
{
	int capt_fd,send_fd=0;
	/*
	send_fd=init_send_socket();
	if(send_fd==0)
		printf("Server connect failed!\n");
	else
		printf("Server connect successfully!\n");
	*/
	if((capt_fd=init_raw_socket())==-1)
	{
		printf("init raw_socket failed\n");
		exit(1);
	}
	else
	{
		printf("Capture Wifi data initing successfully!\n");
		receive_packet(capt_fd,send_fd);
	}	
}

int read_cfg( char *filename,CapInfo * pInfo )
{
	FILE *fp = NULL;
	char keyName[100];

	if( ( fp = fopen(filename,"rt") ) == NULL )
	{
		printf("cannot open file %s\n",filename);
		return -1;
	}

	if( FIND_PARAM_HEADER(fp,USERINFO_HEADER) != 0)
	{
		return -1;
	}

	LOAD_PARAM_STR(fp,keyName,pInfo->ip);
	LOAD_PARAM_STR(fp,keyName,pInfo->port);
	LOAD_PARAM_STR(fp,keyName,pInfo->channel);
	LOAD_PARAM_STR(fp,keyName,pInfo->interface);

	if (fp)
	{
		fclose(fp);
	}

	return 0;
}

void main(int argc,char *argv[])
{
	CapInfo confRead;
	if(argc<2)
	{
		perror("Please input the filename of the file you want to save!");
		exit(1);
	}
	filename=argv[1];
	if(read_cfg(USER_CFG_FILE,&confRead)!=0)
	{
		printf("Configure file error or not exist,please check it!\n");
		exit(1);
	}
	//printf("confInfo:\nIP:%s\nPORT:%s\nCHANNEL:%s\nINTERFACE:%s\n",confRead.ip,confRead.port,confRead.channel,confRead.interface);
	/*
	if(argc<5)
	{
		perror("stderr,the input forum like this : sudo ./client 192.168.1.111 wlan1 auto 3000\n");
		exit(1);
	}
	*/
	if((host=gethostbyname(confRead.ip))==NULL)
	{
		perror("gethostbyname");
		exit(1);
	}
	ifname=confRead.interface;
	chan_flag=confRead.channel;
	port_num=confRead.port;

	signal(SIGPIPE, SIG_IGN);
	set_monitor_mode();

	pthread_t id1,id2;
	int ret;
	ret=pthread_create(&id1,NULL,(void *)wifi_cap_thread,NULL);
	if(ret!=0)
	{
		perror("Create wifi_cap_thread error");
		exit(1);
	}
	ret=pthread_create(&id2,NULL,(void *)change_channel_thread,NULL);
	if(ret!=0)
	{
		perror("Create change_channel_thread error");
		exit(1);
	}			
	pthread_join(id1,NULL);
	pthread_join(id2,NULL);	
}
