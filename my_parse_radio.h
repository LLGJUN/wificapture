/**
802.11 wireless frame radiotap prase function 
*/

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>
#include <string.h>

#include "radiotap_iter.h"

static void print_radiotap_namespace(struct ieee80211_radiotap_iterator *iter)
{
    //char signal = 0;
    unsigned int  signal=0;
    uint32_t phy_freq = 0;

	switch (iter->this_arg_index)
    {
	case IEEE80211_RADIOTAP_TSFT:
		//printf("\tTSFT: %llu\n", le64toh(*(unsigned long long *)iter->this_arg));
		break;
	case IEEE80211_RADIOTAP_FLAGS:
		//printf("\tflags: %02x\n", *iter->this_arg);
		break;
    //rate
	case IEEE80211_RADIOTAP_RATE:
		//printf("\trate: %.2f Mbit/s\n", (double)*iter->this_arg/2);
		break;

#define IEEE80211_CHAN_A \
	(IEEE80211_CHAN_5GHZ | IEEE80211_CHAN_OFDM)
#define IEEE80211_CHAN_G \
	(IEEE80211_CHAN_2GHZ | IEEE80211_CHAN_OFDM)
    //channel message
	case IEEE80211_RADIOTAP_CHANNEL:
        phy_freq = le16toh(*(uint16_t*)iter->this_arg); // 信道
        iter->this_arg = iter->this_arg + 2; // 通道信息如2G、5G，等
        int x = le16toh(*(uint16_t*)iter->this_arg);
        //printf("freq: %d  ", phy_freq);
        //printf("\tfreq: %d type: ", phy_freq);
        if ((x & IEEE80211_CHAN_A) == IEEE80211_CHAN_A)
        {
            //printf("A\n");
        }
        else if ((x & IEEE80211_CHAN_G) == IEEE80211_CHAN_G)
        {
            //printf("G\n");
        }
        else if ((x & IEEE80211_CHAN_2GHZ) == IEEE80211_CHAN_2GHZ)
        {
            //printf("B\n");
        }
        break;
    // 信号强度
	case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
        //signal = *(signed char*)iter->this_arg;
		signal = (signed char)(*iter->this_arg);
        //printf("\tsignal: %d dBm\t", signal);
        break;
		break;
    // 接收标志
	case IEEE80211_RADIOTAP_RX_FLAGS:
		//printf("\tRX flags: %#.4x\n", le16toh(*(uint16_t *)iter->this_arg));
		break;
    case IEEE80211_RADIOTAP_ANTENNA:
        //printf("\tantenna: %x\n", *iter->this_arg);
        break;
    // 忽略下面的
	case IEEE80211_RADIOTAP_RTS_RETRIES:
	case IEEE80211_RADIOTAP_DATA_RETRIES:
    case IEEE80211_RADIOTAP_FHSS:
	case IEEE80211_RADIOTAP_DBM_ANTNOISE:
	case IEEE80211_RADIOTAP_LOCK_QUALITY:
	case IEEE80211_RADIOTAP_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
	case IEEE80211_RADIOTAP_DBM_TX_POWER:
	case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
	case IEEE80211_RADIOTAP_DB_ANTNOISE:
	case IEEE80211_RADIOTAP_TX_FLAGS:
		break;
	default:
		printf("\tBOGUS DATA\n");
		break;
	}
}

int parse_radiotap_message(struct ieee80211_radiotap_header *radiotap_buf,int radiomess_length)
{
    struct ieee80211_radiotap_iterator iter;
    int err;
    int i, j;
    err = ieee80211_radiotap_iterator_init(&iter, radiotap_buf, radiomess_length, NULL);
    //err = ieee80211_radiotap_iterator_init(&iter, (struct ieee80211_radiotap_header *)radiotap_buf, sizeof(radiotap_buf), NULL);
    if(err)
    {
        printf("not valid radiotap...\n");
        return -1;
    }
    j = 0;
    /**
    遍历时，this_arg_index表示当前索引(如IEEE80211_RADIOTAP_TSFT等)，
    this_arg表示当前索引的值，this_arg_size表示值的大小。
    只有flag为true时才会进一步解析。
    */
    while (!(err = ieee80211_radiotap_iterator_next(&iter)))
    {
        //printf("next[%d]: index: %d size: %d\n",j, iter.this_arg_index, iter.this_arg_size);
        if (iter.is_radiotap_ns) // 表示是radiotap的命名空间
        {
            print_radiotap_namespace(&iter);
        }
        j++;
    }
    return 0;
}