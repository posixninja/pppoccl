//
//  main.c
//  pppconfuzz
//
//  Created by Joshua Hill on 2/12/17.
//  Copyright © 2017 Joshua Hill. All rights reserved.
//

#include <time.h>
#include <stdio.h>
#include <sys/un.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>

#include <sys/syslog.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "ppp_msg.h"
#include "ppp_privmsg.h"

#define	PPPIOCGFLAGS	_IOR('t', 90, int)	/* get configuration flags */
#define	PPPIOCSFLAGS	_IOW('t', 89, int)	/* set configuration flags */
#define	PPPIOCGASYNCMAP	_IOR('t', 88, int)	/* get async map */
#define	PPPIOCSASYNCMAP	_IOW('t', 87, int)	/* set async map */
#define	PPPIOCGUNIT	_IOR('t', 86, int)	/* get ppp unit number */
#define	PPPIOCGRASYNCMAP _IOR('t', 85, int)	/* get receive async map */
#define	PPPIOCSRASYNCMAP _IOW('t', 84, int)	/* set receive async map */
#define	PPPIOCGMRU	_IOR('t', 83, int)	/* get max receive unit */
#define	PPPIOCSMRU	_IOW('t', 82, int)	/* set max receive unit */
#define	PPPIOCSMAXCID	_IOW('t', 81, int)	/* set VJ max slot ID */
#define PPPIOCGXASYNCMAP _IOR('t', 80, ext_accm) /* get extended ACCM */
#define PPPIOCSXASYNCMAP _IOW('t', 79, ext_accm) /* set extended ACCM */
#define PPPIOCXFERUNIT	_IO('t', 78)		/* transfer PPP unit */
#define PPPIOCSCOMPRESS	_IOW('t', 77, struct ppp_option_data)
#ifdef KERNEL_PRIVATE
#ifdef __LP64__
#define PPPIOCSCOMPRESS32	_IOW('t', 77, struct ppp_option_data32)
#define PPPIOCSCOMPRESS64	PPPIOCSCOMPRESS
#else
#define PPPIOCSCOMPRESS32	PPPIOCSCOMPRESS
#define PPPIOCSCOMPRESS64	_IOW('t', 77, struct ppp_option_data64)
#endif /* __LP64__ */
#endif /* KERNEL_PRIVATE */
#define PPPIOCGNPMODE	_IOWR('t', 76, struct npioctl) /* get NP mode */
#define PPPIOCSNPMODE	_IOW('t', 75, struct npioctl)  /* set NP mode */
#define PPPIOCSPASS	_IOW('t', 71, struct sock_fprog) /* set pass filter */
#define PPPIOCSACTIVE	_IOW('t', 70, struct sock_fprog) /* set active filt */
#define PPPIOCGDEBUG	_IOR('t', 65, int)	/* Read debug level */
#define PPPIOCSDEBUG	_IOW('t', 64, int)	/* Set debug level */
#define PPPIOCGIDLE	_IOR('t', 63, struct ppp_idle) /* get idle time */
#define PPPIOCNEWUNIT	_IOWR('t', 62, int)	/* create new ppp unit */
#define PPPIOCATTACH	_IOW('t', 61, int)	/* attach to ppp unit */
#define PPPIOCDETACH	_IOW('t', 60, int)	/* detach from ppp unit/chan */
#define PPPIOCSMRRU	_IOW('t', 59, int)	/* set multilink MRU */
#define PPPIOCCONNECT	_IOW('t', 58, int)	/* connect channel to unit */
#define PPPIOCDISCONN	_IO('t', 57)		/* disconnect channel */
#define PPPIOCATTCHAN	_IOW('t', 56, int)	/* attach to ppp channel */
#define PPPIOCGCHAN	_IOR('t', 55, int)	/* get ppp channel number */
#define PPPIOCGNPAFMODE	_IOWR('t', 54, struct npafioctl) /* get NPAF mode */
#define PPPIOCSNPAFMODE	_IOW('t', 53, struct npafioctl)  /* set NPAF mode */
#define PPPIOCSDELEGATE _IOW('t', 52, struct ifpppdelegate)   /* set the delegate interface */

/* GRE definitions */
#define PPTP_GRE_TYPE 		0x880B
#define PPTP_GRE_FLAGS_C	0x80
#define PPTP_GRE_FLAGS_R	0x40
#define PPTP_GRE_FLAGS_K	0x20
#define PPTP_GRE_FLAGS_S	0x10
#define PPTP_GRE_FLAGS_s	0x08

#define PPTP_GRE_FLAGS_A	0x80
#define PPTP_GRE_VER		1



#define PPPPROTO_PPTP		17		/* TEMP - move to ppp.h - 1..32 are reserved */
#define PPTP_NAME		"PPTP"		/* */


#define PPTP_OPT_FLAGS		1	/* see flags definition below */
#define PPTP_OPT_PEERADDRESS	2	/* peer IP address */
#define PPTP_OPT_CALL_ID	3	/* call id for the connection */
#define PPTP_OPT_PEER_CALL_ID	4	/* peer call id for the connection */
#define PPTP_OPT_WINDOW		5	/* our receive window */
#define PPTP_OPT_PEER_WINDOW	6	/* peer receive window */
#define PPTP_OPT_PEER_PPD	7	/* peer packet processing delay */
#define PPTP_OPT_MAXTIMEOUT	8	/* maximum adptative timeout */
#define PPTP_OPT_OURADDRESS	9	/* our IP address */
#define PPTP_OPT_BAUDRATE	10	/* tunnel baudrate */

#define PPPPROTO_CTL		1		/* control protocol for ifnet layer */

#define PPP_NAME		"PPP"		/* ppp family name */


struct sockaddr_ppp {
    u_int8_t	ppp_len;			/* sizeof(struct sockaddr_ppp) + variable part */
    u_int8_t	ppp_family;			/* AF_PPPCTL */
    u_int16_t	ppp_proto;			/* protocol coding address */
    u_int32_t 	ppp_cookie;			/* one long for protocol with few info */
    // variable len, the following are protocol specific addresses
};


struct ppp_link_event_data {
    u_int16_t          lk_index;
    u_int16_t          lk_unit;
    char               lk_name[IFNAMSIZ];
};

/* Define PPP events, as subclass of NETWORK_CLASS events */

#define KEV_PPP_NET_SUBCLASS 	3
#define KEV_PPP_LINK_SUBCLASS 	4


/* flags definition */
#define PPTP_FLAG_DEBUG		0x00000002	/* debug mode, send verbose logs to syslog */

#define	PPPIOCGFLAGS	_IOR('t', 90, int)	/* get configuration flags */
#define	PPPIOCSFLAGS	_IOW('t', 89, int)	/* set configuration flags */
#define	PPPIOCGASYNCMAP	_IOR('t', 88, int)	/* get async map */
#define	PPPIOCSASYNCMAP	_IOW('t', 87, int)	/* set async map */
#define	PPPIOCGUNIT	_IOR('t', 86, int)	/* get ppp unit number */
#define	PPPIOCGRASYNCMAP _IOR('t', 85, int)	/* get receive async map */
#define	PPPIOCSRASYNCMAP _IOW('t', 84, int)	/* set receive async map */
#define	PPPIOCGMRU	_IOR('t', 83, int)	/* get max receive unit */
#define	PPPIOCSMRU	_IOW('t', 82, int)	/* set max receive unit */
#define	PPPIOCSMAXCID	_IOW('t', 81, int)	/* set VJ max slot ID */
#define PPPIOCGXASYNCMAP _IOR('t', 80, ext_accm) /* get extended ACCM */
#define PPPIOCSXASYNCMAP _IOW('t', 79, ext_accm) /* set extended ACCM */
#define PPPIOCXFERUNIT	_IO('t', 78)		/* transfer PPP unit */
#define PPPIOCSCOMPRESS	_IOW('t', 77, struct ppp_option_data)
#ifdef KERNEL_PRIVATE
#ifdef __LP64__
#define PPPIOCSCOMPRESS32	_IOW('t', 77, struct ppp_option_data32)
#define PPPIOCSCOMPRESS64	PPPIOCSCOMPRESS
#else
#define PPPIOCSCOMPRESS32	PPPIOCSCOMPRESS
#define PPPIOCSCOMPRESS64	_IOW('t', 77, struct ppp_option_data64)
#endif /* __LP64__ */
#endif /* KERNEL_PRIVATE */
#define PPPIOCGNPMODE	_IOWR('t', 76, struct npioctl) /* get NP mode */
#define PPPIOCSNPMODE	_IOW('t', 75, struct npioctl)  /* set NP mode */
#define PPPIOCSPASS	_IOW('t', 71, struct sock_fprog) /* set pass filter */
#define PPPIOCSACTIVE	_IOW('t', 70, struct sock_fprog) /* set active filt */
#define PPPIOCGDEBUG	_IOR('t', 65, int)	/* Read debug level */
#define PPPIOCSDEBUG	_IOW('t', 64, int)	/* Set debug level */
#define PPPIOCGIDLE	_IOR('t', 63, struct ppp_idle) /* get idle time */
#define PPPIOCNEWUNIT	_IOWR('t', 62, int)	/* create new ppp unit */
#define PPPIOCATTACH	_IOW('t', 61, int)	/* attach to ppp unit */
#define PPPIOCDETACH	_IOW('t', 60, int)	/* detach from ppp unit/chan */
#define PPPIOCSMRRU	_IOW('t', 59, int)	/* set multilink MRU */
#define PPPIOCCONNECT	_IOW('t', 58, int)	/* connect channel to unit */
#define PPPIOCDISCONN	_IO('t', 57)		/* disconnect channel */
#define PPPIOCATTCHAN	_IOW('t', 56, int)	/* attach to ppp channel */
#define PPPIOCGCHAN	_IOR('t', 55, int)	/* get ppp channel number */
#define PPPIOCGNPAFMODE	_IOWR('t', 54, struct npafioctl) /* get NPAF mode */
#define PPPIOCSNPAFMODE	_IOW('t', 53, struct npafioctl)  /* set NPAF mode */
#define PPPIOCSDELEGATE _IOW('t', 52, struct ifpppdelegate)   /* set the delegate interface */

uint16_t flip_endian16(uint16_t value) {
    uint16_t result = 0;
    result |= (value & 0xFF) << 8;
    result |= (value & 0xFF00) >> 8;
    return result;
}

uint32_t flip_endian32(uint32_t value) {
    uint32_t result = 0;
    result |= (value & 0xFF) << 24;
    result |= (value & 0xFF00) << 8;
    result |= (value & 0xFF0000) >> 8;
    result |= (value & 0xFF000000) >> 24;
    return result;
}

int randomize_string(unsigned char* buffer, int size, float amount) {
    int i = 0;
    //srand(seed++);
    //printf("Seeded with %d\8n", seed);
    //char dbg[0x100];
    int times = (int) ((amount * (float) (size*8)) + 0.5);
    //snprintf(dbg, 0xFF, "%d * %f = %d\n", size, amount, times);
    //printf("%s\n", dbg);
    int bits = size * 8;
    //memset(buffer, '\1', size);
    for (i = 0; i < times; i++) {
        //printf("%d\n", i);
        // Here we're going to flip some bits and record the type of crash we get
        int bit = rand() % bits; // returns a number 0x0 to size * 8
        //printf("Bit = %d\n", bit);
        int index = bit / 8; // returns the byte index of the bit we're going to change
        //printf("Index = 0x%x\n", index);
        //printf("Original byte found was 0x%x at 0x%08x\n", buffer[index], &buffer[index]);
        
        int shift = bit - (index * 8); // the index of the bit from the byte
        //debug("Shift = %d\n", shift);
        char bit_mask = 1 << shift;
        //debug("BitMask = 0x%x\n\n", bit_mask);
        buffer[index] ^= bit_mask;
        //printf("New byte is 0x%x\n\n", buffer[index]);
        //buffer[index] &= ~0x80;
    }
    return 0;
}

unsigned int random_string(unsigned char* buffer, unsigned int size) {
    unsigned int i = 0;
    for (i = 0; i < size; i++) {
        buffer[i] = rand() & 0xFF;
    }
    return size;
}

unsigned int random_int() {
    unsigned int i = 0;
    unsigned int v = 0;
    unsigned char buffer[4];
    for (i = 0; i < 4; i++) {
        buffer[i] = rand() & 0xFF;
    }
    v = *(unsigned int*) buffer;
    return v;
}

unsigned short random_short() {
    unsigned int i = 0;
    unsigned short v = 0;
    unsigned char buffer[2];
    for (i = 0; i < 2; i++) {
        buffer[i] = rand() & 0xFF;
    }
    v = *(unsigned short*) buffer;
    return v;
}

unsigned char random_char() {
    unsigned int i = 0;
    unsigned char v = 0;
    unsigned char buffer[1];
    for (i = 0; i < 1; i++) {
        buffer[i] = rand() & 0xFF;
    }
    v = *(unsigned char*) buffer;
    return v;
}

void hexdump (unsigned char *data, unsigned int amount) {
    unsigned int    dp, p;  /* data pointer */
    const char      trans[] =
    "................................ !\"#$%&'()*+,-./0123456789"
    ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
    "nopqrstuvwxyz{|}~...................................."
    "....................................................."
    "........................................";
    
    
    for (dp = 1; dp <= amount; dp++) {
        //if( data[dp-1] == 0) return;
        fprintf (stderr, "%02x ", data[dp-1]);
        if ((dp % 8) == 0)
            fprintf (stderr, " ");
        if ((dp % 16) == 0) {
            fprintf (stderr, "| ");
            p = dp;
            for (dp -= 16; dp < p; dp++)
                fprintf (stderr, "%c", trans[data[dp]]);
            fflush (stderr);
            fprintf (stderr, "\n");
        }
        fflush (stderr);
    }
    // tail
    if ((amount % 16) != 0) {
        p = dp = 16 - (amount % 16);
        for (dp = p; dp > 0; dp--) {
            fprintf (stderr, "   ");
            if (((dp % 8) == 0) && (p != 8))
                fprintf (stderr, " ");
            fflush (stderr);
        }
        fprintf (stderr, " | ");
        for (dp = (amount - (16 - p)); dp < amount; dp++)
            fprintf (stderr, "%c", trans[data[dp]]);
        fflush (stderr);
    }
    fprintf (stderr, "\n");
    
    return;
}
/*
 struct ppp_msg {
 u_int16_t 		m_flags; 	// special flags
 u_int16_t 		m_type; 	// type of the message
 u_int32_t 		m_result; 	// error code of notification message
 u_int32_t 		m_cookie;	// user param, or error num for event
 u_int32_t 		m_link;		// link for this message
 u_int32_t 		m_len;		// len of the following data
 u_char 		m_data[1];	// msg data sent or received
 };
 */

int gFd = 0;
void debug_ppp_msg(struct ppp_msg* msg) {
    if(msg) {
    printf("Flags = 0x%hx\n", msg->m_flags);
    printf("Type = 0x%hx\n", msg->m_type);
    printf("Result = 0x%x\n", msg->m_result);
    printf("Cookie = 0x%x\n", msg->m_cookie);
    printf("Link = 0x%x\n", msg->m_link);
    printf("Len = 0x%x\n", msg->m_len);
    if(msg->m_result != 0) {
        printf("ERROR: %s\n", strerror(msg->m_result));
    } else
    if(msg->m_len > 0) {
        hexdump(msg, sizeof(struct ppp_msg_hdr) + msg->m_len);
    }
    printf("\n\n");
    }
}

char* ppp_type2str(uint16_t type) {
    switch(type){
        case PPP_STATUS:
            return "PPP Status";
            break;
            
        default:
            return "Unknown Type";
    }
}

void random_prefs() {
    /*
    const CFStringRef kSCResvLink                                      = CFSTR("__LINK__");
    const CFStringRef kSCResvInactive                                  = CFSTR("__INACTIVE__");
    const CFStringRef kSCPropInterfaceName                             = CFSTR("InterfaceName");
    const CFStringRef kSCPropMACAddress                                = CFSTR("MACAddress");
    const CFStringRef kSCPropUserDefinedName                           = CFSTR("UserDefinedName");
    const CFStringRef kSCPropVersion                                   = CFSTR("Version");
    const CFStringRef kSCPropNetIgnoreLinkStatus                       = CFSTR("IgnoreLinkStatus");
    const CFStringRef kSCPropConfirmedInterfaceName                    = CFSTR("ConfirmedInterfaceName");
    const CFStringRef kSCPropDisableUntilNeeded                        = CFSTR("DisableUntilNeeded");
    const CFStringRef kSCPrefCurrentSet                                = CFSTR("CurrentSet");
    const CFStringRef kSCPrefNetworkServices                           = CFSTR("NetworkServices");
    const CFStringRef kSCPrefSets                                      = CFSTR("Sets");
    const CFStringRef kSCPrefSystem                                    = CFSTR("System");
    const CFStringRef kSCPrefVirtualNetworkInterfaces                  = CFSTR("VirtualNetworkInterfaces");
    const CFStringRef kSCCompNetwork                                   = CFSTR("Network");
    const CFStringRef kSCCompService                                   = CFSTR("Service");
    const CFStringRef kSCCompGlobal                                    = CFSTR("Global");
    const CFStringRef kSCCompHostNames                                 = CFSTR("HostNames");
    const CFStringRef kSCCompInterface                                 = CFSTR("Interface");
    const CFStringRef kSCCompSystem                                    = CFSTR("System");
    const CFStringRef kSCCompUsers                                     = CFSTR("Users");
    const CFStringRef kSCCompAnyRegex                                  = CFSTR("[^/]+");
    const CFStringRef kSCEntNetAirPort                                 = CFSTR("AirPort");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCEntNetAppleTalk                               = CFSTR("AppleTalk");
#endif	// !TARGET_OS_IPHONE
    
    const CFStringRef kSCEntNetDHCP                                    = CFSTR("DHCP");
    const CFStringRef kSCEntNetDNS                                     = CFSTR("DNS");
    const CFStringRef kSCEntNetEthernet                                = CFSTR("Ethernet");
    const CFStringRef kSCEntNetFireWire                                = CFSTR("FireWire");
    const CFStringRef kSCEntNetInterface                               = CFSTR("Interface");
    const CFStringRef kSCEntNetIPSec                                   = CFSTR("IPSec");
    const CFStringRef kSCEntNetIPv4                                    = CFSTR("IPv4");
    const CFStringRef kSCEntNetIPv6                                    = CFSTR("IPv6");
    const CFStringRef kSCEntNetL2TP                                    = CFSTR("L2TP");
    const CFStringRef kSCEntNetLink                                    = CFSTR("Link");
    const CFStringRef kSCEntNetModem                                   = CFSTR("Modem");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCEntNetNetInfo                                 = CFSTR("NetInfo");
#endif	// !TARGET_OS_IPHONE
    
    const CFStringRef kSCEntNetPPP                                     = CFSTR("PPP");
    const CFStringRef kSCEntNetPPPoE                                   = CFSTR("PPPoE");
    const CFStringRef kSCEntNetPPPSerial                               = CFSTR("PPPSerial");
    const CFStringRef kSCEntNetPPTP                                    = CFSTR("PPTP");
    const CFStringRef kSCEntNetProxies                                 = CFSTR("Proxies");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCEntNetSMB                                     = CFSTR("SMB");
#endif	// !TARGET_OS_IPHONE
    
    const CFStringRef kSCEntNet6to4                                    = CFSTR("6to4");
    const CFStringRef kSCEntNetActiveDuringSleepRequested              = CFSTR("ActiveDuringSleepRequested");
    const CFStringRef kSCEntNetActiveDuringSleepSupported              = CFSTR("ActiveDuringSleepSupported");
    const CFStringRef kSCEntNetAppLayer                                = CFSTR("AppLayer");
    
    
    const CFStringRef kSCEntNetEAPOL                                   = CFSTR("EAPOL");
    const CFStringRef kSCEntNetIPv4RouterARPFailure                    = CFSTR("IPv4RouterARPFailure");
    const CFStringRef kSCEntNetIPv4RouterARPAlive                      = CFSTR("IPv4RouterARPAlive");
    const CFStringRef kSCEntNetLinkIssues                              = CFSTR("LinkIssues");
    const CFStringRef kSCEntNetLinkQuality                             = CFSTR("LinkQuality");
    const CFStringRef kSCEntNetLoopback                                = CFSTR("Loopback");
    const CFStringRef kSCEntNetOnDemand                                = CFSTR("OnDemand");
    const CFStringRef kSCEntNetQoSMarkingPolicy                        = CFSTR("QoSMarkingPolicy");
    const CFStringRef kSCEntNetService                                 = CFSTR("__SERVICE__");
    const CFStringRef kSCEntNetVPN                                     = CFSTR("VPN");
    const CFStringRef kSCPropNetOverridePrimary                        = CFSTR("OverridePrimary");
    const CFStringRef kSCPropNetServiceOrder                           = CFSTR("ServiceOrder");
    const CFStringRef kSCPropNetPPPOverridePrimary                     = CFSTR("PPPOverridePrimary");
    const CFStringRef kSCPropNetInterfaces                             = CFSTR("Interfaces");
    const CFStringRef kSCPropNetLocalHostName                          = CFSTR("LocalHostName");
    const CFStringRef kSCPropNetAirPortAllowNetCreation                = CFSTR("AllowNetCreation");
    const CFStringRef kSCPropNetAirPortAuthPassword                    = CFSTR("AuthPassword");
    const CFStringRef kSCPropNetAirPortAuthPasswordEncryption          = CFSTR("AuthPasswordEncryption");
    const CFStringRef kSCPropNetAirPortJoinMode                        = CFSTR("JoinMode");
    const CFStringRef kSCPropNetAirPortPowerEnabled                    = CFSTR("PowerEnabled");
    const CFStringRef kSCPropNetAirPortPreferredNetwork                = CFSTR("PreferredNetwork");
    const CFStringRef kSCPropNetAirPortSavePasswords                   = CFSTR("SavePasswords");
    const CFStringRef kSCValNetAirPortJoinModeAutomatic                = CFSTR("Automatic");
    const CFStringRef kSCValNetAirPortJoinModePreferred                = CFSTR("Preferred");
    const CFStringRef kSCValNetAirPortJoinModeRanked                   = CFSTR("Ranked");
    const CFStringRef kSCValNetAirPortJoinModeRecent                   = CFSTR("Recent");
    const CFStringRef kSCValNetAirPortJoinModeStrongest                = CFSTR("Strongest");
    const CFStringRef kSCValNetAirPortAuthPasswordEncryptionKeychain   = CFSTR("Keychain");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCPropNetAppleTalkConfigMethod                  = CFSTR("ConfigMethod");
    const CFStringRef kSCPropNetAppleTalkDefaultZone                   = CFSTR("DefaultZone");
    const CFStringRef kSCPropNetAppleTalkNetworkID                     = CFSTR("NetworkID");
    const CFStringRef kSCPropNetAppleTalkNodeID                        = CFSTR("NodeID");
    const CFStringRef kSCValNetAppleTalkConfigMethodNode               = CFSTR("Node");
#endif	// !TARGET_OS_IPHONE
    
    
    
    const CFStringRef kSCPropNetDNSDomainName                          = CFSTR("DomainName");
    const CFStringRef kSCPropNetDNSOptions                             = CFSTR("Options");
    const CFStringRef kSCPropNetDNSSearchDomains                       = CFSTR("SearchDomains");
    const CFStringRef kSCPropNetDNSSearchOrder                         = CFSTR("SearchOrder");
    const CFStringRef kSCPropNetDNSServerAddresses                     = CFSTR("ServerAddresses");
    const CFStringRef kSCPropNetDNSServerPort                          = CFSTR("ServerPort");
    const CFStringRef kSCPropNetDNSServerTimeout                       = CFSTR("ServerTimeout");
    const CFStringRef kSCPropNetDNSSortList                            = CFSTR("SortList");
    const CFStringRef kSCPropNetDNSSupplementalMatchDomains            = CFSTR("SupplementalMatchDomains");
    const CFStringRef kSCPropNetDNSSupplementalMatchOrders             = CFSTR("SupplementalMatchOrders");
    const CFStringRef kSCPropNetDNSConfirmedServiceID                  = CFSTR("ConfirmedServiceID");
    const CFStringRef kSCPropNetDNSServiceIdentifier                   = CFSTR("ServiceIdentifier");
    const CFStringRef kSCPropNetDNSSupplementalMatchDomainsNoSearch    = CFSTR("SupplementalMatchDomainsNoSearch");
    const CFStringRef kSCPropNetEthernetMediaSubType                   = CFSTR("MediaSubType");
    const CFStringRef kSCPropNetEthernetMediaOptions                   = CFSTR("MediaOptions");
    const CFStringRef kSCPropNetEthernetMTU                            = CFSTR("MTU");
    const CFStringRef kSCPropNetEthernetCapabilityAV                   = CFSTR("AV");
    const CFStringRef kSCPropNetEthernetCapabilityJUMBO_MTU            = CFSTR("JUMBO_MTU");
    const CFStringRef kSCPropNetEthernetCapabilityLRO                  = CFSTR("LRO");
    const CFStringRef kSCPropNetEthernetCapabilityRXCSUM               = CFSTR("RXCSUM");
    const CFStringRef kSCPropNetEthernetCapabilityTSO                  = CFSTR("TSO");
    const CFStringRef kSCPropNetEthernetCapabilityTSO4                 = CFSTR("TSO4");
    const CFStringRef kSCPropNetEthernetCapabilityTSO6                 = CFSTR("TSO6");
    const CFStringRef kSCPropNetEthernetCapabilityTXCSUM               = CFSTR("TXCSUM");
    const CFStringRef kSCPropNetEthernetCapabilityVLAN_HWTAGGING       = CFSTR("VLAN_HWTAGGING");
    const CFStringRef kSCPropNetEthernetCapabilityVLAN_MTU             = CFSTR("VLAN_MTU");
    const CFStringRef kSCPropNetInterfaceDeviceName                    = CFSTR("DeviceName");
    const CFStringRef kSCPropNetInterfaceHardware                      = CFSTR("Hardware");
    const CFStringRef kSCPropNetInterfaceType                          = CFSTR("Type");
    const CFStringRef kSCPropNetInterfaceSubType                       = CFSTR("SubType");
    const CFStringRef kSCPropNetInterfaceSupportsModemOnHold           = CFSTR("SupportsModemOnHold");
    const CFStringRef kSCValNetInterfaceTypeEthernet                   = CFSTR("Ethernet");
    const CFStringRef kSCValNetInterfaceTypeFireWire                   = CFSTR("FireWire");
    const CFStringRef kSCValNetInterfaceTypePPP                        = CFSTR("PPP");
    const CFStringRef kSCValNetInterfaceType6to4                       = CFSTR("6to4");
    const CFStringRef kSCValNetInterfaceTypeIPSec                      = CFSTR("IPSec");
    const CFStringRef kSCValNetInterfaceSubTypePPPoE                   = CFSTR("PPPoE");
    const CFStringRef kSCValNetInterfaceSubTypePPPSerial               = CFSTR("PPPSerial");
    const CFStringRef kSCValNetInterfaceSubTypePPTP                    = CFSTR("PPTP");
    const CFStringRef kSCValNetInterfaceSubTypeL2TP                    = CFSTR("L2TP");
    
    
    const CFStringRef kSCValNetInterfaceTypeLoopback                   = CFSTR("Loopback");
    const CFStringRef kSCValNetInterfaceTypeVPN                        = CFSTR("VPN");
    const CFStringRef kSCPropNetIPSecAuthenticationMethod              = CFSTR("AuthenticationMethod");
    const CFStringRef kSCPropNetIPSecLocalCertificate                  = CFSTR("LocalCertificate");
    const CFStringRef kSCPropNetIPSecLocalIdentifier                   = CFSTR("LocalIdentifier");
    const CFStringRef kSCPropNetIPSecLocalIdentifierType               = CFSTR("LocalIdentifierType");
    const CFStringRef kSCPropNetIPSecSharedSecret                      = CFSTR("SharedSecret");
    const CFStringRef kSCPropNetIPSecSharedSecretEncryption            = CFSTR("SharedSecretEncryption");
    const CFStringRef kSCPropNetIPSecConnectTime                       = CFSTR("ConnectTime");
    const CFStringRef kSCPropNetIPSecRemoteAddress                     = CFSTR("RemoteAddress");
    const CFStringRef kSCPropNetIPSecStatus                            = CFSTR("Status");
    const CFStringRef kSCPropNetIPSecXAuthEnabled                      = CFSTR("XAuthEnabled");
    const CFStringRef kSCPropNetIPSecXAuthName                         = CFSTR("XAuthName");
    const CFStringRef kSCPropNetIPSecXAuthPassword                     = CFSTR("XAuthPassword");
    const CFStringRef kSCPropNetIPSecXAuthPasswordEncryption           = CFSTR("XAuthPasswordEncryption");
    const CFStringRef kSCPropNetIPSecDisconnectOnWake                  = CFSTR("DisconnectOnWake");
    const CFStringRef kSCPropNetIPSecDisconnectOnWakeTimer             = CFSTR("DisconnectOnWakeTimer");
    const CFStringRef kSCValNetIPSecAuthenticationMethodSharedSecret   = CFSTR("SharedSecret");
    const CFStringRef kSCValNetIPSecAuthenticationMethodCertificate    = CFSTR("Certificate");
    const CFStringRef kSCValNetIPSecAuthenticationMethodHybrid         = CFSTR("Hybrid");
    const CFStringRef kSCValNetIPSecLocalIdentifierTypeKeyID           = CFSTR("KeyID");
    const CFStringRef kSCValNetIPSecSharedSecretEncryptionKeychain     = CFSTR("Keychain");
    const CFStringRef kSCValNetIPSecXAuthPasswordEncryptionKeychain    = CFSTR("Keychain");
    const CFStringRef kSCValNetIPSecXAuthPasswordEncryptionPrompt      = CFSTR("Prompt");
    const CFStringRef kSCPropNetIPSecLastCause                         = CFSTR("LastCause");
    const CFStringRef kSCPropNetIPSecOnDemandEnabled                   = CFSTR("OnDemandEnabled");
    const CFStringRef kSCPropNetIPSecOnDemandMatchDomainsAlways        = CFSTR("OnDemandMatchDomainsAlways");
    const CFStringRef kSCPropNetIPSecOnDemandMatchDomainsOnRetry       = CFSTR("OnDemandMatchDomainsOnRetry");
    const CFStringRef kSCPropNetIPSecOnDemandMatchDomainsNever         = CFSTR("OnDemandMatchDomainsNever");
    const CFStringRef kSCPropNetIPv4Addresses                          = CFSTR("Addresses");
    const CFStringRef kSCPropNetIPv4ConfigMethod                       = CFSTR("ConfigMethod");
    const CFStringRef kSCPropNetIPv4DHCPClientID                       = CFSTR("DHCPClientID");
    const CFStringRef kSCPropNetIPv4Router                             = CFSTR("Router");
    const CFStringRef kSCPropNetIPv4SubnetMasks                        = CFSTR("SubnetMasks");
    const CFStringRef kSCPropNetIPv4DestAddresses                      = CFSTR("DestAddresses");
    const CFStringRef kSCPropNetIPv4BroadcastAddresses                 = CFSTR("BroadcastAddresses");
    const CFStringRef kSCValNetIPv4ConfigMethodAutomatic               = CFSTR("Automatic");
    const CFStringRef kSCValNetIPv4ConfigMethodBOOTP                   = CFSTR("BOOTP");
    const CFStringRef kSCValNetIPv4ConfigMethodDHCP                    = CFSTR("DHCP");
    const CFStringRef kSCValNetIPv4ConfigMethodINFORM                  = CFSTR("INFORM");
    const CFStringRef kSCValNetIPv4ConfigMethodLinkLocal               = CFSTR("LinkLocal");
    const CFStringRef kSCValNetIPv4ConfigMethodManual                  = CFSTR("Manual");
    const CFStringRef kSCValNetIPv4ConfigMethodPPP                     = CFSTR("PPP");
    const CFStringRef kSCPropNetIPv4AdditionalRoutes                   = CFSTR("AdditionalRoutes");
    const CFStringRef kSCPropNetIPv4ExcludedRoutes                     = CFSTR("ExcludedRoutes");
    const CFStringRef kSCPropNetIPv4IncludedRoutes                     = CFSTR("IncludedRoutes");
    const CFStringRef kSCValNetIPv4ConfigMethodFailover                = CFSTR("Failover");
    const CFStringRef kSCPropNetIPv4RouteDestinationAddress            = CFSTR("DestinationAddress");
    const CFStringRef kSCPropNetIPv4RouteSubnetMask                    = CFSTR("SubnetMask");
    const CFStringRef kSCPropNetIPv4RouteGatewayAddress                = CFSTR("GatewayAddress");
    const CFStringRef kSCPropNetIPv4RouteInterfaceName                 = CFSTR("InterfaceName");
    const CFStringRef kSCPropNetIPv4ARPResolvedHardwareAddress         = CFSTR("ARPResolvedHardwareAddress");
    const CFStringRef kSCPropNetIPv4ARPResolvedIPAddress               = CFSTR("ARPResolvedIPAddress");
    const CFStringRef kSCPropNetIPv6Addresses                          = CFSTR("Addresses");
    const CFStringRef kSCPropNetIPv6ConfigMethod                       = CFSTR("ConfigMethod");
    const CFStringRef kSCPropNetIPv6DestAddresses                      = CFSTR("DestAddresses");
    const CFStringRef kSCPropNetIPv6Flags                              = CFSTR("Flags");
    const CFStringRef kSCPropNetIPv6PrefixLength                       = CFSTR("PrefixLength");
    const CFStringRef kSCPropNetIPv6Router                             = CFSTR("Router");
    const CFStringRef kSCValNetIPv6ConfigMethodAutomatic               = CFSTR("Automatic");
    const CFStringRef kSCValNetIPv6ConfigMethodLinkLocal               = CFSTR("LinkLocal");
    const CFStringRef kSCValNetIPv6ConfigMethodManual                  = CFSTR("Manual");
    const CFStringRef kSCValNetIPv6ConfigMethodRouterAdvertisement     = CFSTR("RouterAdvertisement");
    const CFStringRef kSCValNetIPv6ConfigMethod6to4                    = CFSTR("6to4");
    const CFStringRef kSCPropNetIPv6AdditionalRoutes                   = CFSTR("AdditionalRoutes");
    const CFStringRef kSCPropNetIPv6ExcludedRoutes                     = CFSTR("ExcludedRoutes");
    const CFStringRef kSCPropNetIPv6IncludedRoutes                     = CFSTR("IncludedRoutes");
    const CFStringRef kSCPropNetIPv6RouteDestinationAddress            = CFSTR("DestinationAddress");
    const CFStringRef kSCPropNetIPv6RoutePrefixLength                  = CFSTR("PrefixLength");
    const CFStringRef kSCPropNetIPv6RouteGatewayAddress                = CFSTR("GatewayAddress");
    const CFStringRef kSCPropNetIPv6RouteInterfaceName                 = CFSTR("InterfaceName");
    const CFStringRef kSCPropNet6to4Relay                              = CFSTR("Relay");
    const CFStringRef kSCPropNetLinkActive                             = CFSTR("Active");
    const CFStringRef kSCPropNetLinkDetaching                          = CFSTR("Detaching");
    const CFStringRef kSCPropNetLinkExpensive                          = CFSTR("Expensive");
    const CFStringRef kSCPropNetLinkIssuesModuleID                     = CFSTR("ModuleID");
    const CFStringRef kSCPropNetLinkIssuesInfo                         = CFSTR("Info");
    const CFStringRef kSCPropNetLinkIssuesTimeStamp                    = CFSTR("TimeStamp");
    const CFStringRef kSCPropNetLinkQuality                            = CFSTR("LinkQuality");
    const CFStringRef kSCPropNetModemAccessPointName                   = CFSTR("AccessPointName");
    const CFStringRef kSCPropNetModemConnectionPersonality             = CFSTR("ConnectionPersonality");
    const CFStringRef kSCPropNetModemConnectionScript                  = CFSTR("ConnectionScript");
    const CFStringRef kSCPropNetModemConnectSpeed                      = CFSTR("ConnectSpeed");
    const CFStringRef kSCPropNetModemDataCompression                   = CFSTR("DataCompression");
    const CFStringRef kSCPropNetModemDeviceContextID                   = CFSTR("DeviceContextID");
    const CFStringRef kSCPropNetModemDeviceModel                       = CFSTR("DeviceModel");
    const CFStringRef kSCPropNetModemDeviceVendor                      = CFSTR("DeviceVendor");
    const CFStringRef kSCPropNetModemDialMode                          = CFSTR("DialMode");
    const CFStringRef kSCPropNetModemErrorCorrection                   = CFSTR("ErrorCorrection");
    const CFStringRef kSCPropNetModemHoldCallWaitingAudibleAlert       = CFSTR("HoldCallWaitingAudibleAlert");
    const CFStringRef kSCPropNetModemHoldDisconnectOnAnswer            = CFSTR("HoldDisconnectOnAnswer");
    const CFStringRef kSCPropNetModemHoldEnabled                       = CFSTR("HoldEnabled");
    const CFStringRef kSCPropNetModemHoldReminder                      = CFSTR("HoldReminder");
    const CFStringRef kSCPropNetModemHoldReminderTime                  = CFSTR("HoldReminderTime");
    const CFStringRef kSCPropNetModemNote                              = CFSTR("Note");
    const CFStringRef kSCPropNetModemPulseDial                         = CFSTR("PulseDial");
    const CFStringRef kSCPropNetModemSpeaker                           = CFSTR("Speaker");
    const CFStringRef kSCPropNetModemSpeed                             = CFSTR("Speed");
    const CFStringRef kSCValNetModemDialModeIgnoreDialTone             = CFSTR("IgnoreDialTone");
    const CFStringRef kSCValNetModemDialModeManual                     = CFSTR("Manual");
    const CFStringRef kSCValNetModemDialModeWaitForDialTone            = CFSTR("WaitForDialTone");
    const CFStringRef kSCPropNetPPPACSPEnabled                         = CFSTR("ACSPEnabled");
    const CFStringRef kSCPropNetPPPConnectTime                         = CFSTR("ConnectTime");
    const CFStringRef kSCPropNetPPPDeviceLastCause                     = CFSTR("DeviceLastCause");
    const CFStringRef kSCPropNetPPPDialOnDemand                        = CFSTR("DialOnDemand");
    const CFStringRef kSCPropNetPPPDisconnectOnFastUserSwitch          = CFSTR("DisconnectOnFastUserSwitch");
    const CFStringRef kSCPropNetPPPDisconnectOnIdle                    = CFSTR("DisconnectOnIdle");
    const CFStringRef kSCPropNetPPPDisconnectOnIdleTimer               = CFSTR("DisconnectOnIdleTimer");
    const CFStringRef kSCPropNetPPPDisconnectOnLogout                  = CFSTR("DisconnectOnLogout");
    const CFStringRef kSCPropNetPPPDisconnectOnSleep                   = CFSTR("DisconnectOnSleep");
    const CFStringRef kSCPropNetPPPDisconnectOnWake                    = CFSTR("DisconnectOnWake");
    const CFStringRef kSCPropNetPPPDisconnectOnWakeTimer               = CFSTR("DisconnectOnWakeTimer");
    const CFStringRef kSCPropNetPPPDisconnectTime                      = CFSTR("DisconnectTime");
    const CFStringRef kSCPropNetPPPIdleReminderTimer                   = CFSTR("IdleReminderTimer");
    const CFStringRef kSCPropNetPPPIdleReminder                        = CFSTR("IdleReminder");
    const CFStringRef kSCPropNetPPPLastCause                           = CFSTR("LastCause");
    const CFStringRef kSCPropNetPPPLogfile                             = CFSTR("Logfile");
    const CFStringRef kSCPropNetPPPPlugins                             = CFSTR("Plugins");
    const CFStringRef kSCPropNetPPPRetryConnectTime                    = CFSTR("RetryConnectTime");
    const CFStringRef kSCPropNetPPPSessionTimer                        = CFSTR("SessionTimer");
    const CFStringRef kSCPropNetPPPStatus                              = CFSTR("Status");
    const CFStringRef kSCPropNetPPPUseSessionTimer                     = CFSTR("UseSessionTimer");
    const CFStringRef kSCPropNetPPPVerboseLogging                      = CFSTR("VerboseLogging");
    const CFStringRef kSCPropNetPPPAuthEAPPlugins                      = CFSTR("AuthEAPPlugins");
    const CFStringRef kSCPropNetPPPAuthName                            = CFSTR("AuthName");
    const CFStringRef kSCPropNetPPPAuthPassword                        = CFSTR("AuthPassword");
    const CFStringRef kSCPropNetPPPAuthPasswordEncryption              = CFSTR("AuthPasswordEncryption");
    const CFStringRef kSCPropNetPPPAuthPrompt                          = CFSTR("AuthPrompt");
    const CFStringRef kSCPropNetPPPAuthProtocol                        = CFSTR("AuthProtocol");
    const CFStringRef kSCValNetPPPAuthPasswordEncryptionKeychain       = CFSTR("Keychain");
    const CFStringRef kSCValNetPPPAuthPasswordEncryptionToken          = CFSTR("Token");
    const CFStringRef kSCValNetPPPAuthPromptBefore                     = CFSTR("Before");
    const CFStringRef kSCValNetPPPAuthPromptAfter                      = CFSTR("After");
    const CFStringRef kSCValNetPPPAuthProtocolCHAP                     = CFSTR("CHAP");
    const CFStringRef kSCValNetPPPAuthProtocolEAP                      = CFSTR("EAP");
    const CFStringRef kSCValNetPPPAuthProtocolMSCHAP1                  = CFSTR("MSCHAP1");
    const CFStringRef kSCValNetPPPAuthProtocolMSCHAP2                  = CFSTR("MSCHAP2");
    const CFStringRef kSCValNetPPPAuthProtocolPAP                      = CFSTR("PAP");
    const CFStringRef kSCPropNetPPPCommAlternateRemoteAddress          = CFSTR("CommAlternateRemoteAddress");
    const CFStringRef kSCPropNetPPPCommConnectDelay                    = CFSTR("CommConnectDelay");
    const CFStringRef kSCPropNetPPPCommDisplayTerminalWindow           = CFSTR("CommDisplayTerminalWindow");
    const CFStringRef kSCPropNetPPPCommRedialCount                     = CFSTR("CommRedialCount");
    const CFStringRef kSCPropNetPPPCommRedialEnabled                   = CFSTR("CommRedialEnabled");
    const CFStringRef kSCPropNetPPPCommRedialInterval                  = CFSTR("CommRedialInterval");
    const CFStringRef kSCPropNetPPPCommRemoteAddress                   = CFSTR("CommRemoteAddress");
    const CFStringRef kSCPropNetPPPCommTerminalScript                  = CFSTR("CommTerminalScript");
    const CFStringRef kSCPropNetPPPCommUseTerminalScript               = CFSTR("CommUseTerminalScript");
    const CFStringRef kSCPropNetPPPCCPEnabled                          = CFSTR("CCPEnabled");
    const CFStringRef kSCPropNetPPPCCPMPPE40Enabled                    = CFSTR("CCPMPPE40Enabled");
    const CFStringRef kSCPropNetPPPCCPMPPE128Enabled                   = CFSTR("CCPMPPE128Enabled");
    const CFStringRef kSCPropNetPPPIPCPCompressionVJ                   = CFSTR("IPCPCompressionVJ");
    const CFStringRef kSCPropNetPPPIPCPUsePeerDNS                      = CFSTR("IPCPUsePeerDNS");
    const CFStringRef kSCPropNetPPPLCPEchoEnabled                      = CFSTR("LCPEchoEnabled");
    const CFStringRef kSCPropNetPPPLCPEchoFailure                      = CFSTR("LCPEchoFailure");
    const CFStringRef kSCPropNetPPPLCPEchoInterval                     = CFSTR("LCPEchoInterval");
    const CFStringRef kSCPropNetPPPLCPCompressionACField               = CFSTR("LCPCompressionACField");
    const CFStringRef kSCPropNetPPPLCPCompressionPField                = CFSTR("LCPCompressionPField");
    const CFStringRef kSCPropNetPPPLCPMRU                              = CFSTR("LCPMRU");
    const CFStringRef kSCPropNetPPPLCPMTU                              = CFSTR("LCPMTU");
    const CFStringRef kSCPropNetPPPLCPReceiveACCM                      = CFSTR("LCPReceiveACCM");
    const CFStringRef kSCPropNetPPPLCPTransmitACCM                     = CFSTR("LCPTransmitACCM");
    const CFStringRef kSCPropNetPPPOnDemandDomains                     = CFSTR("OnDemandDomains");
    const CFStringRef kSCPropNetPPPOnDemandEnabled                     = CFSTR("OnDemandEnabled");
    const CFStringRef kSCPropNetPPPOnDemandHostName                    = CFSTR("OnDemandHostName");
    const CFStringRef kSCPropNetPPPOnDemandMatchDomainsAlways          = CFSTR("OnDemandMatchDomainsAlways");
    const CFStringRef kSCPropNetPPPOnDemandMatchDomainsOnRetry         = CFSTR("OnDemandMatchDomainsOnRetry");
    const CFStringRef kSCPropNetPPPOnDemandMatchDomainsNever           = CFSTR("OnDemandMatchDomainsNever");
    const CFStringRef kSCPropNetPPPOnDemandMode                        = CFSTR("OnDemandMode");
    const CFStringRef kSCPropNetPPPOnDemandPriority                    = CFSTR("OnDemandPriority");
    const CFStringRef kSCValNetPPPOnDemandModeAggressive               = CFSTR("Aggressive");
    const CFStringRef kSCValNetPPPOnDemandModeConservative             = CFSTR("Conservative");
    const CFStringRef kSCValNetPPPOnDemandModeCompatible               = CFSTR("Compatible");
    const CFStringRef kSCValNetPPPOnDemandPriorityDefault              = CFSTR("Default");
    const CFStringRef kSCValNetPPPOnDemandPriorityHigh                 = CFSTR("High");
    const CFStringRef kSCValNetPPPOnDemandPriorityLow                  = CFSTR("Low");
    const CFStringRef kSCPropNetL2TPIPSecSharedSecret                  = CFSTR("IPSecSharedSecret");
    const CFStringRef kSCPropNetL2TPIPSecSharedSecretEncryption        = CFSTR("IPSecSharedSecretEncryption");
    const CFStringRef kSCPropNetL2TPTransport                          = CFSTR("Transport");
    const CFStringRef kSCValNetL2TPIPSecSharedSecretEncryptionKeychain = CFSTR("Keychain");
    const CFStringRef kSCValNetL2TPTransportIP                         = CFSTR("IP");
    const CFStringRef kSCValNetL2TPTransportIPSec                      = CFSTR("IPSec");
    const CFStringRef kSCPropNetProxiesExceptionsList                  = CFSTR("ExceptionsList");
    const CFStringRef kSCPropNetProxiesExcludeSimpleHostnames          = CFSTR("ExcludeSimpleHostnames");
    const CFStringRef kSCPropNetProxiesFTPEnable                       = CFSTR("FTPEnable");
    const CFStringRef kSCPropNetProxiesFTPPassive                      = CFSTR("FTPPassive");
    const CFStringRef kSCPropNetProxiesFTPPort                         = CFSTR("FTPPort");
    const CFStringRef kSCPropNetProxiesFTPProxy                        = CFSTR("FTPProxy");
    const CFStringRef kSCPropNetProxiesGopherEnable                    = CFSTR("GopherEnable");
    const CFStringRef kSCPropNetProxiesGopherPort                      = CFSTR("GopherPort");
    const CFStringRef kSCPropNetProxiesGopherProxy                     = CFSTR("GopherProxy");
    const CFStringRef kSCPropNetProxiesHTTPEnable                      = CFSTR("HTTPEnable");
    const CFStringRef kSCPropNetProxiesHTTPPort                        = CFSTR("HTTPPort");
    const CFStringRef kSCPropNetProxiesHTTPProxy                       = CFSTR("HTTPProxy");
    const CFStringRef kSCPropNetProxiesHTTPSEnable                     = CFSTR("HTTPSEnable");
    const CFStringRef kSCPropNetProxiesHTTPSPort                       = CFSTR("HTTPSPort");
    const CFStringRef kSCPropNetProxiesHTTPSProxy                      = CFSTR("HTTPSProxy");
    const CFStringRef kSCPropNetProxiesRTSPEnable                      = CFSTR("RTSPEnable");
    const CFStringRef kSCPropNetProxiesRTSPPort                        = CFSTR("RTSPPort");
    const CFStringRef kSCPropNetProxiesRTSPProxy                       = CFSTR("RTSPProxy");
    const CFStringRef kSCPropNetProxiesSOCKSEnable                     = CFSTR("SOCKSEnable");
    const CFStringRef kSCPropNetProxiesSOCKSPort                       = CFSTR("SOCKSPort");
    const CFStringRef kSCPropNetProxiesSOCKSProxy                      = CFSTR("SOCKSProxy");
    const CFStringRef kSCPropNetProxiesProxyAutoConfigEnable           = CFSTR("ProxyAutoConfigEnable");
    const CFStringRef kSCPropNetProxiesProxyAutoConfigJavaScript       = CFSTR("ProxyAutoConfigJavaScript");
    const CFStringRef kSCPropNetProxiesProxyAutoConfigURLString        = CFSTR("ProxyAutoConfigURLString");
    const CFStringRef kSCPropNetProxiesProxyAutoDiscoveryEnable        = CFSTR("ProxyAutoDiscoveryEnable");
    const CFStringRef kSCPropNetProxiesBypassAllowed                   = CFSTR("BypassAllowed");
    const CFStringRef kSCPropNetProxiesFallBackAllowed                 = CFSTR("FallBackAllowed");
    const CFStringRef kSCPropNetProxiesSupplementalMatchDomains        = CFSTR("SupplementalMatchDomains");
    const CFStringRef kSCPropNetProxiesSupplementalMatchOrders         = CFSTR("SupplementalMatchOrders");
    const CFStringRef kSCPropNetProxiesServiceSpecific                 = CFSTR("ServiceSpecific");
    const CFStringRef kSCPropNetProxiesScoped                          = CFSTR("__SCOPED__");
    const CFStringRef kSCPropNetProxiesServices                        = CFSTR("__SERVICES__");
    const CFStringRef kSCPropNetProxiesSupplemental                    = CFSTR("__SUPPLEMENTAL__");
    const CFStringRef kSCPropNetProxiesSupplementalMatchDomain         = CFSTR("__MATCH_DOMAIN__");
    const CFStringRef kSCPropNetQoSMarkingAppleAudioVideoCalls         = CFSTR("QoSMarkingAppleAudioVideoCalls");
    const CFStringRef kSCPropNetQoSMarkingEnabled                      = CFSTR("QoSMarkingEnabled");
    const CFStringRef kSCPropNetQoSMarkingWhitelistedAppIdentifiers    = CFSTR("QoSMarkingWhitelistedAppIdentifiers");
    const CFStringRef kSCPropNetServicePrimaryRank                     = CFSTR("PrimaryRank");
    const CFStringRef kSCPropNetServiceServiceIndex                    = CFSTR("ServiceIndex");
    const CFStringRef kSCPropNetServiceUserDefinedName                 = CFSTR("UserDefinedName");
    const CFStringRef kSCValNetServicePrimaryRankFirst                 = CFSTR("First");
    const CFStringRef kSCValNetServicePrimaryRankLast                  = CFSTR("Last");
    const CFStringRef kSCValNetServicePrimaryRankNever                 = CFSTR("Never");
    const CFStringRef kSCValNetServicePrimaryRankScoped                = CFSTR("Scoped");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCPropNetSMBNetBIOSName                         = CFSTR("NetBIOSName");
    const CFStringRef kSCPropNetSMBNetBIOSNodeType                     = CFSTR("NetBIOSNodeType");
    const CFStringRef kSCPropNetSMBNetBIOSScope                        = CFSTR("NetBIOSScope");
    const CFStringRef kSCPropNetSMBWINSAddresses                       = CFSTR("WINSAddresses");
    const CFStringRef kSCPropNetSMBWorkgroup                           = CFSTR("Workgroup");
    const CFStringRef kSCValNetSMBNetBIOSNodeTypeBroadcast             = CFSTR("Broadcast");
    const CFStringRef kSCValNetSMBNetBIOSNodeTypePeer                  = CFSTR("Peer");
    const CFStringRef kSCValNetSMBNetBIOSNodeTypeMixed                 = CFSTR("Mixed");
    const CFStringRef kSCValNetSMBNetBIOSNodeTypeHybrid                = CFSTR("Hybrid");
#endif	// !TARGET_OS_IPHONE
    
    const CFStringRef kSCPropNetVPNAppRules                            = CFSTR("AppRules");
    const CFStringRef kSCPropNetVPNAuthCredentialPassword              = CFSTR("AuthCredentialPassword");
    const CFStringRef kSCPropNetVPNAuthName                            = CFSTR("AuthName");
    const CFStringRef kSCPropNetVPNAuthPassword                        = CFSTR("AuthPassword");
    const CFStringRef kSCPropNetVPNAuthPasswordEncryption              = CFSTR("AuthPasswordEncryption");
    const CFStringRef kSCPropNetVPNAuthPasswordPluginType              = CFSTR("AuthPasswordPluginType");
    const CFStringRef kSCPropNetVPNAuthenticationMethod                = CFSTR("AuthenticationMethod");
    const CFStringRef kSCPropNetVPNConnectTime                         = CFSTR("ConnectTime");
    const CFStringRef kSCPropNetVPNDisconnectOnFastUserSwitch          = CFSTR("DisconnectOnFastUserSwitch");
    const CFStringRef kSCPropNetVPNDisconnectOnIdle                    = CFSTR("DisconnectOnIdle");
    const CFStringRef kSCPropNetVPNDisconnectOnIdleTimer               = CFSTR("DisconnectOnIdleTimer");
    const CFStringRef kSCPropNetVPNDisconnectOnLogout                  = CFSTR("DisconnectOnLogout");
    const CFStringRef kSCPropNetVPNDisconnectOnSleep                   = CFSTR("DisconnectOnSleep");
    const CFStringRef kSCPropNetVPNDisconnectOnWake                    = CFSTR("DisconnectOnWake");
    const CFStringRef kSCPropNetVPNDisconnectOnWakeTimer               = CFSTR("DisconnectOnWakeTimer");
    const CFStringRef kSCPropNetVPNLocalCertificate                    = CFSTR("LocalCertificate");
    const CFStringRef kSCPropNetVPNLogfile                             = CFSTR("Logfile");
    const CFStringRef kSCPropNetVPNMTU                                 = CFSTR("MTU");
    const CFStringRef kSCPropNetVPNOnDemandEnabled                     = CFSTR("OnDemandEnabled");
    const CFStringRef kSCPropNetVPNOnDemandMatchAppEnabled             = CFSTR("OnDemandMatchAppEnabled");
    const CFStringRef kSCPropNetVPNOnDemandMatchDomainsAlways          = CFSTR("OnDemandMatchDomainsAlways");
    const CFStringRef kSCPropNetVPNOnDemandMatchDomainsOnRetry         = CFSTR("OnDemandMatchDomainsOnRetry");
    const CFStringRef kSCPropNetVPNOnDemandMatchDomainsNever           = CFSTR("OnDemandMatchDomainsNever");
    const CFStringRef kSCPropNetVPNOnDemandRules                       = CFSTR("OnDemandRules");
    const CFStringRef kSCPropNetVPNOnDemandSuspended                   = CFSTR("OnDemandSuspended");
    const CFStringRef kSCPropNetVPNPluginCapability                    = CFSTR("PluginCapability");
    const CFStringRef kSCPropNetVPNRemoteAddress                       = CFSTR("RemoteAddress");
    const CFStringRef kSCPropNetVPNStatus                              = CFSTR("Status");
    const CFStringRef kSCPropNetVPNVerboseLogging                      = CFSTR("VerboseLogging");
    const CFStringRef kSCValNetVPNAppRuleAccountIdentifierMatch        = CFSTR("AccountIdentifierMatch");
    const CFStringRef kSCValNetVPNAppRuleDNSDomainMatch                = CFSTR("DNSDomainMatch");
    const CFStringRef kSCValNetVPNAppRuleExecutableMatch               = CFSTR("ExecutableMatch");
    const CFStringRef kSCValNetVPNAppRuleIdentifier                    = CFSTR("Identifier");
    const CFStringRef kSCValNetVPNAppRuleExecutableDesignatedRequirement = CFSTR("DesignatedRequirement");
    const CFStringRef kSCValNetVPNAppRuleExecutableSigningIdentifier   = CFSTR("SigningIdentifier");
    const CFStringRef kSCValNetVPNAppRuleExecutableUUID                = CFSTR("UUID");
    const CFStringRef kSCValNetVPNAuthenticationMethodPassword         = CFSTR("Password");
    const CFStringRef kSCValNetVPNAuthenticationMethodCertificate      = CFSTR("Certificate");
    const CFStringRef kSCValNetVPNAuthPasswordEncryptionExternal       = CFSTR("External");
    const CFStringRef kSCValNetVPNAuthPasswordEncryptionKeychain       = CFSTR("Keychain");
    const CFStringRef kSCValNetVPNAuthPasswordEncryptionPrompt         = CFSTR("Prompt");
    const CFStringRef kSCPropNetVPNOnDemandRuleAction                  = CFSTR("Action");
    const CFStringRef kSCPropNetVPNOnDemandRuleActionParameters        = CFSTR("ActionParameters");
    const CFStringRef kSCPropNetVPNOnDemandRuleDNSDomainMatch          = CFSTR("DNSDomainMatch");
    const CFStringRef kSCPropNetVPNOnDemandRuleDNSServerAddressMatch   = CFSTR("DNSServerAddressMatch");
    const CFStringRef kSCPropNetVPNOnDemandRuleSSIDMatch               = CFSTR("SSIDMatch");
    const CFStringRef kSCPropNetVPNOnDemandRuleInterfaceTypeMatch      = CFSTR("InterfaceTypeMatch");
    const CFStringRef kSCPropNetVPNOnDemandRuleURLStringProbe          = CFSTR("URLStringProbe");
    const CFStringRef kSCValNetVPNOnDemandRuleActionAllow              = CFSTR("Allow");
    const CFStringRef kSCValNetVPNOnDemandRuleActionIgnore             = CFSTR("Ignore");
    const CFStringRef kSCValNetVPNOnDemandRuleActionConnect            = CFSTR("Connect");
    const CFStringRef kSCValNetVPNOnDemandRuleActionDisconnect         = CFSTR("Disconnect");
    const CFStringRef kSCValNetVPNOnDemandRuleActionEvaluateConnection = CFSTR("EvaluateConnection");
    const CFStringRef kSCPropNetVPNOnDemandRuleActionParametersDomainAction = CFSTR("DomainAction");
    const CFStringRef kSCPropNetVPNOnDemandRuleActionParametersDomains = CFSTR("Domains");
    const CFStringRef kSCPropNetVPNOnDemandRuleActionParametersRequiredDNSServers = CFSTR("RequiredDNSServers");
    const CFStringRef kSCPropNetVPNOnDemandRuleActionParametersRequiredURLStringProbe = CFSTR("RequiredURLStringProbe");
    const CFStringRef kSCValNetVPNOnDemandRuleActionParametersDomainActionConnectIfNeeded = CFSTR("ConnectIfNeeded");
    const CFStringRef kSCValNetVPNOnDemandRuleActionParametersDomainActionNeverConnect = CFSTR("NeverConnect");
    
    
    const CFStringRef kSCValNetVPNOnDemandRuleInterfaceTypeMatchEthernet = CFSTR("Ethernet");
    const CFStringRef kSCValNetVPNOnDemandRuleInterfaceTypeMatchWiFi   = CFSTR("WiFi");
    const CFStringRef kSCValNetVPNPluginCapabilityAuth                 = CFSTR("Auth");
    const CFStringRef kSCValNetVPNPluginCapabilityConnect              = CFSTR("Connect");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCEntUsersConsoleUser                           = CFSTR("ConsoleUser");
#endif	// !TARGET_OS_IPHONE
    
    const CFStringRef kSCPropSystemComputerName                        = CFSTR("ComputerName");
    const CFStringRef kSCPropSystemComputerNameEncoding                = CFSTR("ComputerNameEncoding");
    const CFStringRef kSCPropSystemComputerNameRegion                  = CFSTR("ComputerNameRegion");
    const CFStringRef kSCPropSystemHostName                            = CFSTR("HostName");
    const CFStringRef kSCDynamicStoreDomainFile                        = CFSTR("File:");
    const CFStringRef kSCDynamicStoreDomainPlugin                      = CFSTR("Plugin:");
    const CFStringRef kSCDynamicStoreDomainSetup                       = CFSTR("Setup:");
    const CFStringRef kSCDynamicStoreDomainState                       = CFSTR("State:");
    const CFStringRef kSCDynamicStoreDomainPrefs                       = CFSTR("Prefs:");
    const CFStringRef kSCDynamicStorePropSetupCurrentSet               = CFSTR("CurrentSet");
    const CFStringRef kSCDynamicStorePropSetupLastUpdated              = CFSTR("LastUpdated");
    const CFStringRef kSCDynamicStorePropNetInterfaces                 = CFSTR("Interfaces");
    const CFStringRef kSCDynamicStorePropNetPrimaryInterface           = CFSTR("PrimaryInterface");
    const CFStringRef kSCDynamicStorePropNetPrimaryService             = CFSTR("PrimaryService");
    const CFStringRef kSCDynamicStorePropNetServiceIDs                 = CFSTR("ServiceIDs");
    const CFStringRef kSCPropVirtualNetworkInterfacesBondInterfaces    = CFSTR("Interfaces");
    const CFStringRef kSCPropVirtualNetworkInterfacesBondMode          = CFSTR("Mode");
    const CFStringRef kSCPropVirtualNetworkInterfacesBondOptions       = CFSTR("Options");
    const CFStringRef kSCPropVirtualNetworkInterfacesBridgeInterfaces  = CFSTR("Interfaces");
    const CFStringRef kSCPropVirtualNetworkInterfacesBridgeOptions     = CFSTR("Options");
    const CFStringRef kSCPropVirtualNetworkInterfacesVLANInterface     = CFSTR("Interface");
    const CFStringRef kSCPropVirtualNetworkInterfacesVLANTag           = CFSTR("Tag");
    const CFStringRef kSCPropVirtualNetworkInterfacesVLANOptions       = CFSTR("Options");
    
#if	!TARGET_OS_IPHONE
    const CFStringRef kSCPropUsersConsoleUserName                      = CFSTR("Name");
    const CFStringRef kSCPropUsersConsoleUserUID                       = CFSTR("UID");
    const CFStringRef kSCPropUsersConsoleUserGID                       = CFSTR("GID");
    */
}

struct ppp_msg* create_msg(uint16_t type) {
    struct ppp_msg* msg = (struct ppp_msg*)malloc(sizeof(struct ppp_msg));
    
    memset(msg, '\0', sizeof(struct ppp_msg));
    
    msg->m_flags = 0;
    msg->m_type = type;
    msg->m_len = 0;
    msg->m_cookie = 0;
    msg->m_result = 0;
    msg->m_link = 0;
    return msg;
}

struct ppp_msg* send_ppp_msg(struct ppp_msg* msg) {
    int x = 0;
    struct ppp_msg_hdr hdr;
    struct ppp_msg* reply = NULL;
    memset(&hdr, '\0', sizeof(struct ppp_msg_hdr));
    
    printf("SEND\n");
    debug_ppp_msg(msg);
    x = send(gFd, msg, sizeof(struct ppp_msg_hdr), 0);
    if(x == sizeof(struct ppp_msg_hdr) && msg->m_len > 0) {
        x = send(gFd, msg->m_data, msg->m_len, 0);
    }
    
    x = recv(gFd, &hdr, sizeof(struct ppp_msg_hdr), 0);
    if(x == sizeof(struct ppp_msg_hdr)) {
        reply = (struct ppp_msg*)malloc(sizeof(struct ppp_msg_hdr)+hdr.m_len);
        memcpy(reply, &hdr, sizeof(struct ppp_msg_hdr));
        x = recv(gFd, reply->m_data, hdr.m_len, 0);
        printf("RECV\n");
        debug_ppp_msg(reply);
    }
    
    return reply;
    
}


struct ppp_msg* ppp_get_option(int option) {
    struct ppp_msg* msg = (struct ppp_msg*)malloc(sizeof(struct ppp_msg_hdr)+4);
    msg->m_cookie = 0;
    msg->m_flags = 0;
    msg->m_len = 0;
    msg->m_link = 0;
    msg->m_result = 0;
    msg->m_len = 4;
    msg->m_type = PPP_GETOPTION;
    uint32_t* idx = (uint32_t*)msg->m_data;
    *idx = option;
    return send_ppp_msg(msg);
}

struct ppp_msg* ppp_set_option(int option, int value) {
    struct ppp_msg* msg = (struct ppp_msg*)malloc(sizeof(struct ppp_msg_hdr)+4+4);
    msg->m_cookie = 0;
    msg->m_flags = 0;
    msg->m_len = 0;
    msg->m_link = 0;
    msg->m_result = 0;
    msg->m_len = 4;
    msg->m_type = PPP_SETOPTION;
    uint32_t* idx = (uint32_t*)msg->m_data;
    *idx = option;
    
    uint32_t* val = (uint32_t*)msg->m_data+4;
    *val = value;
    return send_ppp_msg(msg);
}

struct ppp_msg* ppp_set_option_str(int option, char* value) {
    struct ppp_msg* msg = (struct ppp_msg*) malloc(sizeof(struct ppp_msg_hdr) + strlen(value) + 4);
    msg->m_cookie = 0;
    msg->m_flags = 0;
    msg->m_link = 0;
    msg->m_result = 0;
    msg->m_type = PPP_SETOPTION;
    
    msg->m_len = strlen(value) + 4;
    uint32_t* idx = (uint32_t*)msg->m_data;
    *idx = option;
    strcpy(msg->m_data+4, value);
    return send_ppp_msg(msg);
}

struct ppp_msg* create_random_packet(int t) {
    struct ppp_msg* msg = NULL;
    int type = t ? t: random_int() % 15;
    switch (type) {
        case PPP_VERSION:
            msg = create_msg(PPP_VERSION);
            break;
        case PPP_STATUS:
            msg = create_msg(PPP_STATUS);
            break;
        case PPP_CONNECT:
            msg = create_msg(PPP_CONNECT);
            break;
        case PPP_DISCONNECT:
            msg = create_msg(PPP_DISCONNECT);
            break;
        case PPP_GETOPTION:
            msg = create_msg(PPP_GETOPTION);
            int option = random_int() % 31;
            switch(option) {
                case PPP_OPT_DEV_NAME:		// string
                    ppp_get_option(PPP_OPT_DEV_NAME);
                    break;
                case PPP_OPT_DEV_SPEED:			// 4 bytes
                    ppp_get_option(PPP_OPT_DEV_SPEED);
                    break;
                case PPP_OPT_DEV_CONNECTSCRIPT:		// string
                    ppp_get_option(PPP_OPT_DEV_CONNECTSCRIPT);
                    break;
                case PPP_OPT_COMM_IDLETIMER:		// 4 bytes
                    ppp_get_option( PPP_OPT_COMM_IDLETIMER);
                    break;
                case PPP_OPT_COMM_REMOTEADDR:		// string
                    ppp_get_option( PPP_OPT_COMM_REMOTEADDR);
                    break;
                case PPP_OPT_AUTH_PROTO:			// 4 bytes
                    ppp_get_option(PPP_OPT_AUTH_PROTO);
                    break;
                case PPP_OPT_AUTH_NAME:			// string
                    ppp_get_option(PPP_OPT_AUTH_NAME);
                    break;
                case PPP_OPT_AUTH_PASSWD:		// string
                    ppp_get_option(PPP_OPT_AUTH_PASSWD);
                    break;
                case PPP_OPT_LCP_HDRCOMP:		// 4 bytes
                    ppp_get_option(PPP_OPT_LCP_HDRCOMP);
                    break;
                case PPP_OPT_LCP_MRU:			// 4 bytes
                    ppp_get_option(PPP_OPT_LCP_MRU);
                    break;
                case PPP_OPT_LCP_MTU:			// 4 bytes
                    ppp_get_option(PPP_OPT_LCP_MTU);
                    break;
                case PPP_OPT_LCP_RCACCM:			// 4 bytes
                    ppp_get_option(PPP_OPT_LCP_RCACCM);
                    break;
                case PPP_OPT_LCP_TXACCM:			// 4 bytes
                    ppp_get_option(PPP_OPT_LCP_TXACCM);
                    break;
                case PPP_OPT_IPCP_HDRCOMP:		// 4 bytes
                    ppp_get_option(PPP_OPT_IPCP_HDRCOMP);
                    break;
                case PPP_OPT_IPCP_LOCALADDR:		// 4 bytes
                    ppp_get_option(PPP_OPT_IPCP_LOCALADDR);
                    break;
                case PPP_OPT_IPCP_REMOTEADDR:		// 4 bytes
                    ppp_get_option(PPP_OPT_IPCP_REMOTEADDR);
                    break;
                case PPP_OPT_LOGFILE:			// string
                    ppp_get_option(PPP_OPT_LOGFILE);
                    break;
                case PPP_OPT_COMM_REMINDERTIMER:		// 4 bytes
                    ppp_get_option(PPP_OPT_COMM_REMINDERTIMER);
                    break;
                case PPP_OPT_ALERTENABLE:		// 4 bytes
                    ppp_get_option(PPP_OPT_ALERTENABLE);
                    break;
                case PPP_OPT_LCP_ECHO:			// struct ppp_opt_echo
                    ppp_get_option(PPP_OPT_LCP_ECHO);
                    break;
                case PPP_OPT_COMM_CONNECTDELAY:		// 4 bytes
                    ppp_get_option(PPP_OPT_COMM_CONNECTDELAY);
                    break;
                case PPP_OPT_COMM_SESSIONTIMER:		// 4 bytes
                    ppp_get_option(PPP_OPT_COMM_SESSIONTIMER);
                    break;
                case PPP_OPT_COMM_TERMINALMODE:		// 4 bytes
                    ppp_get_option(PPP_OPT_COMM_TERMINALMODE);
                    break;
                case PPP_OPT_COMM_TERMINALSCRIPT:	// string. Additionnal connection script, once modem is connected
                    ppp_get_option(PPP_OPT_COMM_TERMINALSCRIPT);
                    break;
                case PPP_OPT_RESERVED1:			// place holder
                    break;
                case PPP_OPT_RESERVED2:			// place holder
                    break;
                case PPP_OPT_DEV_CONNECTSPEED:		// 4 bytes, actual connection speed
                    ppp_get_option(PPP_OPT_DEV_CONNECTSPEED);
                    break;
                case PPP_OPT_SERVICEID:			// string, name of the associated service in the cache
                    ppp_get_option(PPP_OPT_SERVICEID);
                    break;
                case PPP_OPT_IFNAME:			// string, name of the associated interface (ppp0, ...)
                    ppp_get_option(PPP_OPT_IFNAME);
                    break;
                case PPP_OPT_DEV_DIALMODE:		// 4 bytes, dial mode, applies to modem connection
                    ppp_get_option(PPP_OPT_DEV_DIALMODE);
                    break;
                case PPP_OPT_DIALONDEMAND:		// 4 bytes, is service configured for DialOnDemand ?
                    ppp_get_option(PPP_OPT_DIALONDEMAND);
                    break;
                default:
                    break;
                    
            }
            break;
        case PPP_SETOPTION:
            msg = create_msg(PPP_SETOPTION);
            option = random_int() % 31;
            switch(option) {
                case PPP_OPT_DEV_NAME:		// string
                    break;
                case PPP_OPT_DEV_SPEED:			// 4 bytes
                    ppp_set_option(PPP_OPT_DEV_SPEED, random_int());
                    break;
                case PPP_OPT_DEV_CONNECTSCRIPT:		// string
                    break;
                case PPP_OPT_COMM_IDLETIMER:		// 4 bytes
                    ppp_set_option( PPP_OPT_COMM_IDLETIMER, random_int());
                    break;
                case PPP_OPT_COMM_REMOTEADDR:		// string
                    break;
                case PPP_OPT_AUTH_PROTO:			// 4 bytes
                    ppp_set_option(PPP_OPT_AUTH_PROTO, random_int());
                    break;
                case PPP_OPT_AUTH_NAME:			// string
                    break;
                case PPP_OPT_AUTH_PASSWD:		// string
                    break;
                case PPP_OPT_LCP_HDRCOMP:		// 4 bytes
                    ppp_set_option(PPP_OPT_LCP_HDRCOMP, random_int());
                    break;
                case PPP_OPT_LCP_MRU:			// 4 bytes
                    ppp_set_option(PPP_OPT_LCP_MRU, random_int());
                    break;
                case PPP_OPT_LCP_MTU:			// 4 bytes
                    ppp_set_option(PPP_OPT_LCP_MTU, random_int());
                    break;
                case PPP_OPT_LCP_RCACCM:			// 4 bytes
                    ppp_set_option(PPP_OPT_LCP_RCACCM, random_int());
                    break;
                case PPP_OPT_LCP_TXACCM:			// 4 bytes
                    ppp_set_option(PPP_OPT_LCP_TXACCM, random_int());
                    break;
                case PPP_OPT_IPCP_HDRCOMP:		// 4 bytes
                    ppp_set_option(PPP_OPT_IPCP_HDRCOMP, random_int());
                    break;
                case PPP_OPT_IPCP_LOCALADDR:		// 4 bytes
                    ppp_set_option(PPP_OPT_IPCP_LOCALADDR, random_int());
                    break;
                case PPP_OPT_IPCP_REMOTEADDR:		// 4 bytes
                    ppp_set_option(PPP_OPT_IPCP_REMOTEADDR, random_int());
                    break;
                case PPP_OPT_LOGFILE:			// string
                    break;
                case PPP_OPT_COMM_REMINDERTIMER:		// 4 bytes
                    ppp_set_option(PPP_OPT_COMM_REMINDERTIMER, random_int());
                    break;
                case PPP_OPT_ALERTENABLE:		// 4 bytes
                    ppp_set_option(PPP_OPT_ALERTENABLE, random_int());
                    break;
                case PPP_OPT_LCP_ECHO:			// struct ppp_opt_echo
                    break;
                case PPP_OPT_COMM_CONNECTDELAY:		// 4 bytes
                    ppp_set_option(PPP_OPT_COMM_CONNECTDELAY, random_int());
                    break;
                case PPP_OPT_COMM_SESSIONTIMER:		// 4 bytes
                    ppp_set_option(PPP_OPT_COMM_SESSIONTIMER, random_int());
                    break;
                case PPP_OPT_COMM_TERMINALMODE:		// 4 bytes
                    ppp_set_option(PPP_OPT_COMM_TERMINALMODE, random_int());
                    break;
                case PPP_OPT_COMM_TERMINALSCRIPT:	// string. Additionnal connection script, once modem is connected
                    break;
                case PPP_OPT_RESERVED1:			// place holder
                    break;
                case PPP_OPT_RESERVED2:			// place holder
                    break;
                case PPP_OPT_DEV_CONNECTSPEED:		// 4 bytes, actual connection speed
                    ppp_set_option(PPP_OPT_DEV_CONNECTSPEED, random_int());
                    break;
                    // case PPP_OPT_SERVICEID:			// string, name of the associated service in the cache
                    //     break;
                    // case PPP_OPT_IFNAME:			// string, name of the associated interface (ppp0, ...)
                    //     break;
                    // case PPP_OPT_DEV_DIALMODE:		// 4 bytes, dial mode, applies to modem connection
                    //     break;
                    // case PPP_OPT_DIALONDEMAND:		// 4 bytes, is service configured for DialOnDemand ?
                    //     break;
                default:
                    break;
                    
            }
            break;
        case PPP_ENABLE_EVENT:
            msg = create_msg(PPP_ENABLE_EVENT);
            int evt = random_int() % 23;
            switch(evt) {
                case PPP_EVT_DISCONNECTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONNSCRIPT_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONNSCRIPT_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_TERMSCRIPT_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_TERMSCRIPT_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LOWERLAYER_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LOWERLAYER_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LCP_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LCP_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_IPCP_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_IPCP_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_FAILED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_SUCCEDED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_FAILED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_SUCCEDED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_DISC_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_DISC_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_STOPPED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONTINUED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_REQUEST_INSTALL:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_REQUEST_UNINSTALL:
                    ppp_set_option(evt, 1);
                    break;
                default:
                    break;
            }
            break;
        case PPP_DISABLE_EVENT:
            msg = create_msg(PPP_DISABLE_EVENT);
            evt = random_int() % 23;
            switch(evt) {
                case PPP_EVT_DISCONNECTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONNSCRIPT_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONNSCRIPT_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_TERMSCRIPT_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_TERMSCRIPT_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LOWERLAYER_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LOWERLAYER_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LCP_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_LCP_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_IPCP_UP:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_IPCP_DOWN:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_FAILED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_AUTH_SUCCEDED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_FAILED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONN_SUCCEDED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_DISC_STARTED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_DISC_FINISHED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_STOPPED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_CONTINUED:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_REQUEST_INSTALL:
                    ppp_set_option(evt, 1);
                    break;
                case PPP_EVT_REQUEST_UNINSTALL:
                    ppp_set_option(evt, 1);
                    break;
                default:
                    break;
            }
            break;
        case PPP_EVENT:
            break;
        case PPP_GETNBLINKS:
            msg = create_msg(PPP_GETNBLINKS);
            break;
        case PPP_GETLINKBYINDEX:
            msg = create_msg(PPP_GETLINKBYINDEX);
            break;
        case PPP_GETLINKBYSERVICEID:
            msg = create_msg(PPP_GETLINKBYSERVICEID);
            break;
        case PPP_GETLINKBYIFNAME:
            msg = create_msg(PPP_GETLINKBYIFNAME);
            break;
        case PPP_SUSPEND:
            msg = create_msg(PPP_SUSPEND);
            break;
        case PPP_RESUME:
            msg = create_msg(PPP_RESUME);
            break;
        case PPP_EXTENDEDSTATUS:
            msg = create_msg(PPP_EXTENDEDSTATUS);
            break;
        case PPP_GETCONNECTDATA:
            msg = create_msg(PPP_GETCONNECTDATA);
            break;
        default:
            break;
    }
    return msg;
}

int ppp_connect(void) {
    int x = 0;
    int fd = 0;
    struct sockaddr_un sun;
    memset((struct sockaddr_un*)&sun, '\0', sizeof(struct sockaddr_un));
    
    sun.sun_family = AF_UNIX;
    fd = socket(PF_LOCAL, SOCK_STREAM, 0);
    
    //int flags;
    //flags = fcntl(fd,F_GETFL,0);
    //fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    
    strncpy(sun.sun_path, PPP_PATH, sizeof(sun.sun_path));
    x = connect(fd, (struct sockaddr_un*)&sun, sizeof(sun));
    return fd;
}

void ppp_shutdown(int fd) {
    if(fd > 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
    }
}




int main(int argc, const char * argv[]) {
    srand(time(0));
    int seed = random_int();
    srand(seed);
    unsigned char buf[1028];
    memset(buf, '\0', sizeof(buf));
    
    printf("Connecting to pppconfd socket\n");
    gFd = ppp_connect();
    
    printf("Getting number of links\n");
    send_ppp_msg(create_msg(PPP_GETNBLINKS));
    
    printf("Getting device name option\n");
    ppp_get_option(PPP_OPT_DEV_NAME);
    
    printf("Setting device name option\n");
    ppp_set_option_str(PPP_OPT_DEV_NAME, "/dev/cu.serial1");
    
    printf("Getting device name option\n");
    ppp_get_option(PPP_OPT_DEV_NAME);
    
    while(1) {
        
        send_ppp_msg(create_msg(PPP_DISCONNECT));
        int i = 0;
        for(i = (random_int() % 10); i > 0; --i) {
            int len = 0;
        struct ppp_msg* msg = create_random_packet(0);
            if(msg) {
                len = msg->m_len;
                randomize_string((unsigned char*)msg, len, 0.1);
                msg->m_len = len;
                if(msg) {
                    int len = msg->m_len;
                    randomize_string((unsigned char*)msg, len, 0.1);
                    msg->m_len = len;
                }
            }
        msg = create_random_packet(PPP_GETOPTION);
        if(msg) {
        len = msg->m_len;
        randomize_string((unsigned char*)msg, len, 0.1);
        msg->m_len = len;
            struct ppp_msg* reply = send_ppp_msg(msg);
            if(reply) {
                if(reply->m_result != 0) {
                //i++;
                    continue;
                }
            
                
                reply->m_type = PPP_SETOPTION;
                reply->m_result = 0;
                randomize_string((unsigned char*)reply, len, 0.1);
                reply = send_ppp_msg(reply);
            }
        }
        send_ppp_msg(create_msg(PPP_CONNECT));
        }
    }
    
    printf("Getting connection script option\n");
    ppp_get_option(PPP_OPT_DEV_CONNECTSCRIPT);
    
    //printf("Setting connect script option\n");
    ppp_set_option_str(PPP_OPT_DEV_CONNECTSCRIPT, "/Users/posixninja/Desktop/pwn.ccl");
    
    printf("Getting connection script option\n");
    ppp_get_option(PPP_OPT_DEV_CONNECTSCRIPT);
    
    printf("Getting terminal script option\n");
    ppp_get_option(PPP_OPT_COMM_TERMINALSCRIPT);
    
    printf("Setting terminal script option\n");
    ppp_set_option_str(PPP_OPT_COMM_TERMINALSCRIPT, "/Users/posixninja/Desktop/test.ccl");
    
    printf("Getting terminal script option\n");
    ppp_get_option(PPP_OPT_COMM_TERMINALSCRIPT);
    
    printf("Connecting to pppd\n");
    send_ppp_msg(create_msg(PPP_CONNECT));
    
    printf("Shutting down socket\n");
    ppp_shutdown(gFd);
    return 0;
}
