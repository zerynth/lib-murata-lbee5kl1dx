#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "network/wwd_network_constants.h"

#define MEM_ALIGNMENT           4

#define TCP_MSS                 (WICED_PAYLOAD_MTU-20-20)

#define TCP_SND_BUF             (3 * TCP_MSS)
#define TCP_SND_QUEUELEN        8

#define TCP_WND                 (2 * TCP_MSS)

// !!! Without this appending sdpcm header fails and no lwip packet is going to be sent
#define PBUF_LINK_HLEN                 (WICED_PHYSICAL_HEADER)

/**
 * LWIP_NETIF_TX_SINGLE_PBUF: if this is set to 1, lwIP tries to put all data
 * to be sent into one single pbuf. This is for compatibility with DMA-enabled
 * MACs that do not support scatter-gather.
 * Beware that this might involve CPU-memcpy before transmitting that would not
 * be needed without this flag! Use this only if you need to!
 *
 * @todo: TCP and IP-frag do not work with this, yet:
 */
/* TODO: remove this option once buffer chaining has been implemented */
// #define LWIP_NETIF_TX_SINGLE_PBUF      (1)

/** LWIP_SUPPORT_CUSTOM_PBUF==1: Custom pbufs behave much like their pbuf type
 * but they are allocated by external code (initialised by calling
 * pbuf_alloced_custom()) and when pbuf_free gives up their last reference, they
 * are freed by calling pbuf_custom->custom_free_function().
 * Currently, the pbuf_custom code is only needed for one specific configuration
 * of IP_FRAG, unless required by external driver/application code. */
// #define LWIP_SUPPORT_CUSTOM_PBUF        1

#define LWIP_COMPAT_MUTEX_ALLOWED      (1)
#define LWIP_COMPAT_MUTEX              (1)

#define TCPIP_THREAD_STACKSIZE  1024
#define DEFAULT_THREAD_STACKSIZE 1024

/**
 * TCPIP_THREAD_PRIO: The priority assigned to the main tcpip thread.
 * The priority value itself is platform-dependent, but is passed to
 * sys_thread_new() when the thread is created.
 */
#define TCPIP_THREAD_PRIO              (VOS_PRIO_HIGH)

#define LWIP_PROVIDE_ERRNO             (1)

/* ARP before DHCP causes multi-second delay  - turn it off */
#define DHCP_DOES_ARP_CHECK            (0)

/**
 * ARP_QUEUEING==1: Multiple outgoing packets are queued during hardware address
 * resolution. By default, only the most recent packet is queued per IP address.
 * This is sufficient for most protocols and mainly reduces TCP connection
 * startup time. Set this to 1 if you know your application sends more than one
 * packet in a row to an IP address that is not in the ARP cache.
 */
/* ARP Queue size needs to be reduced to avoid using up all PBUFs when SoftAP is in use under load in busy environments */
#define ARP_QUEUEING                   (1)

/**
 * MEMP_NUM_ARP_QUEUE: the number of simultaneously queued outgoing
 * packets (pbufs) that are waiting for an ARP request (to resolve
 * their destination address) to finish.
 * (requires the ARP_QUEUEING option)
 */
#define MEMP_NUM_ARP_QUEUE              5

/**
 * LWIP_SO_RCVTIMEO==1: Enable receive timeout for sockets/netconns and
 * SO_RCVTIMEO processing.
 */
#define LWIP_SO_RCVTIMEO               (1)

#define LWIP_RAND()                    (vhalRngGenerate())

/**
 * LWIP_TCP_KEEPALIVE==1: Enable TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT
 * options processing. Note that TCP_KEEPIDLE and TCP_KEEPINTVL have to be set
 * in seconds. (does not require sockets.c, and will affect tcp.c)
 */
#define LWIP_TCP_KEEPALIVE             (1)


#define MEM_USE_POOLS (0)
#define MEMP_SEPARATE_POOLS             (0)

#define NO_SYS                  0
#define LWIP_SOCKET             1
#define LWIP_NETCONN            1
#define SYS_LIGHTWEIGHT_PROT    1

#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1


#define TCPIP_MBOX_SIZE             8
#define DEFAULT_TCP_RECVMBOX_SIZE   8
#define DEFAULT_UDP_RECVMBOX_SIZE   8
#define DEFAULT_RAW_RECVMBOX_SIZE   8
#define DEFAULT_ACCEPTMBOX_SIZE     8

#define MEM_SIZE                8 * 1024

#define PBUF_POOL_SIZE          8
#define PBUF_POOL_BUFSIZE       (LWIP_MEM_ALIGN_SIZE(WICED_LINK_MTU) + LWIP_MEM_ALIGN_SIZE(sizeof(struct pbuf)) + 1)

#define PBUF_POOL_TX_SIZE                 (3)
#define PBUF_POOL_RX_SIZE                 (3)
#define MEMP_NUM_PBUF                   ( PBUF_POOL_TX_SIZE + PBUF_POOL_RX_SIZE + 2 )


#define LWIP_DHCP               1
#define LWIP_DNS                1
#define LWIP_UDP                1
#define LWIP_TCP                1


#if 0
#define LWIP_DEBUG
#define DHCP_DEBUG                     (LWIP_DBG_ON)
#define UDP_DEBUG                      (LWIP_DBG_ON)
#define IP_DEBUG                       (LWIP_DBG_ON)
#define DNS_DEBUG                      (LWIP_DBG_ON)
#define TCPIP_DEBUG                    (LWIP_DBG_ON)
#define PBUF_DEBUG                     (LWIP_DBG_ON)

#define MEM_DEBUG                      (LWIP_DBG_ON)
#define MEMP_DEBUG                     (LWIP_DBG_ON)

#define API_LIB_DEBUG                  (LWIP_DBG_ON)
#define API_MSG_DEBUG                  (LWIP_DBG_ON)
#define NETIF_DEBUG                    (LWIP_DBG_ON)
#define SOCKETS_DEBUG                  (LWIP_DBG_ON)
#define DEMO_DEBUG                     (LWIP_DBG_ON)
#define IP_REASS_DEBUG                 (LWIP_DBG_ON)
#define RAW_DEBUG                      (LWIP_DBG_ON)
#define ICMP_DEBUG                     (LWIP_DBG_ON)
#define TCP_DEBUG                      (LWIP_DBG_ON)
#define TCP_INPUT_DEBUG                (LWIP_DBG_ON)
#define TCP_OUTPUT_DEBUG               (LWIP_DBG_ON)
#define TCP_RTO_DEBUG                  (LWIP_DBG_ON)
#define TCP_CWND_DEBUG                 (LWIP_DBG_ON)
#define TCP_WND_DEBUG                  (LWIP_DBG_ON)
#define TCP_FR_DEBUG                   (LWIP_DBG_ON)
#define TCP_QLEN_DEBUG                 (LWIP_DBG_ON)
#define TCP_RST_DEBUG                  (LWIP_DBG_ON)
#define PPP_DEBUG                      (LWIP_DBG_ON)
#define ETHARP_DEBUG                   (LWIP_DBG_ON)
#define IGMP_DEBUG                     (LWIP_DBG_ON)
#define INET_DEBUG                     (LWIP_DBG_ON)
#define SYS_DEBUG                      (LWIP_DBG_ON)
#define TIMERS_DEBUG                   (LWIP_DBG_ON)
#define SLIP_DEBUG                     (LWIP_DBG_ON)
#define AUTOIP_DEBUG                   (LWIP_DBG_ON)
#define SNMP_MSG_DEBUG                 (LWIP_DBG_ON)
#define SNMP_MIB_DEBUG                 (LWIP_DBG_ON)
#endif

#ifdef __cplusplus
}
#endif
#endif /* __LWIPOPTS_H__ */

