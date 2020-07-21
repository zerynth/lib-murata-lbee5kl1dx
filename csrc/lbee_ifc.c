/*
* @Author: lorenzo
* @Date:   2019-02-06 15:54:08
* @Last Modified by:   l.rizzello
* @Last Modified time: 2019-04-12 16:33:02
*/

#include "platform_mcu_peripheral.h"
#include "wiced_platform.h"
#include "platform.h"

#include "lwip/opt.h"
#include "lwip/icmp.h"
#include "lwip/inet_chksum.h"
#include "lwip/mem.h"
#include "lwip/inet.h"
#include "netif/etharp.h"
#include "lwip/tcpip.h"
#include "lwip/prot/dhcp.h"
#include "lwip/dhcp.h"
#include "wwd_network.h"

#include "zerynth_sockets.h"

#define ZERYNTH_PRINTF
#include "zerynth.h"

#define ZER_AUTH_WIFI_OPEN  0
#define ZER_AUTH_WIFI_WEP  1
#define ZER_AUTH_WIFI_WPA  2
#define ZER_AUTH_WIFI_WPA2  3

wiced_security_t zerynth_2_wiced_security[] = {
  WICED_SECURITY_OPEN,
  WICED_SECURITY_WEP_SHARED,
  WICED_SECURITY_WPA_MIXED_PSK,
  WICED_SECURITY_WPA2_MIXED_PSK
};

#pragma pack(push)  /* push current alignment to stack */
#pragma pack(4)     /* set alignment to 4 byte boundary */

typedef struct _lbee_drv_data {
    VSemaphore wwd_lock;
    wiced_mac_t mac_address;
    struct netif wiced_if;
    struct dhcp netif_dhcp;
    ip_addr_t net_ip;
    ip_addr_t net_mask;
    ip_addr_t net_gw;
    ip_addr_t net_dns;
    uint8_t static_ip;
} lbee_drv_data_t;

lbee_drv_data_t lbee_drv_data;
#pragma pack(pop)   /* restore original alignment from stack */
SocketAPIPointers lbee_api;

wiced_scan_result_t result_buff[1];
typedef struct scan_udata {
    VEvent scan_event;
    PDict *scan_dict;
} lbee_scan_data_t;

static void scan_results_handler( wiced_scan_result_t** result_ptr, void* user_data, wiced_scan_status_t status ) {
    lbee_scan_data_t *scan_data = (lbee_scan_data_t*) user_data;

    if ( result_ptr == NULL ) {
        vosEventSet(scan_data->scan_event);
        return;
    }

    wiced_scan_result_t* record = ( *result_ptr );

    PBytes *bssid = pbytes_new(6, record->BSSID.octet);
    if (pdict_get(scan_data->scan_dict, bssid)) {
        return;
    }

    int sec = -1;
    if (record->security == WICED_SECURITY_OPEN)
        sec = ZER_AUTH_WIFI_OPEN;
    else if (record->security & WICED_SECURITY_WPA_MIXED_PSK)
        sec = ZER_AUTH_WIFI_WPA;
    else if (record->security & WICED_SECURITY_WPA2_MIXED_PSK)
        sec = ZER_AUTH_WIFI_WPA2;
    else if (record->security & WICED_SECURITY_WEP_SHARED)
        sec = ZER_AUTH_WIFI_WEP;
    else return;

    PTuple * scan_element = ptuple_new(4, NULL);
    PTUPLE_SET_ITEM(scan_element, 0, pstring_new(record->SSID.length, record->SSID.value));
    PTUPLE_SET_ITEM(scan_element, 1, PSMALLINT_NEW(sec));
    PTUPLE_SET_ITEM(scan_element, 2, PSMALLINT_NEW(record->signal_strength));
    PTUPLE_SET_ITEM(scan_element, 3, bssid);
    pdict_put(scan_data->scan_dict, bssid, scan_element);
}

static void tcpip_init_done( void * arg ) {
    VEvent tcpip_init_event = (VEvent) arg;
    vosEventSet(tcpip_init_event);
}

C_NATIVE(_lbee_init) {
    NATIVE_UNWARN();
    wiced_country_code_t wiced_country;
    uint8_t *cntry;
    uint32_t cntrylen;

    if (parse_py_args("s", nargs, args, &cntry, &cntrylen) != 1)
        return ERR_TYPE_EXC;

    if (cntrylen >= 2) {
        wiced_country = MK_CNTRY(cntry[0], cntry[1], (cntrylen >= 3) ? (cntry[2] - '0') : 0);
    } else {
        return ERR_TYPE_EXC;
    }

    vhalInitSDIO(NULL);

    VEvent tcpip_init_event = vosEventCreate();
    tcpip_init( tcpip_init_done, (void*) tcpip_init_event);
    vosEventWait(tcpip_init_event, VTIME_INFINITE);
    vosEventClear(tcpip_init_event);
    vosEventDestroy(tcpip_init_event);

    wwd_result_t wres = wwd_management_wifi_on( wiced_country );
    if (WWD_SUCCESS !=  wres) {
        return ERR_TYPE_EXC;
    }

    wwd_wifi_set_up();
    wwd_wifi_get_mac_address( &lbee_drv_data.mac_address, WWD_STA_INTERFACE );
    wwd_wifi_disable_powersave();

    lbee_drv_data.static_ip = 0;
    lbee_drv_data.wwd_lock = vosSemCreate(1);

    //setup Z sockets
    lbee_api.socket = lwip_socket;
    lbee_api.connect = lwip_connect;
    lbee_api.setsockopt = lwip_setsockopt;
    lbee_api.getsockopt = lwip_getsockopt;
    lbee_api.send = lwip_send;
    lbee_api.sendto = lwip_sendto;
    lbee_api.write = lwip_write;
    lbee_api.recv = lwip_recv;
    lbee_api.recvfrom = lwip_recvfrom;
    lbee_api.read = lwip_read;
    lbee_api.close = lwip_close;
    lbee_api.shutdown = lwip_shutdown;
    lbee_api.bind = lwip_bind;
    lbee_api.accept = lwip_accept;
    lbee_api.listen = lwip_listen;
    lbee_api.select = lwip_select;
    lbee_api.fcntl = lwip_fcntl;
    lbee_api.ioctl = lwip_ioctl;
    lbee_api.getaddrinfo = lwip_getaddrinfo;
    lbee_api.freeaddrinfo = lwip_freeaddrinfo;
    lbee_api.inet_addr = ipaddr_addr;
    lbee_api.inet_ntoa = ip4addr_ntoa;

    gzsock_init(&lbee_api);

    return ERR_OK;
}

int32_t do_wifi_link(uint8_t *ssid, int32_t sidlen, uint8_t* password, int32_t passlen, int32_t sec) {
    wiced_ssid_t ap_ssid;
    wwd_result_t result;

    ap_ssid.length = sidlen;
    memcpy(ap_ssid.value, ssid, sidlen);
    wwd_wifi_select_antenna(WICED_ANTENNA_AUTO);
    if ( (result = wwd_wifi_join( &ap_ssid, zerynth_2_wiced_security[sec], password, passlen, NULL, WWD_STA_INTERFACE )) != WWD_SUCCESS ) {
        return ERR_IOERROR_EXC;
    } 

    if (netif_dhcp_data(&lbee_drv_data.wiced_if) != NULL) {
        dhcp_release(&lbee_drv_data.wiced_if);
        dhcp_stop(&lbee_drv_data.wiced_if);
    }

    if (!lbee_drv_data.static_ip) {
        ip_addr_set_zero( &lbee_drv_data.net_gw );
        ip_addr_set_zero( &lbee_drv_data.net_ip );
        ip_addr_set_zero( &lbee_drv_data.net_mask );
    }

    if ( NULL == netif_add( &lbee_drv_data.wiced_if, 
                            &lbee_drv_data.net_ip, &lbee_drv_data.net_mask, &lbee_drv_data.net_gw,
                            (void*) WWD_STA_INTERFACE, 
                            ethernetif_init, ethernet_input) ) {
        return ERR_IOERROR_EXC;
    }

    if (!lbee_drv_data.static_ip) {
        /* Bring up the network interface */
        netif_set_up( &lbee_drv_data.wiced_if );
        netif_set_default( &lbee_drv_data.wiced_if );

        dhcp_set_struct( &lbee_drv_data.wiced_if, &lbee_drv_data.netif_dhcp );

        dhcp_start( &lbee_drv_data.wiced_if );
        int cnt = 0;
        while ( lbee_drv_data.netif_dhcp.state != DHCP_STATE_BOUND ) {
            sys_msleep(60);
            cnt += 1;
            if (cnt > 100) {
                dhcp_stop(&lbee_drv_data.wiced_if);
                netif_remove(&lbee_drv_data.wiced_if);
                return ERR_IOERROR_EXC;
            }
        }

    }
    else {
        netif_set_up( &lbee_drv_data.wiced_if );
        netif_set_default( &lbee_drv_data.wiced_if );
        if (!lbee_drv_data.net_dns.addr) {
            OAL_MAKE_IP(lbee_drv_data.net_dns.addr, 8, 8, 8, 8);
        }
        dns_setserver(0, lbee_drv_data.net_dns);
    }

    return ERR_OK;
}

C_NATIVE(lbee_wifi_link) {
    C_NATIVE_UNWARN();
    uint8_t *ssid;
    int sidlen, sec, passlen;
    uint8_t *password;
    int32_t err;

    *res = MAKE_NONE();

    if (parse_py_args("sis", nargs, args, &ssid, &sidlen, &sec, &password, &passlen) != 3)
        return ERR_TYPE_EXC;

    RELEASE_GIL();
    vosSemWait(lbee_drv_data.wwd_lock);
    err = do_wifi_link(ssid, sidlen, password, passlen, sec);
    vosSemSignal(lbee_drv_data.wwd_lock);
    ACQUIRE_GIL();

    return err;
}

C_NATIVE(lbee_wifi_unlink) {
    NATIVE_UNWARN();
    *res = MAKE_NONE();

    RELEASE_GIL();
    vosSemWait(lbee_drv_data.wwd_lock);

    if (!lbee_drv_data.static_ip && lbee_drv_data.netif_dhcp.state != DHCP_STATE_BOUND) {
        dhcp_release(&lbee_drv_data.wiced_if);
        dhcp_stop(&lbee_drv_data.wiced_if);
    }
    netif_remove(&lbee_drv_data.wiced_if);
    wwd_result_t result = wwd_wifi_leave( WWD_STA_INTERFACE );

    vosSemSignal(lbee_drv_data.wwd_lock);
    ACQUIRE_GIL();

    if (result == WWD_SUCCESS) {
        return ERR_OK;
    }
    return ERR_IOERROR_EXC;
}


C_NATIVE(lbee_link_info) {
    NATIVE_UNWARN();

    NetAddress addr;
    addr.port = 0;
    vosSemWait(lbee_drv_data.wwd_lock);

    PTuple *tpl = psequence_new(PTUPLE, 5);

    if (lbee_drv_data.static_ip) {
        addr.ip = lbee_drv_data.net_ip.addr;
        PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
        addr.ip = lbee_drv_data.net_mask.addr;
        PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
        addr.ip = lbee_drv_data.net_gw.addr;
        PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
        addr.ip = lbee_drv_data.net_dns.addr;
        PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));
    }
    else {
        addr.ip = lbee_drv_data.wiced_if.ip_addr.addr;
        PTUPLE_SET_ITEM(tpl, 0, netaddress_to_object(&addr));
        addr.ip = lbee_drv_data.wiced_if.netmask.addr;
        PTUPLE_SET_ITEM(tpl, 1, netaddress_to_object(&addr));
        addr.ip = lbee_drv_data.wiced_if.gw.addr;
        PTUPLE_SET_ITEM(tpl, 2, netaddress_to_object(&addr));
        addr.ip = dns_getserver(0);
        PTUPLE_SET_ITEM(tpl, 3, netaddress_to_object(&addr));
    }

    PObject *mac = psequence_new(PBYTES, 6);
    memcpy(PSEQUENCE_BYTES(mac), lbee_drv_data.mac_address.octet, 6);
    PTUPLE_SET_ITEM(tpl, 4, mac);
    *res = tpl;

    vosSemSignal(lbee_drv_data.wwd_lock);
    return ERR_OK;
}


C_NATIVE(lbee_set_link_info) {
    C_NATIVE_UNWARN();

    NetAddress ip;
    NetAddress mask;
    NetAddress gw;
    NetAddress dns;

    if (parse_py_args("nnnn", nargs, args,
                      &ip,
                      &mask,
                      &gw,
                      &dns) != 4) return ERR_TYPE_EXC;

    if (dns.ip == 0) {
        OAL_MAKE_IP(dns.ip, 8, 8, 8, 8);
    }
    if (mask.ip == 0) {
        OAL_MAKE_IP(mask.ip, 255, 255, 255, 255);
    }
    if (gw.ip == 0) {
        OAL_MAKE_IP(gw.ip, OAL_IP_AT(ip.ip, 0), OAL_IP_AT(ip.ip, 1), OAL_IP_AT(ip.ip, 2), 1);
    }

    lbee_drv_data.static_ip = 1;
    lbee_drv_data.net_ip.addr = ip.ip;
    lbee_drv_data.net_gw.addr = gw.ip;
    lbee_drv_data.net_dns.addr = dns.ip;
    lbee_drv_data.net_mask.addr = mask.ip;

    *res = MAKE_NONE();
    return ERR_OK;
}

C_NATIVE(lbee_wifi_is_linked) {
    C_NATIVE_UNWARN();

    RELEASE_GIL();
    vosSemWait(lbee_drv_data.wwd_lock);
    wwd_result_t  result = wwd_wifi_is_ready_to_transceive(WWD_STA_INTERFACE);
    if (result == WWD_SUCCESS && !lbee_drv_data.static_ip &&
        lbee_drv_data.netif_dhcp.state != DHCP_STATE_BOUND) {
        // if DHCP check also if ip is assigned
        result = WWD_WLAN_ERROR;
    }
    vosSemSignal(lbee_drv_data.wwd_lock);
    ACQUIRE_GIL();

    *res = (result == WWD_SUCCESS) ? (PBOOL_TRUE()) : (PBOOL_FALSE());
    return ERR_OK;
}

C_NATIVE(lbee_scan) {
    C_NATIVE_UNWARN();
    int32_t time;
    int32_t i;

    if (parse_py_args("i", nargs, args, &time) != 1)
        return ERR_TYPE_EXC;

    lbee_scan_data_t scan_data;
    scan_data.scan_event = vosEventCreate();
    scan_data.scan_dict = pdict_new(16);

    wiced_scan_result_t* result_ptr = (wiced_scan_result_t *) &result_buff;

    RELEASE_GIL();
    vosSemWait(lbee_drv_data.wwd_lock);

    if ( WWD_SUCCESS != wwd_wifi_scan( WICED_SCAN_TYPE_ACTIVE, WICED_BSS_TYPE_ANY, NULL, NULL, NULL, NULL, scan_results_handler, (wiced_scan_result_t **) &result_ptr, &scan_data, WWD_STA_INTERFACE ) ) {
        vosEventDestroy(scan_data.scan_event);
        ACQUIRE_GIL();
        return ERR_IOERROR_EXC;
    }
    vosEventWait(scan_data.scan_event, VTIME_INFINITE);
    vosEventClear(scan_data.scan_event);
    /* Wait until scan is complete */
    wwd_wifi_abort_scan();
    vosSemSignal(lbee_drv_data.wwd_lock);
    ACQUIRE_GIL();
    vosEventDestroy(scan_data.scan_event);


    *res = ptuple_new(PDICT_ELEMENTS(scan_data.scan_dict), NULL);
    GC_START_STAGING();
    for (i = 0; i < PDICT_ELEMENTS(scan_data.scan_dict); i++) {
        PObject *tpl = PDICT_VAL(scan_data.scan_dict, i);
        GC_UNSTAGE(tpl); //must be unstaged, it was created in a non Python thread
        GC_UNSTAGE(PTUPLE_ITEM(tpl, 0));
        GC_UNSTAGE(PTUPLE_ITEM(tpl, 3));
        PTUPLE_SET_ITEM(*res, i, tpl);
    }
    GC_STOP_STAGING();

    return ERR_OK;
}

typedef struct sockaddr_in sockaddr_t;
static inline void zeraddr_to_sockaddr(sockaddr_t* sockaddr, NetAddress* zeraddr)
{
    sockaddr->sin_family = AF_INET;
    sockaddr->sin_port = zeraddr->port;
    sockaddr->sin_addr.s_addr = zeraddr->ip;
}
