"""
.. module:: lbee5kl1dx

*****************
LBEE5KL1DX Module
*****************

This module implements the lbee5kl1dx wifi driver. At the moment some functionalities are missing:

    * soft ap
    * wifi direct

It can be used with Cypress PSoC6 WiFi-BT Pioneer Kit.
``lbee5kl1dx`` communication is based on the SDIO standard.

TLS support is available by means of Zeynth mbedTLS integration.
To enable it and allow the creation of TLS sockets using the Zerynth ``ssl`` module, place ``ZERYNTH_SSL: true`` inside your project ``project.yml`` file.

    """

@native_c("_lbee_init", 
    [
        "csrc/lbee_ifc.c",
        "csrc/43xxx_Wi-Fi/WICED/WWD/internal/*",
        "csrc/43xxx_Wi-Fi/WICED/WWD/internal/chips/4343x/*",
        "csrc/43xxx_Wi-Fi/WICED/WWD/internal/bus_protocols/SDIO/wwd_bus_protocol.c",
        "csrc/43xxx_Wi-Fi/WICED/WWD/internal/bus_protocols/wwd_bus_common.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/WWD/*",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/dns.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/init.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ip.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/dhcp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/autoip.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/icmp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/igmp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/ip4.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/ip4_addr.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/ip4_frag.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/ipv4/etharp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/inet_chksum.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/def.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/mem.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/memp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/netif.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/pbuf.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/raw.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/stats.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/sys.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/timeouts.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/tcp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/tcp_in.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/tcp_out.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/core/udp.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/netif/ethernet.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/api_lib.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/api_msg.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/err.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/netbuf.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/netdb.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/netifapi.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/sockets.c",
        "csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/api/tcpip.c",
        "csrc/43xxx_Wi-Fi/WICED/internal/wiced_smaller_lib.c",
        "csrc/43xxx_Wi-Fi/WICED/platform/MCU/platform_resource.c",
        "csrc/43xxx_Wi-Fi/WICED/platform/MCU/wwd_resources.c",
        "csrc/43xxx_Wi-Fi/libraries/utilities/TLV/*",
        "csrc/resources/4343WA1_bin.c",
        "csrc/resources/4343WA1_clm_blob.c",
        "csrc/WICED_port/WICED/RTOS/Zerynth/WWD/wwd_rtos.c",
        "csrc/WICED_port/WICED/network/LwIP/WWD/Zerynth/sys_arch.c",
        "csrc/WICED_port/zerynth_host_platform.c",
        "#csrc/misc/zstdlib.c",
        "#csrc/zsockets/*",
#-if ZERYNTH_SSL
        "#csrc/tls/mbedtls/library/*",
#-endif
    ],
    [
        "VHAL_SDIO",
        "VHAL_WWD_SDIO",
        "WWD_DOWNLOAD_CLM_BLOB",
        "WICED_DISABLE_BOOTLOADER",
        "WICED_DISABLE_MCU_POWERSAVE",
    ],
    [
        "-I.../csrc/WICED_port/WICED/network/LwIP/WWD/Zerynth",
        "-I.../csrc/WICED_port/WICED/RTOS/Zerynth/WICED",
        "-I.../csrc/WICED_port/WICED/RTOS/Zerynth/WWD",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD/internal/chips/4343x",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD/internal/bus_protocols/SDIO",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD/include",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD/include/RTOS",
        "-I.../csrc/43xxx_Wi-Fi/WICED/WWD/include/network",
        "-I.../csrc/43xxx_Wi-Fi/WICED/platform/include",
        "-I.../csrc/43xxx_Wi-Fi/WICED/platform/ARM_CM4",
        "-I.../csrc/43xxx_Wi-Fi/WICED/platform/MCU",
        "-I.../csrc/43xxx_Wi-Fi/WICED/platform/GCC",
        "-I.../csrc/43xxx_Wi-Fi/WICED/network/LwIP/WWD",
        "-I.../csrc/43xxx_Wi-Fi/WICED/network/LwIP/ver2.0.3/src/include",
        "-I.../csrc/43xxx_Wi-Fi/WICED/security/BESL/include",
        "-I.../csrc/43xxx_Wi-Fi/libraries/utilities/TLV",
        "-I.../csrc/43xxx_Wi-Fi/libraries/utilities/ring_buffer",
        "-I.../csrc/43xxx_Wi-Fi/platforms",
        "-I.../csrc/43xxx_Wi-Fi/platforms/CY8CKIT_062",
        "-I.../csrc/43xxx_Wi-Fi/include",
        "-I.../csrc/43xxx_Wi-Fi",
        "-I.../csrc/resources",
        "-I.../csrc/inc",
        "-I#csrc/zsockets",
#-if ZERYNTH_SSL
        "-I#csrc/tls/mbedtls/include",
#-endif
    ])
def _hw_init(country):
    pass

def init(country):
    """
.. function:: init(country)

        :param contry: two-letter country code

        Tries to init the lbee5kl1dx driver.

        :raises PeripheralError: in case of failed initialization
    """
    _hw_init(country)
    __builtins__.__default_net["wifi"] = __module__
    __builtins__.__default_net["sock"][0] = __module__ #AF_INET
    __builtins__.__default_net["ssl"] = __module__

def auto_init(country="US"):
    """
.. function:: auto_init(country="US")

        :param contry: two-letter country code

        Tries to automatically init the lbee5kl1dx driver by looking at the device type.

        :raises PeripheralError: in case of failed initialization
    """
    init(country)

@native_c("lbee_wifi_link", [])
def link(ssid,sec,password):
    pass

@native_c("lbee_wifi_is_linked", [])
def is_linked():
    pass

@native_c("lbee_scan", [])
def scan(duration):
    pass

@native_c("lbee_wifi_unlink", [])
def unlink():
    pass

@native_c("lbee_link_info", [])
def link_info():
    pass

@native_c("lbee_set_link_info", [])
def set_link_info(ip,mask,gw,dns):
    pass

@native_c("lbee_resolve", [])
def gethostbyname(hostname):
    pass

@native_c("lbee_socket", [])
def socket(family,type,proto):
    pass

@native_c("lbee_setsockopt", [])
def setsockopt(sock,level,optname,value):
    pass

@native_c("lbee_close", [])
def close(sock):
    pass

@native_c("lbee_connect", [])
def connect(sock,addr):
    pass

@native_c("lbee_select",[])
def select(rlist,wist,xlist,timeout):
    pass

@native_c("lbee_send", [])
def send(sock,buf,flags=0):
    pass

@native_c("lbee_send_all", [])
def sendall(sock,buf,flags=0):
    pass

@native_c("lbee_recv_into", [])
def recv_into(sock,buf,bufsize,flags=0,ofs=0):
    pass

@native_c("lbee_recvfrom_into", [])
def recvfrom_into(sock,buf,bufsize,flags=0):
    pass

@native_c("lbee_sendto", [])
def sendto(sock,buf,addr,flags=0):
    pass

@native_c("lbee_bind", [])
def bind(sock,addr):
    pass

@native_c("lbee_listen", [])
def listen(sock,maxlog=2):
    pass

@native_c("lbee_accept", [])
def accept(sock):
    pass

#-if ZERYNTH_SSL
@native_c("lbee_secure_socket", [], [])
def secure_socket(family, type, proto, ctx):
    pass
#-else
def secure_socket(family, type, proto, ctx):
    raise UnsupportedError
#-endif