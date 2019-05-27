added defines for malloc and free in:

    43xxx_Wi-Fi/WICED/WWD/internal/wwd_wifi.c
    43xxx_Wi-Fi/WICED/WWD/internal/wwd_clm.c
    43xxx_Wi-Fi/WICED/WWD/internal/wwd_internal.c
    43xxx_Wi-Fi/WICED/platform/MCU/platform_resource.c

removed wwd_wifi_ds1_get_status_string from
    43xxx_Wi-Fi/WICED/WWD/internal/wwd_wifi_sleep.c
due to snprintf

added mesh defines to
    43xxx_Wi-Fi/WICED/WWD/internal/wwd_wifi.c

using custom 
    43xxx_Wi-Fi/WICED/internal/wiced_smaller_lib.c
instead of
    43xxx_Wi-Fi/WICED/internal/wiced_lib.c
to avoid string dependencies
