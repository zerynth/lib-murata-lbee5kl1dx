/*
* @Author: Lorenzo
* @Date:   2019-02-07 11:14:40
* @Last Modified by:   Lorenzo
* @Last Modified time: 2019-02-07 11:15:04
*/

#include "wiced_utilities.h"

char* wiced_ether_ntoa( const uint8_t *ea, char *buf, uint8_t buf_len )
{
    const char hex[] =
    {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    char *output = buf;
    const uint8_t *octet = ea;

    if ( buf_len < WICED_ETHER_ADDR_STR_LEN )
    {
        if ( buf_len > 0 )
        {
            /* buffer too short */
            buf[0] = '\0';
        }
        return buf;
    }

    for ( ; octet != &ea[WICED_ETHER_ADDR_LEN] ; octet++) {
        *output++ = hex[(*octet >> 4) & 0xf];
        *output++ = hex[*octet & 0xf];
        *output++ = ':';
    }

    *(output-1) = '\0';

    return buf;
}