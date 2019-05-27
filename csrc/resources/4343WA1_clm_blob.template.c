#include "wiced_resource.h"

const char wifi_firmware_clm_blob_data[7222] = {
};

const resource_hnd_t wifi_firmware_clm_blob = { RESOURCE_IN_MEMORY,  7222, {.mem = { (const char *) wifi_firmware_clm_blob_data } }};

