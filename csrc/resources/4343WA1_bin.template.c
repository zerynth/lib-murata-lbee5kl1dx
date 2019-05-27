#include "wiced_resource.h"

const char wifi_firmware_image_data[383110] = {
};

const resource_hnd_t wifi_firmware_image = { RESOURCE_IN_MEMORY,  383110, {.mem = { (const char *) wifi_firmware_image_data } }};

