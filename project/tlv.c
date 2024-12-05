#include "tlv.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

TLV to_TLV_fromMessage(const uint8_t *message, size_t size) {
    // Init tlv:
    TLV tlv;
    // Ensure sufficient data to parse TLV:
    if (size < 3) {
        fprintf(stderr, "Error: Insufficient data to parse TLV.\n");
        exit(1);
    }
    // Extract type (1 byte):
    tlv.type = message[0];
    // Extract length (2 bytes, big->little endian):
    tlv.length = (size_t)(message[1] << 8 | (message[2]));
    // Print length:
    fprintf(stderr, "Length: %zu\n", tlv.length);
    // Ensure the length is within bounds:
    if (tlv.length > 1009) {
        fprintf(stderr, "Error: TLV length out of bounds.\n");
        exit(1);
    }
    if ((3 + tlv.length) > size) {
        fprintf(stderr, "Note: Insufficient data to parse TLV.\n");
        tlv.valid = false;
    }
    else {
        // Extract value (length bytes)
        memcpy(tlv.value, &message[3], tlv.length);
        tlv.valid = true;
    }
    return tlv;
}

TLV to_TLV_fromComponents(uint8_t type, size_t length, const uint8_t *value) {
    // Init tlv:
    TLV tlv;
    // Ensure the length is within bounds:
    if (length > 1009) {
        fprintf(stderr, "Error: Value length exceeds maximum allowed size.\n");
        exit(1);
    }
    // Assign fields:
    tlv.type = type;
    tlv.length = length;
    if (length > 0) {
        memcpy(tlv.value, value, length);
    }
    tlv.valid = true;
    return tlv;
}

size_t to_RAW_fromTLV(TLV tlv, uint8_t *buffer) {
    // Check buffer:
    if (buffer == NULL) {
        fprintf(stderr, "Error: NULL buffer passed to to_raw.\n");
        exit(1);
    }
    // Write type:
    buffer[0] = tlv.type;
    // Write length (2 bytes, little->big endian):
    buffer[1] = (uint8_t)((tlv.length >> 8) & 0xFF);
    buffer[2] = (uint8_t)(tlv.length & 0xFF);
    // Write value:
    memcpy(&buffer[3], tlv.value, tlv.length);
    // Return total size of the raw message:
    return 3 + tlv.length;
}

size_t size(TLV tlv) {
    return 3 + tlv.length;
}
