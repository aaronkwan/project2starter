#include "tlv.h"
#include <string.h>
#include <stdio.h>

TLV* to_TLV(const uint8_t *message, size_t size) {
    if (message == NULL || size < 3) {
        return NULL; // Not enough data for a TLV header
    }

    TLV *tlv = (TLV*)malloc(sizeof(TLV));
    if (!tlv) {
        return NULL; // Memory allocation failed
    }

    // Extract the type (1 byte)
    tlv->type = message[0];

    // Extract the length (2 bytes, big-endian)
    tlv->length = (message[1] << 8) | message[2];

    // Validate length and allocate memory for the value
    if (3 + tlv->length <= size) {
        tlv->value = (uint8_t*)malloc(tlv->length);
        if (tlv->value) {
            memcpy(tlv->value, &message[3], tlv->length);
        } else {
            free(tlv);
            return NULL; // Memory allocation for value failed
        }
    } else {
        free(tlv);
        return NULL; // Invalid length
    }

    return tlv;
}

void free_TLV(TLV *tlv) {
    if (tlv) {
        if (tlv->value) {
            free(tlv->value);
        }
        free(tlv);
    }
}
