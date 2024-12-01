#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

// Define the TLV structure
typedef struct {
    uint8_t type;           // Type field
    size_t length;          // Length field
    uint8_t value[1009];    // Value field
    bool valid;             // Validity flag
} TLV;

// Function to parse a TLV from a raw message in buffer:
TLV to_TLV_fromMessage(const uint8_t *message, size_t size);

// Function to create a TLV from components:
TLV to_TLV_fromComponents(uint8_t type, size_t length, const uint8_t *value);

// Function to generate a RAW message from a TLV (return size in bytes):
size_t to_RAW_fromTLV(TLV tlv, uint8_t *buffer);

// Function to get the size of a TLV in bytes:
size_t size(TLV tlv);

#endif // TLV_H
