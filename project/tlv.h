#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stdlib.h>

// Define the TLV structure
typedef struct {
    uint8_t type;       // Type field
    size_t length;    // Length field
    uint8_t[1009] value;     // Value field
} TLV;

// Function to parse a TLV from a raw message in buffer:
TLV to_TLV(const uint8_t *message, size_t size);

// Function to create a TLV from components:
TLV to_TLV(uint8_t type, size_t length, const uint8_t *value);

// Function to generate a RAW message from a TLV (return size in bytes):
size_t to_RAW(TLV tlv, uint8_t *buffer);

#endif // TLV_H
