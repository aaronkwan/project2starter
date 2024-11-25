#ifndef TLV_H
#define TLV_H

#include <stdint.h>
#include <stdlib.h>

// Define the TLV structure
typedef struct {
    uint8_t type;       // Type field
    uint16_t length;    // Length field
    uint8_t *value;     // Pointer to the value
} TLV;

// Function to parse a TLV from a raw message
TLV* to_TLV(const uint8_t *message, size_t size);

// Function to free the memory allocated for a TLV
void free_TLV(TLV *tlv);

#endif // TLV_H
