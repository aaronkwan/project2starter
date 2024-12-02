#pragma once

#include <stdint.h>
#include <unistd.h>

// Initialize security layer
void init_sec(int initial_state);

// Get input from security layer
ssize_t input_sec(uint8_t* buf, size_t max_length);

// Output to security layer
void output_sec(uint8_t* buf, size_t length);

// Buffer for output; used to store partial tlvs:
uint8_t output_buffer[1012];
size_t output_buffer_size;