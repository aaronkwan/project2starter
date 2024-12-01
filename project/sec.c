#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "consts.h"
#include "io.h"
#include "security.h"
#include "tlv.h"

int state_sec = 0;              // Current state for handshake
uint8_t nonce[NONCE_SIZE];      // Store generated nonce to verify signature
uint8_t peer_nonce[NONCE_SIZE]; // Store peer's nonce to sign

void init_sec(int initial_state) {
    state_sec = initial_state;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key();
        derive_public_key();
        derive_self_signed_certificate();
        load_ca_public_key("ca_public_key.bin");
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_certificate("server_cert.bin");
        load_private_key("server_key.bin");
        derive_public_key();
    }

    generate_nonce(nonce, NONCE_SIZE);
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    // This passes it directly to standard input (working like Project 1)
    // return input_io(buf, max_length);

    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        // Init raw messages:
        uint8_t nonce_RAW[1012] = {0};
        uint8_t hello_RAW[1012] = {0};
        // Make nonce raw:
        TLV nonce_tlv = to_TLV_fromComponents(0x01, NONCE_SIZE, nonce);
        size_t nonce_size = to_RAW_fromTLV(nonce_tlv, nonce_RAW);
        // Make hello raw:
        TLV hello_tlv = to_TLV_fromComponents(CLIENT_HELLO, nonce_size, nonce_RAW);
        size_t hello_size = to_RAW_fromTLV(hello_tlv, hello_RAW);
        // Print nonce:
        fprintf(stderr, "SEND NONCE ");
        for (size_t i = 0; i < NONCE_SIZE; i++) {
            fprintf(stderr, "%02x", nonce[i]);
        }
        // Pass into input buffer:
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        memcpy(buf, hello_RAW, hello_size);
        return hello_size;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // Init raw messages:
        uint8_t hello_RAW[1012] = {0}; // contains (1), (2), (3)
        uint8_t nonce_RAW[1012] = {0}; // (1)
        uint8_t cert_RAW[1012] = {0}; // (2)
        uint8_t pubkey_RAW[1012] = {0}; // (2a)
        uint8_t sign_RAW[1012] = {0}; // (2b)
        uint8_t nonce_sign_RAW[1012] = {0}; // (3)
        // Make nonce raw:
        TLV nonce_tlv = to_TLV_fromComponents(0x01, NONCE_SIZE, nonce);
        size_t nonce_size = to_RAW_fromTLV(nonce_tlv, nonce_RAW);
        // Make certificate raw:
        TLV cert_tlv = to_TLV_fromComponents(0x02, cert_len, cert);
        size_t cert_size = to_RAW_fromTLV(cert_tlv, cert_RAW);
        // Make public key raw:
        TLV pubkey_tlv = to_TLV_fromComponents(0x02a, pubkey_len, pubkey);
        size_t pubkey_size = to_RAW_fromTLV(pubkey_tlv, pubkey_RAW);
        // Make signature raw:
        TLV sign_tlv = to_TLV_fromComponents(0x02b, sign_len, sign);
        size_t sign_size = to_RAW_fromTLV(sign_tlv, sign_RAW);
        // Make nonce signature raw:
        TLV nonce_sign_tlv = to_TLV_fromComponents(0x03, sign_len, sign);
        size_t nonce_sign_size = to_RAW_fromTLV(nonce_sign_tlv, nonce_sign_RAW);
        // Concatenate all:
        size_t hello_size = 0;
        memcpy(hello_RAW, nonce_RAW, nonce_size);
        hello_size += nonce_size;
        memcpy(hello_RAW + hello_size, cert_RAW, cert_size);
        hello_size += cert_size;
        memcpy(hello_RAW + hello_size, pubkey_RAW, pubkey_size);
        hello_size += pubkey_size;
        memcpy(hello_RAW + hello_size, sign_RAW, sign_size);
        hello_size += sign_size;
        memcpy(hello_RAW + hello_size, nonce_sign_RAW, nonce_sign_size);
        hello_size += nonce_sign_size;
        // Pass into input buffer:

        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        return 0;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request sending logic here */

        state_sec = CLIENT_FINISHED_AWAIT;
        return 0;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        /* Insert Finished sending logic here */

        state_sec = DATA_STATE;
        return 0;
    }
    case DATA_STATE: {
        /* Insert Data sending logic here */

        // PT refers to the amount you read from stdin in bytes
        // CT refers to the resulting ciphertext size
        // fprintf(stderr, "SEND DATA PT %ld CT %lu\n", stdin_size, cip_size);

        return 0;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1)
    return output_io(buf, length);

    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        if (*buf != CLIENT_HELLO)
            exit(4);

        print("RECV CLIENT HELLO");

        // Attempt to parse the received message:
        TLV hello_tlv = to_TLV_fromMessage(buf, length);
        if (!hello_tlv.valid) {
            break;
        }
        // Ensure the type is correct:
        if (hello_tlv.type != CLIENT_HELLO) {
            fprintf(stderr, "Error: Unexpected message type.\n");
            exit(4);
        }
        // Extract client nonce:
        TLV nonce_tlv = to_TLV_fromMessage(hello_tlv.value, hello_tlv.length);
        if (!nonce_tlv.valid) {
            break;
        }
        // Ensure the type is correct:
        if (nonce_tlv.type != 0x01) {
            fprintf(stderr, "Error: Unexpected nonce type.\n");
            exit(4);
        }
        // Print the nonce:
        fprintf(stderr, "RECV NONCE ");
        for (size_t i = 0; i < nonce_tlv.length; i++) {
            fprintf(stderr, "%02x", nonce_tlv.value[i]);
        }
        // Store the nonce:
        memcpy(peer_nonce, nonce_tlv.value, nonce_tlv.length);
        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        if (*buf != SERVER_HELLO)
            exit(4);

        print("RECV SERVER HELLO");

        /* Insert Server Hello receiving logic here */

        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        /* Insert Key Exchange Request receiving logic here */

        state_sec = SERVER_FINISHED_SEND;
        break;
    }
    case CLIENT_FINISHED_AWAIT: {
        if (*buf != FINISHED)
            exit(4);

        print("RECV FINISHED");

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        if (*buf != DATA)
            exit(4);

        /* Insert Data receiving logic here */

        // PT refers to the resulting plaintext size in bytes
        // CT refers to the received ciphertext size
        // fprintf(stderr, "RECV DATA PT %ld CT %hu\n", data_len, cip_len);
        break;
    }
    default:
        break;
    }
}
