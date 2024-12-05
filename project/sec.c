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
        TLV nonce_tlv = to_TLV_fromComponents(NONCE_CLIENT_HELLO, NONCE_SIZE, nonce);
        size_t nonce_size = to_RAW_fromTLV(nonce_tlv, nonce_RAW);
        // Make hello raw:
        TLV hello_tlv = to_TLV_fromComponents(CLIENT_HELLO, nonce_size, nonce_RAW);
        size_t hello_size = to_RAW_fromTLV(hello_tlv, hello_RAW);
        // Print hello_tlv.length:
        fprintf(stderr, "SEND LENGTH %zu\n", hello_tlv.length);
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
        uint8_t hello_RAW[1012] = {0}; // contains the final tlv
        uint8_t hello_value_RAW[1012] = {0}; // contains (1), (2), (3)
        uint8_t nonce_RAW[1012] = {0}; // (1)
        uint8_t cert_RAW[1012] = {0}; // (2)
        uint8_t nonce_sign_RAW[1012] = {0}; // (3)
        // Make nonce raw:
        TLV nonce_tlv = to_TLV_fromComponents(NONCE_SERVER_HELLO, NONCE_SIZE, nonce);
        size_t nonce_size = to_RAW_fromTLV(nonce_tlv, nonce_RAW);
        // Make certificate raw:
            // use cert_size and certificate (already done for us).
        // Make nonce signature raw:
            // sign peer_nonce using private key.
        uint8_t nonce_sign_value_RAW[1012] = {0};
        size_t nonce_sign_value_size = sign(peer_nonce, NONCE_SIZE, nonce_sign_value_RAW);
        TLV nonce_sign_tlv = to_TLV_fromComponents(NONCE_SIGNATURE_SERVER_HELLO, nonce_sign_value_size, nonce_sign_value_RAW);
        size_t nonce_sign_size = to_RAW_fromTLV(nonce_sign_tlv, nonce_sign_RAW);
        // Concatenate all into hello_value_RAW:
        size_t hello_value_size = 0;
        memcpy(hello_value_RAW, nonce_RAW, nonce_size);
        hello_value_size += nonce_size;
        memcpy(hello_value_RAW + hello_value_size, certificate, cert_size);
        hello_value_size += cert_size;
        memcpy(hello_value_RAW + hello_value_size, nonce_sign_RAW, nonce_sign_size);
        hello_value_size += nonce_sign_size;
        // Make hello raw:
        TLV hello_tlv = to_TLV_fromComponents(SERVER_HELLO, hello_value_size, hello_value_RAW);
        size_t hello_size = to_RAW_fromTLV(hello_tlv, hello_RAW);
        // Print nonce:
        fprintf(stderr, "SEND NONCE ");
        for (size_t i = 0; i < NONCE_SIZE; i++) {
            fprintf(stderr, "%02x", nonce[i]);
        }
        // Pass into input buffer:
        state_sec = SERVER_KEY_EXCHANGE_REQUEST_AWAIT;
        memcpy(buf, hello_RAW, hello_size);
        return hello_size;
    }
    case CLIENT_KEY_EXCHANGE_REQUEST_SEND: {
        print("SEND KEY EXCHANGE REQUEST");

        // Init raw messages:
        uint8_t keyExchange_RAW[1012] = {0}; // contains the final tlv
        uint8_t keyExchange_value_RAW[1012] = {0}; // contains (1), (2)
        uint8_t cert_RAW[1012] = {0}; // (1)
        uint8_t nonce_sign_RAW[1012] = {0}; // (2)
        // Make certificate raw:
            // use cert_size and certificate (already done for us).
        // Make nonce signature raw:
            // sign peer_nonce using private key.
        uint8_t nonce_sign_value_RAW[1012] = {0};
        size_t nonce_sign_value_size = sign(peer_nonce, NONCE_SIZE, nonce_sign_value_RAW);
        TLV nonce_sign_tlv = to_TLV_fromComponents(NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST, nonce_sign_value_size, nonce_sign_value_RAW);
        size_t nonce_sign_size = to_RAW_fromTLV(nonce_sign_tlv, nonce_sign_RAW);
        // Concatenate all into keyExchange_value_RAW:
        size_t keyExchange_value_size = 0;
        memcpy(keyExchange_value_RAW, certificate, cert_size);
        keyExchange_value_size += cert_size;
        memcpy(keyExchange_value_RAW + keyExchange_value_size, nonce_sign_RAW, nonce_sign_size);
        keyExchange_value_size += nonce_sign_size;
        // Make keyExchange raw:
        TLV keyExchange_tlv = to_TLV_fromComponents(KEY_EXCHANGE_REQUEST, keyExchange_value_size, keyExchange_value_RAW);
        size_t keyExchange_size = to_RAW_fromTLV(keyExchange_tlv, keyExchange_RAW);
        // Pass into input buffer:
        state_sec = CLIENT_FINISHED_AWAIT;
        memcpy(buf, keyExchange_RAW, keyExchange_size);
        return keyExchange_size;
    }
    case SERVER_FINISHED_SEND: {
        print("SEND FINISHED");

        // Init raw messages:
        uint8_t finished_RAW[1012] = {0}; // contains the final tlv
        // Make finished raw:
        TLV finished_tlv = to_TLV_fromComponents(FINISHED, 0, NULL);
        size_t finished_size = to_RAW_fromTLV(finished_tlv, finished_RAW);
        // Pass into input buffer:
        state_sec = DATA_STATE;
        memcpy(buf, finished_RAW, finished_size);
        return finished_size;
    }
    case DATA_STATE: {
        // print("SEND DATA");

        // Read in up to 943 bytes from stdin:
        uint8_t stdin_buffer[1012] = {0};
        size_t stdin_buffer_size = input_io(stdin_buffer, (max_length < 943 ? max_length : 943));
        if (stdin_buffer_size == 0) {
            return 0;
        }
        fprintf(stderr, "SEND DATA read: %ld \n", stdin_buffer_size);

        // Init raw messages:
        uint8_t data_RAW[1012] = {0}; // contains the final tlv
        uint8_t data_value_RAW[1012] = {0}; // contains TLV(IV), TLV(CIPHER), TLV(MAC)
        uint8_t iv_RAW[1012] = {0}; // (1)
        uint8_t cipher_RAW[1012] = {0}; // (2)
        uint8_t mac_RAW[1012] = {0}; // (3)
        // Encrypt data:
        size_t cipher_value_size = encrypt_data(stdin_buffer, stdin_buffer_size, iv_RAW, cipher_RAW);
        fprintf(stderr, "SEND DATA cipher_value_size: %zu\n", cipher_value_size);
        TLV iv_tlv = to_TLV_fromComponents(INITIALIZATION_VECTOR, IV_SIZE, iv_RAW);
        size_t iv_size = to_RAW_fromTLV(iv_tlv, iv_RAW);
        TLV cipher_tlv = to_TLV_fromComponents(CIPHERTEXT, cipher_value_size, cipher_RAW);
        size_t cipher_size = to_RAW_fromTLV(cipher_tlv, cipher_RAW);
        fprintf(stderr, "SEND DATA cipher_size: %zu\n", cipher_size);
        // Generate signature of (IV, CIPHER) using MAC (MAC):
            // Create (IV, CIPHER) buffer:
        uint8_t iv_and_cipher[1012] = {0};
        memcpy(iv_and_cipher, iv_tlv.value, iv_tlv.length);
        memcpy(iv_and_cipher + iv_tlv.length, cipher_tlv.value, cipher_tlv.length);
        size_t iv_and_cipher_size = iv_tlv.length + cipher_tlv.length;
            // Create and populate MAC buffer:
        uint8_t mac_value_RAW[MAC_SIZE] = {0};
        hmac(iv_and_cipher, iv_and_cipher_size, mac_value_RAW);
        TLV mac_tlv = to_TLV_fromComponents(MESSAGE_AUTHENTICATION_CODE, MAC_SIZE, mac_value_RAW);
        size_t mac_size = to_RAW_fromTLV(mac_tlv, mac_RAW);
        fprintf(stderr, "SEND DATA mac_size: %zu\n", mac_size);
        // Append TLV{TLV(IV), TLV(CIPHER), TLV(MAC)} to buffer:
        size_t data_value_size = 0;
        memcpy(data_value_RAW, iv_RAW, iv_size);
        data_value_size += iv_size;
        memcpy(data_value_RAW + data_value_size, cipher_RAW, cipher_size);
        data_value_size += cipher_size;
        memcpy(data_value_RAW + data_value_size, mac_RAW, mac_size);
        data_value_size += mac_size;
        // Make data raw:
        TLV data_tlv = to_TLV_fromComponents(DATA, data_value_size, data_value_RAW);
        size_t data_size = to_RAW_fromTLV(data_tlv, data_RAW);
        // Print sizes of all components:
        fprintf(stderr, "SEND DATA DATA %zu IV %zu CIPHER %zu MAC %zu\n", data_size, iv_size, cipher_size, mac_size);
        // Pass into input buffer:
        // memcpy(buf, data_RAW, data_size);
        // return data_size;
        size_t real = max_length < data_size ? max_length : data_size;
        real = (640 + 320) / 2;
        real = 510;
        real = data_size;
        fprintf(stderr, "real, max_length: %zu, %zu\n", real, max_length);
        memcpy(buf, data_RAW, real);
        return real;
    }
    default:
        return 0;
    }
}

void output_sec(uint8_t* buf, size_t length) {
    // This passes it directly to standard output (working like Project 1).
    // We need to keep a temp buffer to store partial TLVs: `output_buffer`.
    // return output_io(buf, length);

    // Add to output buffer:
    // memcpy(output_buffer + output_buffer_size, buf, length);
    // output_buffer_size += length;

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
        if (nonce_tlv.type != NONCE_CLIENT_HELLO) {
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

        // Attempt to parse the received message:
        TLV hello_tlv = to_TLV_fromMessage(buf, length);
        if (!hello_tlv.valid) {
            break;
        }
        // Ensure the type is correct:
        if (hello_tlv.type != SERVER_HELLO) {
            fprintf(stderr, "Error: Unexpected message type.\n");
            exit(4);
        }
        // Unpack hello_tlv into nonce, certificate, and signed nonce:
            // Note: hello_tlv.value contains tlvs (1), (2), (3)
            // Thus, we move by size(tlv) to get to the next tlv.
        uint8_t hello_value_RAW[1012] = {0};
        memcpy(hello_value_RAW, hello_tlv.value, hello_tlv.length);
        TLV nonce_tlv = to_TLV_fromMessage(hello_value_RAW, hello_tlv.length);
        TLV cert_tlv = to_TLV_fromMessage(hello_value_RAW + size(nonce_tlv), hello_tlv.length - size(nonce_tlv));
        TLV nonce_sign_tlv = to_TLV_fromMessage(hello_value_RAW + size(nonce_tlv) + size(cert_tlv), hello_tlv.length - size(nonce_tlv) - size(cert_tlv));
        // Ensure the types are correct:
        if (nonce_tlv.type != NONCE_SERVER_HELLO || cert_tlv.type != CERTIFICATE || nonce_sign_tlv.type != NONCE_SIGNATURE_SERVER_HELLO) {
            fprintf(stderr, "Error: Unexpected nonce type.\n");
            exit(4);
        }
        // Verify certificate:
        TLV cert_pubKey_tlv = to_TLV_fromMessage(cert_tlv.value, cert_tlv.length);
        TLV cert_signature_tlv = to_TLV_fromMessage(cert_tlv.value + size(cert_pubKey_tlv), cert_tlv.length - size(cert_pubKey_tlv));
        if (!verify(cert_pubKey_tlv.value, cert_pubKey_tlv.length, cert_signature_tlv.value, cert_signature_tlv.length, ec_ca_public_key)) {
            fprintf(stderr, "Error: Certificate verification failed.\n");
            exit(1);
        }
        fprintf(stderr, "Certificate verification successful.\n");
        // Verify nonce signature:
            // get ec_peer_public_key from cert_pubKey_tlv
            // verify with: nonce, nonce_sign.value, ec_peer_public_key
        load_peer_public_key(cert_pubKey_tlv.value, cert_pubKey_tlv.length);
        if (!verify(nonce, NONCE_SIZE, nonce_sign_tlv.value, nonce_sign_tlv.length, ec_peer_public_key)) {
            fprintf(stderr, "Error: Nonce signature verification failed.\n");
            exit(2);
        }
        fprintf(stderr, "Nonce signature verification successful.\n");
        // Print the nonce:
        fprintf(stderr, "RECV NONCE ");
        for (size_t i = 0; i < nonce_tlv.length; i++) {
            fprintf(stderr, "%02x", nonce_tlv.value[i]);
        }
        // Generate ENC and MAC:
        derive_secret();
        derive_keys();
        // Store the nonce:
        memcpy(peer_nonce, nonce_tlv.value, nonce_tlv.length);
        state_sec = CLIENT_KEY_EXCHANGE_REQUEST_SEND;
        break;
    }
    case SERVER_KEY_EXCHANGE_REQUEST_AWAIT: {
        if (*buf != KEY_EXCHANGE_REQUEST)
            exit(4);

        print("RECV KEY EXCHANGE REQUEST");

        // Attempt to parse the received message:
        TLV keyExchange_tlv = to_TLV_fromMessage(buf, length);
        if (!keyExchange_tlv.valid) {
            break;
        }
        // Ensure the type is correct:
        if (keyExchange_tlv.type != KEY_EXCHANGE_REQUEST) {
            fprintf(stderr, "Error: Unexpected message type.\n");
            exit(1);
        }
        // Unpack keyExchange_tlv into certificate and signed nonce:
            // Note: keyExchange_tlv.value contains tlvs (1), (2)
            // Thus, we move by size(tlv) to get to the next tlv.
        uint8_t keyExchange_value_RAW[1012] = {0};
        memcpy(keyExchange_value_RAW, keyExchange_tlv.value, keyExchange_tlv.length);
        TLV cert_tlv = to_TLV_fromMessage(keyExchange_value_RAW, keyExchange_tlv.length);
        TLV nonce_sign_tlv = to_TLV_fromMessage(keyExchange_value_RAW + size(cert_tlv), keyExchange_tlv.length - size(cert_tlv));
        // Ensure the types are correct:
        if (cert_tlv.type != CERTIFICATE || nonce_sign_tlv.type != NONCE_SIGNATURE_KEY_EXCHANGE_REQUEST) {
            fprintf(stderr, "Error: Unexpected nonce type.\n");
            exit(4);
        }
        // Verify certificate:
        TLV cert_pubKey_tlv = to_TLV_fromMessage(cert_tlv.value, cert_tlv.length);
        TLV cert_signature_tlv = to_TLV_fromMessage(cert_tlv.value + size(cert_pubKey_tlv), cert_tlv.length - size(cert_pubKey_tlv));
        load_peer_public_key(cert_pubKey_tlv.value, cert_pubKey_tlv.length);
        if (!verify(cert_pubKey_tlv.value, cert_pubKey_tlv.length, cert_signature_tlv.value, cert_signature_tlv.length, ec_peer_public_key)) {
            fprintf(stderr, "Error: Certificate verification failed.\n");
            exit(1);
        }
        fprintf(stderr, "Certificate verification successful.\n");
        // Verify nonce signature:
            // get ec_peer_public_key from cert_pubKey_tlv
            // verify with: nonce, nonce_sign.value, ec_peer_public_key
        if (!verify(nonce, NONCE_SIZE, nonce_sign_tlv.value, nonce_sign_tlv.length, ec_peer_public_key)) {
            fprintf(stderr, "Error: Nonce signature verification failed.\n");
            exit(2);
        }
        fprintf(stderr, "Nonce signature verification successful.\n");

        // Generate ENC and MAC:
        derive_secret();
        derive_keys();
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
