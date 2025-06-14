#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "consts.h"
#include "io.h"
#include "libsecurity.h"

int state_sec = 0;     // Current state for handshake
char* hostname = NULL; // For client: storing inputted hostname
EVP_PKEY* priv_key = NULL;
tlv* client_hello = NULL;
tlv* server_hello = NULL;

uint8_t ts[1000] = {0};
uint16_t ts_len = 0;

bool inc_mac = false;  // For testing only: send incorrect MACs

void init_sec(int initial_state, char* host, bool bad_mac) {
    state_sec = initial_state;
    hostname = host;
    inc_mac = bad_mac;
    init_io();

    if (state_sec == CLIENT_CLIENT_HELLO_SEND) {
        generate_private_key();
        derive_public_key();
    } else if (state_sec == SERVER_CLIENT_HELLO_AWAIT) {
        load_private_key("server_key.bin");
        derive_public_key();
        load_certificate("server_cert.bin");
        load_ca_public_key("ca_public_key.bin");
    }
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    switch (state_sec) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        client_hello = create_tlv(CLIENT_HELLO);

        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(client_hello, nn);

        tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
        add_val(public_key_tlv, public_key, pub_key_size);

        add_tlv(client_hello, public_key_tlv);

        ssize_t len = serialize_tlv(buf, client_hello);
        print_tlv_bytes(buf, len);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return len;
        break;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        server_hello = create_tlv(SERVER_HELLO);

        // nonce
        tlv* nonce_tlv = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);
        add_val(nonce_tlv, nonce, NONCE_SIZE);
        add_tlv(server_hello, nonce_tlv);

        // certificate TODO
        tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
        add_tlv(server_hello, cert_tlv);

        // server public key
        tlv* public_key_tlv = create_tlv(PUBLIC_KEY);
        add_val(public_key_tlv, public_key, pub_key_size);
        add_tlv(server_hello, public_key_tlv);

        // handshake signature
        uint8_t* client_hello_serialized = malloc(client_hello->length);
        uint8_t* nonce_serialized = malloc(nonce_tlv->length);
        uint8_t* certificate_serialized = malloc(cert_tlv->length);
        uint8_t* public_key_serialized = malloc(public_key_tlv->length);

        size_t client_hello_size = serialize_tlv(client_hello_serialized, client_hello);
        size_t nonce_size = serialize_tlv(nonce_serialized, nonce_tlv);
        size_t certificate_size = serialize_tlv(certificate_serialized, cert_tlv);
        size_t public_key_size = serialize_tlv(public_key_serialized, public_key_tlv);

        size_t total_size = client_hello_size + nonce_size + certificate_size + public_key_size;
        uint8_t* handshake_data = malloc(total_size);
        size_t offset = 0;
        memcpy(handshake_data, client_hello_serialized, client_hello_size);
        offset += client_hello_size;
        memcpy(handshake_data + offset, nonce_serialized, nonce_size);
        offset += nonce_size;
        memcpy(handshake_data + offset, certificate_serialized, certificate_size);
        offset += certificate_size;
        memcpy(handshake_data + offset, public_key_serialized, public_key_size);

        uint8_t signature[72];
        size_t sig_size = sign(signature, handshake_data, total_size);
        free(handshake_data);

        tlv* signature_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(signature_tlv, signature, sig_size);
        add_tlv(server_hello, signature_tlv);

        free(nonce_serialized);
        free(certificate_serialized);
        free(public_key_serialized);

        ssize_t len = serialize_tlv(buf, server_hello);
        print_tlv_bytes(buf, len);

        // Symmetric shared secret using Diffie-Hellman
        derive_secret();

        // Derive keys for encryption and MAC
        uint8_t* salt = malloc(client_hello->length + server_hello->length);
        memcpy(salt, client_hello_serialized, client_hello->length);
        memcpy(salt + client_hello->length, buf, server_hello->length);
        free(client_hello_serialized);

        derive_keys(salt, client_hello->length + server_hello->length);
        free(salt);

        state_sec = SERVER_FINISHED_AWAIT;
        return len;
        break;
    }
    case CLIENT_FINISHED_SEND: {
        print("SEND FINISHED");
        break;
    }
    case DATA_STATE: {
        break;
    }
    default:
        return 0;
    }
    return 0;
}

void output_sec(uint8_t* buf, size_t length) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        client_hello = deserialize_tlv(buf, length);
        tlv* client_public_key = get_tlv(client_hello, PUBLIC_KEY);
        load_peer_public_key(client_public_key->val, client_public_key->length);
        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        server_hello = deserialize_tlv(buf, length);
        print_tlv_bytes(buf, length);
        break;
    }
    case SERVER_FINISHED_AWAIT: {
        break;
    }
    case DATA_STATE: {
        tlv* data = deserialize_tlv(buf, length);
        break;
    }
    default:
        break;
    }
}
