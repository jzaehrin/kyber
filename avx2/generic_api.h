#ifndef KYBER_GENERIC_API_H
#define KYBER_GENERIC_API_H

#include <stdint.h>
#include <stdbool.h>

/* Kyber structure */
struct kyber {
    int type;
    unsigned char * pk;
    unsigned char * sk;
};
typedef struct kyber KYBER;

/* Kyber variation */
#define KYBER1024 3
#define KYBER768 2
#define KYBER512 1

KYBER *kyber_new(void);
int kyber_prepare(KYBER* k, int type);
int kyber_generate_key(KYBER* k);
int kyber_enc(unsigned char *ct, unsigned char *ss, const KYBER* k);
int kyber_dec(unsigned char *ss, const unsigned char *ct, const KYBER* k);
void kyber_shake(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void kyber_free(KYBER* k);

bool kyber_is_valid_type(int type);
size_t kyber_sk_bytes(KYBER * k);
size_t kyber_pk_bytes(KYBER * k);
size_t kyber_ss_bytes(void);
size_t kyber_ct_bytes(KYBER * k);

#endif