#include <stdlib.h>
#include <stdbool.h>

#include "generic_api.h"
#include "implicit.h"
#include "fips202.h"

/* Allocate Kyber structure */
KYBER *kyber_new(void) {
    KYBER * kyber = NULL;

    if ((kyber = malloc(sizeof(KYBER))) == NULL) {
        return NULL; /* Allocation error */
    }

    return kyber;
}

/* Shake shared secret for key exchange, user need to allocate output buffer */
void kyber_shake(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen) {
    pqcrystals_fips202_ref_shake256(out, outlen, in, inlen);
}

/* Prepare key buffers according to kyber variant type to store them */
int kyber_prepare(KYBER* k, int type) {
    if (!kyber_is_valid_type(type))
        return 1; /* Type unknown */

    k->type = type;

    if ((k->pk = malloc(kyber_pk_bytes(k))) == NULL ||
	    (k->sk = malloc(kyber_sk_bytes(k))) == NULL) {
		return 1; /* Allocation error */
	}

    return 0;
}

/* Verify if the variant type is a correct type for kyber */
bool kyber_is_valid_type(int type) {
    switch (type)
    {
        case KYBER1024:
        case KYBER768:
        case KYBER512:
            return true;
        default: 
            return false;
    }
}

/* Get the secret key size */
size_t kyber_sk_bytes(KYBER * k) {
    size_t size = 0;
    switch (k->type)
    {
        case KYBER1024:
            size = 3168; 
            break;

        case KYBER768:
            size = 2400;
            break;

        case KYBER512:
            size = 1632;
            break;
    }

    return size;

}
/* Get the public key size */
size_t kyber_pk_bytes(KYBER * k) {
    size_t size = 0;
    switch (k->type)
    {
        case KYBER1024:
            size = 1568; 
            break;

        case KYBER768:
            size = 1184;
            break;

        case KYBER512:
            size = 800;
            break;
    }

    return size;
}

/* Generate a pair of secret and public keys */
int kyber_generate_key(KYBER* k) {
    switch (k->type)
    {
        case KYBER1024:
            return pqcrystals_kyber1024_avx2_keypair(k->pk, k->sk);

        case KYBER768:
            return pqcrystals_kyber768_avx2_keypair(k->pk, k->sk);

        case KYBER512:
            return pqcrystals_kyber512_avx2_keypair(k->pk, k->sk);
    }

    return 1;
}

/*
 * Generate a number in ss and encrypt this number in ss
 *  user need to allocate ct and ss buffer
 */
int kyber_enc(unsigned char *ct, unsigned char *ss, const KYBER* k) {
    switch (k->type)
    {
        case KYBER1024:
            return pqcrystals_kyber1024_avx2_enc(ct, ss, k->pk);

        case KYBER768:
            return pqcrystals_kyber768_avx2_enc(ct, ss, k->pk);

        case KYBER512:
            return pqcrystals_kyber512_avx2_enc(ct, ss, k->pk);
    }

    return 1;
}

/*
 * Verify and decrypt ciphertext ct and store the number in ss
 *  user need to allocate ss buffer
 */
int kyber_dec(unsigned char *ss, const unsigned char *ct, const KYBER* k){
    switch (k->type)
    {
        case KYBER1024:
            return pqcrystals_kyber1024_avx2_dec(ss, ct, k->sk);

        case KYBER768:
            return pqcrystals_kyber768_avx2_dec(ss, ct, k->sk);

        case KYBER512:
            return pqcrystals_kyber512_avx2_dec(ss, ct, k->sk);
    }

    return 1;
}

/* Free kyber structure */
void kyber_free(KYBER* k) {
    if (k == NULL)
        return;

    if(k->pk != NULL)
        free(k->pk);

    if(k->sk != NULL)
        free(k->sk);

    free(k);
}

/* Get number size from enc */
size_t kyber_ss_bytes(void) {
    return 32;
}

/* Get ciphertext size */
size_t kyber_ct_bytes(KYBER * k) {
    size_t size = 0;
    switch (k->type)
    {
        case KYBER1024:
            size = 1568; 
            break;

        case KYBER768:
            size = 1088;
            break;

        case KYBER512:
            size = 736;
            break;
    }

    return size;
}