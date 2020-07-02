#ifndef IMPLICIT_H
#define IMPLICIT_H

int pqcrystals_kyber1024_avx2_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_kyber1024_avx2_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int pqcrystals_kyber1024_avx2_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

int pqcrystals_kyber768_avx2_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_kyber768_avx2_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int pqcrystals_kyber768_avx2_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

int pqcrystals_kyber512_avx2_keypair(unsigned char *pk, unsigned char *sk);
int pqcrystals_kyber512_avx2_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int pqcrystals_kyber512_avx2_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif