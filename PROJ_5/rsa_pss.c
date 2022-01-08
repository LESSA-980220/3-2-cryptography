/*
 * Copyright 2020,2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "rsa_pss.h"
#include <stdint.h>

#include <bsd/stdlib.h>

#if defined(SHA224)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha224;
#elif defined(SHA256)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha256;
#elif defined(SHA384)
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha384;
#else
void (*sha)(const unsigned char *, unsigned int, unsigned char *) = sha512;
#endif

/*
 * Copyright 2020, 2021. Heekuck Oh, all rights reserved
 * rsa_generate_key() - generates RSA keys e, d and n in octet strings.
 * If mode = 0, then e = 65537 is used. Otherwise e will be randomly selected.
 * Carmichael's totient function Lambda(n) is used.
 */
void rsa_generate_key(void *_e, void *_d, void *_n, int mode)
{
    mpz_t p, q, lambda, e, d, n, gcd;
    gmp_randstate_t state;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(p, q, lambda, e, d, n, gcd, NULL);
    gmp_randinit_default(state);
    gmp_randseed_ui(state, arc4random());
    /*
     * Generate prime p and q such that 2^(RSAKEYSIZE-1) <= p*q < 2^RSAKEYSIZE
     */
    do {
        do {
            mpz_urandomb(p, state, RSAKEYSIZE/2);
            mpz_setbit(p, 0);
            mpz_setbit(p, RSAKEYSIZE/2-1);
       } while (mpz_probab_prime_p(p, 50) == 0);
        do {
            mpz_urandomb(q, state, RSAKEYSIZE/2);
            mpz_setbit(q, 0);
            mpz_setbit(q, RSAKEYSIZE/2-1);
        } while (mpz_probab_prime_p(q, 50) == 0);
        mpz_mul(n, p, q);
    } while (!mpz_tstbit(n, RSAKEYSIZE-1));
    /*
     * Generate e and d using Lambda(n)
     */
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_lcm(lambda, p, q);
    if (mode == 0)
        mpz_set_ui(e, 65537);
    else do {
        mpz_urandomb(e, state, RSAKEYSIZE);
        mpz_gcd(gcd, e, lambda);
    } while (mpz_cmp(e, lambda) >= 0 || mpz_cmp_ui(gcd, 1) != 0);
    mpz_invert(d, e, lambda);
    /*
     * Convert mpz_t values into octet strings
     */
    mpz_export(_e, NULL, 1, RSAKEYSIZE/8, 1, 0, e);
    mpz_export(_d, NULL, 1, RSAKEYSIZE/8, 1, 0, d);
    mpz_export(_n, NULL, 1, RSAKEYSIZE/8, 1, 0, n);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(p, q, lambda, e, d, n, gcd, NULL);
}

/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * rsa_cipher() - compute m^k mod n
 * If m >= n then returns EM_MSG_OUT_OF_RANGE, otherwise returns 0 for success.
 */
static int rsa_cipher(void *_m, const void *_k, const void *_n)
{
    mpz_t m, k, n;
    
    /*
     * Initialize mpz variables
     */
    mpz_inits(m, k, n, NULL);
    /*
     * Convert big-endian octets into mpz_t values
     */
    mpz_import(m, RSAKEYSIZE/8, 1, 1, 1, 0, _m);
    mpz_import(k, RSAKEYSIZE/8, 1, 1, 1, 0, _k);
    mpz_import(n, RSAKEYSIZE/8, 1, 1, 1, 0, _n);
    /*
     * Compute m^k mod n
     */
    if (mpz_cmp(m, n) >= 0) {
        mpz_clears(m, k, n, NULL);
        return EM_MSG_OUT_OF_RANGE;
    }
    mpz_powm(m, m, k, n);
    /*
     * Convert mpz_t m into the octet string _m
     */
    mpz_export(_m, NULL, 1, RSAKEYSIZE/8, 1, 0, m);
    /*
     * Free the space occupied by mpz variables
     */
    mpz_clears(m, k, n, NULL);
    return 0;
}

/*
 * Copyright 2020. Heekuck Oh, all rights reserved
 * A mask generation function based on a hash function
 */
static unsigned char *mgf(const unsigned char *mgfSeed, size_t seedLen, unsigned char *mask, size_t maskLen)
{
    uint32_t i, count, c;
    size_t hLen;
    unsigned char *mgfIn, *m;
    
    /*
     * Check if maskLen > 2^32*hLen
     */
    hLen = SHASIZE/8;
    if (maskLen > 0x0100000000*hLen)
        return NULL;
    /*
     * Generate octet string mask
     */
    if ((mgfIn = (unsigned char *)malloc(seedLen+4)) == NULL)
        return NULL;
    memcpy(mgfIn, mgfSeed, seedLen);
    count = maskLen/hLen + (maskLen%hLen ? 1 : 0);
    if ((m = (unsigned char *)malloc(count*hLen)) == NULL)
        return NULL;
    /*
     * Convert i to an octet string C of length 4 octets
     * Concatenate the hash of the seed mgfSeed and C to the octet string T:
     *       T = T || Hash(mgfSeed || C)
     */
    for (i = 0; i < count; i++) {
        c = i;
        mgfIn[seedLen+3] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen+2] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen+1] = c & 0x000000ff; c >>= 8;
        mgfIn[seedLen] = c & 0x000000ff;
        (*sha)(mgfIn, seedLen+4, m+i*hLen);
    }
    /*
     * Copy the mask and free memory
     */
    memcpy(mask, m, maskLen);
    free(mgfIn); free(m);
    return mask;
}

/*
 * rsassa_pss_sign - RSA Signature Scheme with Appendix
 */
int rsassa_pss_sign(const void *m, size_t mLen, const void *d, const void *n, void *s)
{
    // SHA224, SHA256에서 hash function의 input이 너무 길면 EM_MSG_TOO_LONG return
    if (((SHASIZE || 224) || (SHASIZE || 256)) && mLen > 0x1fffffffffffffff)
        return EM_MSG_TOO_LONG;

    unsigned char mHash[SHASIZE/8];
    unsigned char mgf_Hash[DB_LEN];
    unsigned char MPrime[2*(SHASIZE/8)+8];
    unsigned char salt[SHASIZE/8];
    unsigned char H[SHASIZE/8];
    unsigned char DB[DB_LEN];
    unsigned char EM[RSAKEYSIZE/8];

    // m을 hash하여 mHash 획득
    sha(m, mLen, mHash);

    // salt를 random number로 채움
    for (int i=0; i<SHASIZE/8; i++){
        salt[i] = arc4random() & 255;
    }    

    // MPrime의 처음 8 bytes는 0x00로 채우고 이후 mHash, salt를 이어붙임
    memset(MPrime, 0x00, 8);
    memcpy(MPrime + 8, mHash, SHASIZE/8);
    memcpy(MPrime + 8 + SHASIZE/8, salt, SHASIZE/8);

    // MPrime을 hash하여 H 획득
    sha(MPrime, 2*(SHASIZE/8)+8, H);

    // hash H의 길이가 너무 커서 EM에 넣을 수 없는 경우 EM_HASH_TOO_LONG return
    if ((sizeof(H) / sizeof(H[0]) > RSAKEYSIZE/2))
        return EM_HASH_TOO_LONG;

    // DB를 제외한 나머지 EM의 요소를 채움
    memcpy(EM + DB_LEN, H, SHASIZE/8);
    memset(EM + DB_LEN + SHASIZE/8, 0xbc, 1);

    // DB 구성, 0으로 계속 padding하다가 salt 바로 앞 bit를 1로 설정하여 salt 구분
    memset(DB, 0x00, PS_LEN-1);
    memset(DB+PS_LEN-1, 0x01, 1);
    memcpy(DB+PS_LEN, salt, SHASIZE/8);

    // mgf로 mgf_Hash 생성
    mgf(H, SHASIZE/8, mgf_Hash, DB_LEN);

    // DB와 mgf_Hash를 XOR하여 EM 구성
    for (int i=0; i<DB_LEN; i++){
        EM[i] = DB[i] ^ mgf_Hash[i];
    }

    // EM의 맨 처음 bit가 1일 시 0으로 변경 
    if ((EM[0] >> 7) == 1)
        EM[0] &= 0x7f;

    // EM을 (d, n)으로 서명
    // 이때 RSA 데이터 값이 modulus n보다 크거나 같다면 EM_MSG_OUT_OF_RANGE return
    if (rsa_cipher(EM, d, n))
        return EM_MSG_OUT_OF_RANGE;

    // EM을 s에 복사
    memcpy(s, EM, RSAKEYSIZE/8);

    return 0;
}

/*
 * rsassa_pss_verify - RSA Signature Scheme with Appendix
 */
int rsassa_pss_verify(const void *m, size_t mLen, const void *e, const void *n, const void *s)
{
    unsigned char EM[RSAKEYSIZE/8];
    unsigned char maskedDB[DB_LEN];
    unsigned char DB[DB_LEN];
    unsigned char mgf_Hash[DB_LEN];
    unsigned char H[SHASIZE/8];
    unsigned char salt[SHASIZE/8];
    unsigned char mHash[SHASIZE/8];
    unsigned char HPrime[SHASIZE/8];
    unsigned char MPrime[2*(SHASIZE/8)+8];

    // s를 EM에 복사
    memcpy(EM, s, RSAKEYSIZE/8);

    // EM을 (e, n)으로 검증
    // 이때 RSA 데이터 값이 modulus n보다 크거나 같다면 EM_MSG_OUT_OF_RANGE return
    if (rsa_cipher(EM, e, n))
        return EM_MSG_OUT_OF_RANGE;

    // EM의 마지막 byte가 0xbc가 아니면 EM_INVALID_LAST return
    if (EM[RSAKEYSIZE/8 - 1] != 0xbc)
        return EM_INVALID_LAST;

    // EM의 첫 bit가 0이 아니면 EM_INVALID_INIT return
    if ((EM[0] >> 7) != 0)
        return EM_INVALID_INIT;

    // EM에서 maskedDB, H를 추출
    memcpy(maskedDB, EM, DB_LEN);
    memcpy(H, EM + DB_LEN, SHASIZE/8);

    // mgf로 mgf_Hash 복구
    mgf(H, SHASIZE/8, mgf_Hash, DB_LEN);

    // DB의 첫 byte를 항상 0으로 설정
    DB[0] = 0x00;

    // maskedDB와 mgf_Hash를 XOR하여 DB 구성
    for (int i=1; i<DB_LEN; i++){
        DB[i] = maskedDB[i] ^ mgf_Hash[i];
    }

    // DB의 pad가 0x000...01이 아니라면 EM_INVALID_PD2 return
    for (int i=0; i<PS_LEN-1; i++){
        if ((DB[i] ^ 0x00) != 0)
            return EM_INVALID_PD2;
    }

    if (DB[PS_LEN-1] != 0x01)
        return EM_INVALID_PD2;

    // DB로부터 salt 추출
    memcpy(salt, DB + PS_LEN, SHASIZE/8);

    // m을 hash하여 mHash 획득
    sha(m, mLen, mHash);

    // MPrime의 첫 8 bytes는 0, 그 이후 mHash, salt를 이어붙임
    memset(MPrime, 0x00, 8);
    memcpy(MPrime + 8, mHash, SHASIZE/8);
    memcpy(MPrime + 8 + SHASIZE/8, salt, SHASIZE/8);

    // MPrime을 hash하여 HPrime 획득
    sha(MPrime, 2*(SHASIZE/8)+8, HPrime);

    // H와 HPrime의 일치여부 확인
    // 일치하지 않는다면 EM_HASH_MISMATCH return
    if (memcmp(H, HPrime, SHASIZE/8) != 0)
        return EM_HASH_MISMATCH;

    return 0;
}

