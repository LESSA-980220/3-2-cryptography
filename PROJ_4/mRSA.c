/*
 * Copyright 2020, 2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include <stdlib.h>
#include "mRSA.h"

#include <bsd/stdlib.h>

const uint64_t a[ALEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * mRSA_generate_key() - generates mini RSA keys e, d and n
 * Carmichael's totient function Lambda(n) is used.
 */
void mRSA_generate_key(uint64_t *e, uint64_t *d, uint64_t *n)
{
    uint64_t p, q;
    uint64_t lambda_n;

    // randomly 32bit integer x
    uint64_t x = arc4random_uniform(0x7fffffff) + 0x80000000;
    int num = 0;

    // first while loop for p, q
    while(1){
        // if find first prime, p
        if (miller_rabin(x) && !num){
            p = x;
            x = arc4random_uniform(0x7fffffff) + 0x80000000;
            num++;
        }

        // if find second prime, q
        else if (miller_rabin(x) && num){
            q = x;
            if (p * q > MINIMUM_N){
                *n = p * q;
                break;
            }
            else {
                num = 0;
                x = arc4random_uniform(0x7fffffff) + 0x80000000;
            }
        }
        x++;
    }
    
    // to reduce the calculation, use lambda_n
    lambda_n = (p-1) * (q-1) / gcd(p-1, q-1);

    // to get randomly 64bit integer i,
    // use 2-randomly 32bit integer random1, random2
    uint64_t random1, random2, i;

    // second while loop for e, d
    while (1){
        random1 = arc4random_uniform(p-1);
        random2 = arc4random_uniform(q-1);

        i = random1 * random2 / gcd(p-1, q-1);
        
        // if i and lambda_n is relatively prime and i has its inverse d,
        // e = i and can get d
        if (gcd(i, lambda_n) == 1){
            *d = mul_inv(i, lambda_n);
            if (*d == 0) continue;
            else {
                *e = i;
                break;
            }
        }
    }
}

/*
 * mRSA_cipher() - compute m^k mod n
 * If data >= n then returns 1 (error), otherwise 0 (success).
 */
int mRSA_cipher(uint64_t *m, uint64_t k, uint64_t n)
{
    *m = mod_pow(*m, k, n);

    // over range
    if (*m >= n) return 1;
    else return 0;
}

uint64_t gcd(uint64_t a, uint64_t b){
    uint64_t temp = 0, result = 0;

    while (a != 0 && b != 0){
        temp = a;
        a = b;
        b = temp % b;
    }

    if (a == 0)
        result = b;
    else
        result = a;

    return result; 
}

uint64_t mul_inv(uint64_t a, uint64_t m){
    uint64_t d0 = a, d1 = m;
    uint64_t x0 = 1, x1 = 0;

    uint64_t q = d0 / d1;
    uint64_t d2 = d0 - q * d1;
    uint64_t x2 = x0 - q * x1;

    while (d2 > 1){
        q = d0 / d1;
        d2 = d0 - q * d1;
        x2 = x0 - q * x1;

        d0 = d1;
        d1 = d2;
        x0 = x1;
        x1 = x2;
    }

    if (d2 == 1)
        return (x2 > (uint64_t)1<<63 ? x2+m : x2);
    else
        return 0;
}

uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m)
{
    a = a - (a / m) * m;
    b = b - (b / m) * m;

    return ((a >= m - b) ? a - (m - b) : a + b);
}

uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r=0;

    while (b > 0){
        if (b & 1) r = mod_add(r, a, m);
        b = b >> 1;
        a = mod_add(a, a, m);
    }

    return r;
}

uint64_t mod_pow(uint64_t a, uint64_t b, uint64_t m)
{
    uint64_t r=1;

    while (b > 0){
        if (b & 1) r = mod_mul(r, a, m);
        b = b >> 1;
        a = mod_mul(a, a, m);
    }

    return r;
}

int miller_rabin(uint64_t n)
{
    if (n % 2 == 0 && n != 2) return COMPOSITE;

    int k = 0;
    uint64_t q = n-1;

    while ((q % 2) == 0){
        q /= 2;
        k++;
    }

    for (int i=0; i<ALEN && a[i] < n-1; i++){
        uint64_t x = mod_pow(a[i], q, n);
        int count = 0;

        if (x == 1) continue;

        for (int j = 0; j < k; j++){
            if (mod_pow(x, 1 << j, n) == n-1){
                count++;
                break;
            }
        }

        if (count == 0) return COMPOSITE;
    }
    return PRIME;
}
