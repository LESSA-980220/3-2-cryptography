/*
 * Copyright 2020, 2021. Heekuck Oh, all rights reserved
 * 이 프로그램은 한양대학교 ERICA 소프트웨어학부 재학생을 위한 교육용으로 제작되었습니다.
 */
#include "miller_rabin.h"

/*
 * Miller-Rabin Primality Testing against small sets of bases
 *
 * if n < 2^64,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, and 37.
 *
 * if n < 3,317,044,064,679,887,385,961,981,
 * it is enough to test a = 2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, and 41.
 */
const uint64_t a[ALEN] = {2,3,5,7,11,13,17,19,23,29,31,37};

/*
 * miller_rabin() - Miller-Rabin Primality Test (deterministic version)
 *
 * n > 3, an odd integer to be tested for primality
 * It returns 1 if n is prime, 0 otherwise.
 */
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
