#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

int main(int argc, char* argv[]){
    mpz_t p, q, candidate;
    gmp_randstate_t state;
    int runs = 25;
    int bits_p = 166;
    int bits_q = 173;
    
    mpz_init(p);
    mpz_init(q);
    mpz_init(candidate);
    gmp_randinit_mt(state);
    gmp_randseed_ui(state, time(NULL));

    // Generate prime p
    mpz_urandomb(candidate, state, bits_p);
    mpz_setbit(candidate, bits_p-1);
    mpz_setbit(candidate, 0);
    mpz_nextprime(p, candidate);

    // Generate prime q
    mpz_urandomb(candidate, state, bits_q);
    mpz_setbit(candidate, bits_q-1);
    mpz_setbit(candidate, 0);
    mpz_nextprime(q, candidate);

    if (mpz_probab_prime_p(p, runs) < 1 || mpz_probab_prime_p(q, runs) < 1) {
        printf("{\"error\": \"Primality test failed\"}\n");
        return 1;
    }

    mpz_t n, p_n, e, d, p_1, q_1, gcd;
    mpz_inits(n, p_n, e, d, p_1, q_1, gcd, NULL);

    // Calculate n = p * q
    mpz_mul(n, p, q);

    // Calculate phi(n) = (p-1)(q-1)
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(p_n, p_1, q_1);

    // Find e such that gcd(e, phi(n)) = 1
    mpz_set_ui(e, 65537); // Common choice for e
    mpz_gcd(gcd, e, p_n);
    
    while(mpz_cmp_ui(gcd, 1) != 0) {
        mpz_add_ui(e, e, 2);
        mpz_gcd(gcd, e, p_n);
    }

    // Calculate d = e^(-1) mod phi(n)
    mpz_invert(d, e, p_n);

    // Output JSON
    printf("{\n");
    printf("  \"publicKey\": {\n");
    printf("    \"n\": \"");
    mpz_out_str(stdout, 10, n);
    printf("\",\n");
    printf("    \"e\": \"");
    mpz_out_str(stdout, 10, e);
    printf("\"\n");
    printf("  },\n");
    printf("  \"privateKey\": {\n");
    printf("    \"n\": \"");
    mpz_out_str(stdout, 10, n);
    printf("\",\n");
    printf("    \"d\": \"");
    mpz_out_str(stdout, 10, d);
    printf("\"\n");
    printf("  }\n");
    printf("}\n");

    mpz_clears(p, q, candidate, n, p_n, e, d, p_1, q_1, gcd, NULL);
    gmp_randclear(state);
    return 0;
}