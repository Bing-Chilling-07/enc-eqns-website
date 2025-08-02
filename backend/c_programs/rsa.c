#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

// Function to generate RSA key pair
void generate_keys() {
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
        return;
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
}

// Function to encrypt a message
void encrypt_message(const char* message, const char* n_str, const char* e_str) {
    mpz_t n, e, msg, enc_msg;
    mpz_inits(n, e, msg, enc_msg, NULL);

    // Parse public key
    if (mpz_set_str(n, n_str, 10) != 0 || mpz_set_str(e, e_str, 10) != 0) {
        printf("{\"error\": \"Invalid public key format\"}\n");
        mpz_clears(n, e, msg, enc_msg, NULL);
        return;
    }

    // Convert message to number (treating as decimal string or converting from text)
    if (mpz_set_str(msg, message, 10) != 0) {
        // If not a valid number, convert text to big integer
        mpz_set_ui(msg, 0);
        for (int i = 0; message[i] != '\0'; i++) {
            mpz_mul_ui(msg, msg, 256);
            mpz_add_ui(msg, msg, (unsigned char)message[i]);
        }
    }

    // Check if message < n
    if (mpz_cmp(msg, n) >= 0) {
        printf("{\"error\": \"Message too large for key size\"}\n");
        mpz_clears(n, e, msg, enc_msg, NULL);
        return;
    }

    // Encrypt: c = m^e mod n
    mpz_powm(enc_msg, msg, e, n);

    // Output JSON
    printf("{\n");
    printf("  \"encrypted\": \"");
    mpz_out_str(stdout, 16, enc_msg); // Output in hex for better readability
    printf("\",\n");
    printf("  \"original\": \"");
    mpz_out_str(stdout, 10, msg);
    printf("\"\n");
    printf("}\n");

    mpz_clears(n, e, msg, enc_msg, NULL);
}

// Function to decrypt a message
void decrypt_message(const char* encrypted_hex, const char* n_str, const char* d_str) {
    mpz_t n, d, enc_msg, dec_msg;
    mpz_inits(n, d, enc_msg, dec_msg, NULL);

    // Parse private key
    if (mpz_set_str(n, n_str, 10) != 0 || mpz_set_str(d, d_str, 10) != 0) {
        printf("{\"error\": \"Invalid private key format\"}\n");
        mpz_clears(n, d, enc_msg, dec_msg, NULL);
        return;
    }

    // Parse encrypted message (assuming hex format)
    if (mpz_set_str(enc_msg, encrypted_hex, 16) != 0) {
        printf("{\"error\": \"Invalid encrypted message format\"}\n");
        mpz_clears(n, d, enc_msg, dec_msg, NULL);
        return;
    }

    // Decrypt: m = c^d mod n
    mpz_powm(dec_msg, enc_msg, d, n);

    // Try to convert back to text
    char* result_text = malloc(1000); // Allocate buffer for text
    result_text[0] = '\0';
    
    mpz_t temp, remainder;
    mpz_inits(temp, remainder, NULL);
    mpz_set(temp, dec_msg);
    
    char temp_str[1000] = "";
    int pos = 0;
    
    // Convert big integer back to text
    while (mpz_cmp_ui(temp, 0) > 0 && pos < 999) {
        mpz_tdiv_qr_ui(temp, remainder, temp, 256);
        unsigned long char_val = mpz_get_ui(remainder);
        if (char_val > 0 && char_val < 256) {
            temp_str[pos++] = (char)char_val;
        } else {
            break;
        }
    }
    
    // Reverse the string
    for (int i = 0; i < pos; i++) {
        result_text[i] = temp_str[pos - 1 - i];
    }
    result_text[pos] = '\0';

    // Output JSON
    printf("{\n");
    printf("  \"decrypted\": \"");
    mpz_out_str(stdout, 10, dec_msg);
    printf("\",\n");
    printf("  \"text\": \"%s\"\n", result_text);
    printf("}\n");

    free(result_text);
    mpz_clears(n, d, enc_msg, dec_msg, temp, remainder, NULL);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("{\"error\": \"Usage: %s <command> [args...]\"}\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "generate") == 0) {
        generate_keys();
    }
    else if (strcmp(argv[1], "encrypt") == 0) {
        if (argc != 5) {
            printf("{\"error\": \"Usage: %s encrypt <message> <n> <e>\"}\n", argv[0]);
            return 1;
        }
        encrypt_message(argv[2], argv[3], argv[4]);
    }
    else if (strcmp(argv[1], "decrypt") == 0) {
        if (argc != 5) {
            printf("{\"error\": \"Usage: %s decrypt <encrypted_hex> <n> <d>\"}\n", argv[0]);
            return 1;
        }
        decrypt_message(argv[2], argv[3], argv[4]);
    }
    else {
        printf("{\"error\": \"Unknown command: %s\"}\n", argv[1]);
        return 1;
    }

    return 0;
}