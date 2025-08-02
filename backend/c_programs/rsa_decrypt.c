#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("{\"error\": \"Usage: %s <encrypted_hex> <n> <d>\"}\n", argv[0]);
        return 1;
    }

    const char* encrypted_hex = argv[1];
    const char* n_str = argv[2];
    const char* d_str = argv[3];

    mpz_t n, d, enc_msg, dec_msg;
    mpz_inits(n, d, enc_msg, dec_msg, NULL);

    // Parse private key
    if (mpz_set_str(n, n_str, 10) != 0 || mpz_set_str(d, d_str, 10) != 0) {
        printf("{\"error\": \"Invalid private key format\"}\n");
        mpz_clears(n, d, enc_msg, dec_msg, NULL);
        return 1;
    }

    // Parse encrypted message (hex format)
    if (mpz_set_str(enc_msg, encrypted_hex, 16) != 0) {
        printf("{\"error\": \"Invalid encrypted message format (expected hex)\"}\n");
        mpz_clears(n, d, enc_msg, dec_msg, NULL);
        return 1;
    }

    // Decrypt: m = c^d mod n
    mpz_powm(dec_msg, enc_msg, d, n);

    // Try to convert back to text
    char* result_text = malloc(1000);
    result_text[0] = '\0';
    
    mpz_t temp, remainder;
    mpz_inits(temp, remainder, NULL);
    mpz_set(temp, dec_msg);
    
    char temp_chars[1000];
    int pos = 0;
    
    // Convert big integer back to characters
    while (mpz_cmp_ui(temp, 0) > 0 && pos < 999) {
        mpz_tdiv_qr_ui(temp, remainder, temp, 256);
        unsigned long char_val = mpz_get_ui(remainder);
        if (char_val > 0 && char_val < 256) {
            temp_chars[pos++] = (char)char_val;
        } else {
            break;
        }
    }
    
    // Reverse the string (since we built it backwards)
    for (int i = 0; i < pos; i++) {
        result_text[i] = temp_chars[pos - 1 - i];
    }
    result_text[pos] = '\0';

    // Check if it's printable text
    int is_printable = 1;
    for (int i = 0; i < pos; i++) {
        if (result_text[i] < 32 || result_text[i] > 126) {
            if (result_text[i] != '\n' && result_text[i] != '\t') {
                is_printable = 0;
                break;
            }
        }
    }

    // Output JSON
    printf("{\n");
    printf("  \"success\": true,\n");
    printf("  \"decryptedNumber\": \"");
    mpz_out_str(stdout, 10, dec_msg);
    printf("\"");
    
    if (is_printable && pos > 0) {
        printf(",\n  \"decryptedText\": \"%s\"", result_text);
    }
    
    printf("\n}\n");

    free(result_text);
    mpz_clears(n, d, enc_msg, dec_msg, temp, remainder, NULL);
    return 0;
}