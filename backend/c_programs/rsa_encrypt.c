#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>

void print_json_escaped(const char* s) {
    for (; *s; s++) {
        switch (*s) {
            case '\"': printf("\\\""); break;
            case '\\': printf("\\\\"); break;
            case '\b': printf("\\b"); break;
            case '\f': printf("\\f"); break;
            case '\n': printf("\\n"); break;
            case '\r': printf("\\r"); break;
            case '\t': printf("\\t"); break;
            default:
                if ((unsigned char)*s < 0x20) // Control chars
                    printf("\\u%04x", (unsigned char)*s);
                else
                    putchar(*s);
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("{\"error\": \"Usage: %s <message> <n> <e>\"}\n", argv[0]);
        return 1;
    }

    const char* message = argv[1];
    const char* n_str = argv[2];
    const char* e_str = argv[3];

    mpz_t n, e, msg, enc_msg;
    mpz_inits(n, e, msg, enc_msg, NULL);

    // Parse public key
    if (mpz_set_str(n, n_str, 10) != 0 || mpz_set_str(e, e_str, 10) != 0) {
        printf("{\"error\": \"Invalid public key format\"}\n");
        mpz_clears(n, e, msg, enc_msg, NULL);
        return 1;
    }

    // Convert message to number
    // First try as a decimal number
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
        return 1;
    }

    // Encrypt: c = m^e mod n
    mpz_powm(enc_msg, msg, e, n);

    // Output JSON
    printf("{\n");
    printf("  \"success\": true,\n");
    printf("  \"encrypted\": \"");
    mpz_out_str(stdout, 16, enc_msg); // Output in hex
    printf("\",\n");
    printf("  \"originalNumber\": \"");
    mpz_out_str(stdout, 10, msg);
    printf("\",\n");
    printf("  \"originalText\": \"");
    print_json_escaped(message);
    printf("\"\n");
    printf("}\n");

    mpz_clears(n, e, msg, enc_msg, NULL);
    return 0;
}