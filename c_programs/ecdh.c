#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <gmp.h>
#include <sys/types.h>

struct point {
    mpz_t x, y;
};

void cube(mpz_t x, mpz_t x3, mpz_t m){
    mpz_pow_ui(x3, x, 3);
    mpz_mod(x3, x3, m);
}

int y_2(mpz_t y2, mpz_t y, mpz_t m) {
    if (mpz_cmp_ui(y2, 0) == 0) {
        mpz_set_ui(y, 0);
        return 1;
    }
    if (mpz_legendre(y2, m) != 1) {
        return 0;
    }

    if (mpz_tstbit(m, 0) && mpz_tstbit(m, 1)) {
        mpz_t exp;
        mpz_init(exp);
        mpz_add_ui(exp, m, 1);
        mpz_fdiv_q_ui(exp, exp, 4);
        mpz_powm(y, y2, exp, m);
        mpz_clear(exp);
        return 1;
    }

    mpz_t q, s, z, c, t, r, b, tmp;
    unsigned long int i, e;
    mpz_inits(q, s, z, c, t, r, b, tmp, NULL);

    mpz_sub_ui(q, m, 1);
    mpz_set_ui(s, 0);
    while (mpz_even_p(q)) {
        mpz_fdiv_q_2exp(q, q, 1);
        mpz_add_ui(s, s, 1);
    }

    mpz_set_ui(z, 2);
    while (mpz_legendre(z, m) != -1) {
        mpz_add_ui(z, z, 1);
    }

    mpz_powm(c, z, q, m);
    mpz_add_ui(tmp, q, 1);
    mpz_fdiv_q_ui(tmp, tmp, 2);
    mpz_powm(r, y2, tmp, m);
    mpz_powm(t, y2, q, m);

    e = mpz_get_ui(s);
    while (mpz_cmp_ui(t, 1) != 0) {
        mpz_set(tmp, t);
        for (i = 1; i < e; i++) {
            mpz_powm_ui(tmp, tmp, 2, m);
            if (mpz_cmp_ui(tmp, 1) == 0) break;
        }
        mpz_powm_ui(b, c, 1UL << (e - i - 1), m);
        mpz_mul(r, r, b); mpz_mod(r, r, m);
        mpz_mul(c, b, b); mpz_mod(c, c, m);
        mpz_mul(t, t, c); mpz_mod(t, t, m);
        e = i;
    }

    mpz_mod(r, r, m);
    mpz_set(y, r);
    mpz_clears(q, s, z, c, t, r, b, tmp, NULL);
    return 1;
}

void add_points(struct point *P, struct point *Q, struct point *R, mpz_t a, mpz_t b, mpz_t m) {
    if (mpz_cmp_ui(P->x, 0)==0 && mpz_cmp_ui(P->y,0)==0) {
        mpz_set(R->x, Q->x);
        mpz_set(R->y, Q->y);
        return;
    }
    if (mpz_cmp_ui(Q->x, 0)==0 && mpz_cmp_ui(Q->y,0)==0) {
        mpz_set(R->x, P->x);
        mpz_set(R->y, P->y);
        return;
    }

    mpz_t sumy;
    mpz_init(sumy);
    mpz_add(sumy, P->y, Q->y);
    mpz_mod(sumy, sumy, m);
    if (mpz_cmp(P->x, Q->x)==0 && mpz_cmp_ui(sumy,0)==0) {
        mpz_set_ui(R->x, 0);
        mpz_set_ui(R->y, 0);
        mpz_clear(sumy);
        return;
    }
    mpz_clear(sumy);

    mpz_t lam, inv, tmp;
    mpz_inits(lam, inv, tmp, NULL);

    if (mpz_cmp(P->x, Q->x)==0 && mpz_cmp(P->y, Q->y)==0) {
        mpz_mul(lam, P->x, P->x);
        mpz_mul_ui(lam, lam, 3);
        mpz_add(lam, lam, a);
        mpz_mul_ui(tmp, P->y, 2);
        mpz_invert(inv, tmp, m);
    } else {
        mpz_sub(lam, Q->y, P->y);
        mpz_sub(tmp, Q->x, P->x);
        mpz_invert(inv, tmp, m);
    }
    mpz_mul(lam, lam, inv);
    mpz_mod(lam, lam, m);

    mpz_mul(tmp, lam, lam);
    mpz_sub(tmp, tmp, P->x);
    mpz_sub(tmp, tmp, Q->x);
    mpz_mod(R->x, tmp, m);

    mpz_sub(tmp, P->x, R->x);
    mpz_mul(tmp, lam, tmp);
    mpz_sub(tmp, tmp, P->y);
    mpz_mod(R->y, tmp, m);

    mpz_clears(lam, inv, tmp, NULL);
}

void point_multiplier(struct point *G, struct point *out, mpz_t a, mpz_t b, mpz_t m, mpz_t n) {
    struct point result, base, tmp;
    mpz_inits(result.x, result.y, base.x, base.y, tmp.x, tmp.y, NULL);

    mpz_set_ui(result.x, 0);
    mpz_set_ui(result.y, 0);
    mpz_set(base.x, G->x);
    mpz_set(base.y, G->y);

    size_t n_bits = mpz_sizeinbase(n, 2);
    for (size_t i = 0; i < n_bits; ++i) {
        if (mpz_tstbit(n, i)) {
            add_points(&result, &base, &tmp, a, b, m);
            mpz_set(result.x, tmp.x);
            mpz_set(result.y, tmp.y);
        }
        add_points(&base, &base, &tmp, a, b, m);
        mpz_set(base.x, tmp.x);
        mpz_set(base.y, tmp.y);
    }

    mpz_set(out->x, result.x);
    mpz_set(out->y, result.y);

    mpz_clears(result.x, result.y, base.x, base.y, tmp.x, tmp.y, NULL);
}

void generate_secure_mpz(mpz_t result, int num_bits) {
    int num_bytes = (num_bits + 7) / 8;
    unsigned char buffer[64];
    if (num_bytes > sizeof(buffer)) {
        fprintf(stderr, "Too many bits requested.\n");
        return;
    }

    if (RAND_bytes(buffer, num_bytes) != 1) {
        fprintf(stderr, "OpenSSL RAND_bytes failed\n");
        return;
    }

    mpz_import(result, num_bytes, 1, 1, 0, 0, buffer);

    if (mpz_sizeinbase(result, 2) > num_bits) {
        mpz_fdiv_r_2exp(result, result, num_bits);
    }
}

void print_json_error(const char* message) {
    printf("{\"error\":\"%s\"}\n", message);
}

void print_json_success(const char* action, mpz_t priv_a, mpz_t priv_b, 
                       struct point *pub_a, struct point *pub_b, 
                       struct point *shared, mpz_t a, mpz_t b, mpz_t m, 
                       struct point *g) {
    printf("{\n");
    printf("  \"success\": true,\n");
    printf("  \"action\": \"%s\",\n", action);
    
    if (strcmp(action, "generate") == 0 || strcmp(action, "exchange") == 0) {
        printf("  \"curve\": {\n");
        gmp_printf("    \"a\": \"%Zd\",\n", a);
        gmp_printf("    \"b\": \"%Zd\",\n", b);
        gmp_printf("    \"m\": \"%Zd\",\n", m);
        gmp_printf("    \"generator\": {\"x\": \"%Zx\", \"y\": \"%Zx\"}\n", g->x, g->y);
        printf("  },\n");
        
        printf("  \"alice\": {\n");
        gmp_printf("    \"privateKey\": \"%Zx\",\n", priv_a);
        gmp_printf("    \"publicKey\": {\"x\": \"%Zx\", \"y\": \"%Zx\"}\n", pub_a->x, pub_a->y);
        printf("  },\n");
        
        printf("  \"bob\": {\n");
        gmp_printf("    \"privateKey\": \"%Zx\",\n", priv_b);
        gmp_printf("    \"publicKey\": {\"x\": \"%Zx\", \"y\": \"%Zx\"}\n", pub_b->x, pub_b->y);
        printf("  }");
        
        if (shared) {
            printf(",\n");
            printf("  \"sharedSecret\": {\n");
            gmp_printf("    \"x\": \"%Zx\",\n", shared->x);
            gmp_printf("    \"y\": \"%Zx\"\n", shared->y);
            printf("  }");
        }
    }
    
    printf("\n}\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_json_error("Usage: ecdh <action> [parameters]");
        return 1;
    }
    
    mpz_t a, b, m;
    struct point g;
    mpz_inits(a, b, m, g.x, g.y, NULL);
    
    // Default curve parameters (can be customized via arguments)
    mpz_set_ui(a, 5);
    mpz_set_ui(b, 87);
    mpz_set_ui(m, 524287);
    mpz_set_ui(g.x, 3);
    mpz_set_ui(g.y, 47926);
    
    if (strcmp(argv[1], "generate") == 0) {
        // Parse custom curve parameters if provided
        if (argc >= 8) {
            if (mpz_set_str(a, argv[2], 10) != 0 ||
                mpz_set_str(b, argv[3], 10) != 0 ||
                mpz_set_str(m, argv[4], 10) != 0 ||
                mpz_set_str(g.x, argv[5], 16) != 0 ||
                mpz_set_str(g.y, argv[6], 16) != 0) {
                print_json_error("Invalid curve parameters");
                return 1;
            }
        }
        
        mpz_t priv_a, priv_b;
        struct point pub_a, pub_b;
        mpz_inits(priv_a, priv_b, pub_a.x, pub_a.y, pub_b.x, pub_b.y, NULL);
        
        // Parse custom private keys if provided
        if (argc >= 10) {
            if (mpz_set_str(priv_a, argv[7], 16) != 0 ||
                mpz_set_str(priv_b, argv[8], 16) != 0) {
                print_json_error("Invalid private keys");
                return 1;
            }
        } else {
            // Generate random private keys
            generate_secure_mpz(priv_a, 256);
            generate_secure_mpz(priv_b, 256);
            
            // Ensure private keys are not zero
            if (mpz_cmp_ui(priv_a, 0) == 0) mpz_set_ui(priv_a, 1);
            if (mpz_cmp_ui(priv_b, 0) == 0) mpz_set_ui(priv_b, 1);
        }
        
        // Generate public keys
        point_multiplier(&g, &pub_a, a, b, m, priv_a);
        point_multiplier(&g, &pub_b, a, b, m, priv_b);
        
        print_json_success("generate", priv_a, priv_b, &pub_a, &pub_b, NULL, a, b, m, &g);
        
        mpz_clears(priv_a, priv_b, pub_a.x, pub_a.y, pub_b.x, pub_b.y, NULL);
        
    } else if (strcmp(argv[1], "exchange") == 0) {
        if (argc < 12) {
            print_json_error("Usage: ecdh exchange <a> <b> <m> <gx> <gy> <priv_a> <priv_b> [pub_ax] [pub_ay] [pub_bx] [pub_by]");
            return 1;
        }
        
        // Parse all parameters
        if (mpz_set_str(a, argv[2], 10) != 0 ||
            mpz_set_str(b, argv[3], 10) != 0 ||
            mpz_set_str(m, argv[4], 10) != 0 ||
            mpz_set_str(g.x, argv[5], 16) != 0 ||
            mpz_set_str(g.y, argv[6], 16) != 0) {
            print_json_error("Invalid curve parameters");
            return 1;
        }
        
        mpz_t priv_a, priv_b;
        struct point pub_a, pub_b, shared_a, shared_b;
        mpz_inits(priv_a, priv_b, pub_a.x, pub_a.y, pub_b.x, pub_b.y, 
                 shared_a.x, shared_a.y, shared_b.x, shared_b.y, NULL);
        
        if (mpz_set_str(priv_a, argv[7], 16) != 0 ||
            mpz_set_str(priv_b, argv[8], 16) != 0) {
            print_json_error("Invalid private keys");
            return 1;
        }
        
        // Check if public keys are provided
        if (argc >= 14) {
            if (mpz_set_str(pub_a.x, argv[9], 16) != 0 ||
                mpz_set_str(pub_a.y, argv[10], 16) != 0 ||
                mpz_set_str(pub_b.x, argv[11], 16) != 0 ||
                mpz_set_str(pub_b.y, argv[12], 16) != 0) {
                print_json_error("Invalid public keys");
                return 1;
            }
        } else {
            // Generate public keys from private keys
            point_multiplier(&g, &pub_a, a, b, m, priv_a);
            point_multiplier(&g, &pub_b, a, b, m, priv_b);
        }
        
        // Perform key exchange
        point_multiplier(&pub_b, &shared_a, a, b, m, priv_a); // Alice computes shared secret
        point_multiplier(&pub_a, &shared_b, a, b, m, priv_b); // Bob computes shared secret
        
        // Verify shared secrets match
        if (mpz_cmp(shared_a.x, shared_b.x) != 0 || mpz_cmp(shared_a.y, shared_b.y) != 0) {
            print_json_error("Shared secrets do not match!");
            return 1;
        }
        
        print_json_success("exchange", priv_a, priv_b, &pub_a, &pub_b, &shared_a, a, b, m, &g);
        
        mpz_clears(priv_a, priv_b, pub_a.x, pub_a.y, pub_b.x, pub_b.y, 
                  shared_a.x, shared_a.y, shared_b.x, shared_b.y, NULL);
        
    } else if (strcmp(argv[1], "compute_shared") == 0) {
        if (argc < 9) {
            print_json_error("Usage: ecdh compute_shared <a> <b> <m> <private_key> <public_x> <public_y>");
            return 1;
        }
        
        if (mpz_set_str(a, argv[2], 10) != 0 ||
            mpz_set_str(b, argv[3], 10) != 0 ||
            mpz_set_str(m, argv[4], 10) != 0) {
            print_json_error("Invalid curve parameters");
            return 1;
        }
        
        mpz_t private_key;
        struct point public_key, shared_secret;
        mpz_inits(private_key, public_key.x, public_key.y, shared_secret.x, shared_secret.y, NULL);
        
        if (mpz_set_str(private_key, argv[5], 16) != 0 ||
            mpz_set_str(public_key.x, argv[6], 16) != 0 ||
            mpz_set_str(public_key.y, argv[7], 16) != 0) {
            print_json_error("Invalid keys");
            return 1;
        }
        
        // Compute shared secret
        point_multiplier(&public_key, &shared_secret, a, b, m, private_key);
        
        printf("{\n");
        printf("  \"success\": true,\n");
        printf("  \"action\": \"compute_shared\",\n");
        printf("  \"sharedSecret\": {\n");
        gmp_printf("    \"x\": \"%Zx\",\n", shared_secret.x);
        gmp_printf("    \"y\": \"%Zx\"\n", shared_secret.y);
        printf("  }\n");
        printf("}\n");
        
        mpz_clears(private_key, public_key.x, public_key.y, shared_secret.x, shared_secret.y, NULL);
        
    } else {
        print_json_error("Unknown action. Use: generate, exchange, or compute_shared");
        return 1;
    }
    
    mpz_clears(a, b, m, g.x, g.y, NULL);
    return 0;
}