//#include <emscripten/bind.h>
#include "wasm_interface.h"

void read_fmpz_poly(fmpz_mod_poly_t f, const poly_rep g, encryption_scheme_t encryption_scheme) {
    fmpz_mod_poly_init(f, encryption_scheme->ctx_p);
    utils_fmpz_mod_poly_from_string(f, g);
}

void read_nmod_poly(nmod_poly_t f, const poly_rep g) {
    nmod_poly_init(f, MODP);
    utils_nmod_poly_from_string(f, g);
}

void read_commitkey(commitkey_t *key, const PK_C pkC) {
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            for (int k = 0; k < 2; k++) {
                read_nmod_poly(key->B1[i][j][k], pkC.B1[i][j][k]);
            }
        }
    }
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            read_nmod_poly(key->b2[i][j], pkC.b2[i][j]);
        }
    }

}

void read_publickey(publickey_t *key, const PK_VE pkV, encryption_scheme_t encryption_scheme) {
    for (int i = 0; i < DIM; i++) {
        for (int j = 0; j < DIM; j++) {
            for (int k = 0; k < 2; k++) {
                read_fmpz_poly(key->A[i][j][k], pkV.A[i][j][k], encryption_scheme);
            }
        }
    }
    for (int i = 0; i < DIM; i++) {
        for (int j = 0; j < 2; j++) {
            read_fmpz_poly(key->t[i][j], pkV.t[i][j], encryption_scheme);
        }
    }
}

void read_commitment(commit_t *c, const COM com) {
    for (int i = 0; i < 2; i++) {
        read_nmod_poly(c->c1[i], com.c1[i]);
        read_nmod_poly(c->c2[i], com.c2[i]);
    }
}

void wasm_commit_doit(commitment_scheme_t commitment_scheme, commit_t *c, nmod_poly_t m, commitkey_t *pk_C, pcrt_poly_t d[WIDTH]) {
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_init(d[i][j], MODP);
        }
        commit_sample_short_crt(commitment_scheme, d[i]);
    }
    commit_doit(commitment_scheme, c, m, pk_C, d);
}

void opening_to_fmpz(commitment_scheme_t commitment_scheme, encryption_scheme_t encryption_scheme,
                     fmpz_mod_poly_t f[WIDTH], pcrt_poly_t d[WIDTH]) {
    nmod_poly_t aux;
    nmod_poly_init(aux, MODP);
    for (int i = 0; i < WIDTH; i++) {
        fmpz_mod_poly_init(f[i], *encrypt_modulus_ctx(encryption_scheme));
        pcrt_poly_rec(commitment_scheme, aux, d[i]);
        utils_nmod_to_fmpz(f[i], aux);
    }
    nmod_poly_clear(aux);
}

void encrypt_opening(commitment_scheme_t commitment_scheme, encryption_scheme_t  encryption_scheme, veritext_t *e,
                     publickey_t *pk, pcrt_poly_t d[WIDTH], commit_t *c, commitkey_t *key, flint_rand_t rand) {
    fmpz_mod_poly_t u;
    fmpz_mod_poly_init(u, *encrypt_modulus_ctx(encryption_scheme));

    nmod_poly_t aux;
    nmod_poly_init(aux, MODP);
    pcrt_poly_rec(commitment_scheme, aux, c->c1);

    utils_nmod_to_fmpz(u, aux);

    fmpz_mod_poly_t t[VECTOR];
    opening_to_fmpz(commitment_scheme, encryption_scheme, t, key->B1[0]);

    fmpz_mod_poly_t fmpz_d[VECTOR];
    opening_to_fmpz(commitment_scheme, encryption_scheme, fmpz_d, d);

    vericrypt_doit(e, t, u, fmpz_d, encryption_scheme, pk, rand);

    fmpz_mod_poly_clear(u, *encrypt_modulus_ctx(encryption_scheme));
    for (int i = 0; i < VECTOR; i++) {
        fmpz_mod_poly_clear(t[i], *encrypt_modulus_ctx(encryption_scheme));
    }
    nmod_poly_clear(aux);
}

void gen_sum_proof(commitment_scheme_t commitment_scheme, SUM_PROOF *psum, commitkey_t *key, commit_t c,
                   commit_t c_a, commit_t c_r, pcrt_poly_t d[WIDTH], pcrt_poly_t d_a[WIDTH],
                   pcrt_poly_t d_r[WIDTH]) {
    nmod_poly_t alpha, beta;

    nmod_poly_init(alpha, MODP);
    nmod_poly_init(beta, MODP);
    nmod_poly_one(alpha);
    nmod_poly_one(beta);

    nmod_poly_t y1[WIDTH][2], y2[WIDTH][2], y3[WIDTH][2];
    nmod_poly_t t1[2], t2[2], t3[2], u[2];

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_init(y1[i][j], MODP);
            nmod_poly_init(y2[i][j], MODP);
            nmod_poly_init(y3[i][j], MODP);
        }
    }
    for (int i = 0; i < 2; i++) {
        nmod_poly_init(t1[i], MODP);
        nmod_poly_init(t2[i], MODP);
        nmod_poly_init(t3[i], MODP);
        nmod_poly_init(u[i], MODP);
    }

    sum_prover(y1, y2, y3, t1, t2, t3, u, commitment_scheme,
               c, c_a, c_r, key, alpha, beta, d, d_a, d_r);

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            psum->y1[i][j] = utils_nmod_poly_to_string(y1[i][j]);
            psum->y2[i][j] = utils_nmod_poly_to_string(y2[i][j]);
            psum->y3[i][j] = utils_nmod_poly_to_string(y3[i][j]);
        }
    }

    for (int i = 0; i < 2; i++) {
        psum->t1[i] = utils_nmod_poly_to_string(t1[i]);
        psum->t2[i] = utils_nmod_poly_to_string(t2[i]);
        psum->t3[i] = utils_nmod_poly_to_string(t3[i]);
        psum->u[i] = utils_nmod_poly_to_string(u[i]);
    }

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(y1[i][j]);
            nmod_poly_clear(y2[i][j]);
            nmod_poly_clear(y3[i][j]);
        }
    }

    for (int i = 0; i < 2; i++) {
        nmod_poly_clear(t1[i]);
        nmod_poly_clear(t2[i]);
        nmod_poly_clear(t3[i]);
        nmod_poly_clear(u[i]);
    }

    nmod_poly_clear(alpha);
    nmod_poly_clear(beta);
}

void build_ev(EV *ev, commit_t *c, veritext_t *e, encryption_scheme_t encryption_scheme) {
    for (int i = 0; i < 2; i++) {
        ev->c.c1[i] = utils_nmod_poly_to_string(c->c1[i]);
        ev->c.c2[i] = utils_nmod_poly_to_string(c->c2[i]);
    }
    for (int i = 0; i < VECTOR; i++) {
        for (int j = 0; j < DIM; j++) {
            for (int k = 0; k < 2; k++) {
                ev->cipher[i].v[j][k] = utils_fmpz_mod_poly_to_string(e->cipher[i].v[j][k],
                                                                   *encrypt_modulus_ctx(encryption_scheme));
            }
        }
        for (int j = 0; j < 2; j++) {
            ev->cipher[i].w[j] = utils_fmpz_mod_poly_to_string(e->cipher[i].w[j],
                                                            *encrypt_modulus_ctx(encryption_scheme));
        }
    }
    ev->e_c = utils_fmpz_mod_poly_to_string(e->c, *encrypt_modulus_ctx(encryption_scheme));
}

void build_proof(PROOF *proof, veritext_t *e, commit_t *c_r, veritext_t *e_r, SUM_PROOF *psum,
                 encryption_scheme_t encryption_scheme) {
    for (int i = 0; i < VECTOR; i++) {
        for (int j = 0; j < DIM; j++) {
            for (int k = 0; k < 2; k++) {
                proof->z.r[i][j][k] = utils_fmpz_mod_poly_to_string(e->r[i][j][k],
                                                                *encrypt_modulus_ctx(encryption_scheme));
                proof->z.e[i][j][k] = utils_fmpz_mod_poly_to_string(e->e[i][j][k],
                                                                *encrypt_modulus_ctx(encryption_scheme));
            }
        }
        for (int j = 0; j < 2; j++) {
            proof->z.e_[i][j] = utils_fmpz_mod_poly_to_string(e->e_[i][j],
                                                           *encrypt_modulus_ctx(encryption_scheme));
        }
        proof->z.u[i] = utils_fmpz_mod_poly_to_string(e->u[i], *encrypt_modulus_ctx(encryption_scheme));
    }

    for (int i = 0; i < 2; i++) {
        proof->c_r.c1[i] = utils_nmod_poly_to_string(c_r->c1[i]);
        proof->c_r.c2[i] = utils_nmod_poly_to_string(c_r->c2[i]);
    }

    for (int i = 0; i < VECTOR; i++) {
        for (int j = 0; j < DIM; j++) {
            for (int k = 0; k < 2; k++) {
                proof->e_r.cipher[i].v[j][k] = utils_fmpz_mod_poly_to_string(e_r->cipher[i].v[j][k],
                                                                    *encrypt_modulus_ctx(encryption_scheme));
                proof->e_r.r[i][j][k] = utils_fmpz_mod_poly_to_string(e_r->r[i][j][k],
                                                                *encrypt_modulus_ctx(encryption_scheme));
                proof->e_r.e[i][j][k] = utils_fmpz_mod_poly_to_string(e_r->e[i][j][k],
                                                                *encrypt_modulus_ctx(encryption_scheme));
            }
        }
        for (int j = 0; j < 2; j++) {
            proof->e_r.cipher[i].w[j] = utils_fmpz_mod_poly_to_string(e_r->cipher[i].w[j],
                                                                      *encrypt_modulus_ctx(encryption_scheme));
            proof->e_r.e_[i][j] = utils_fmpz_mod_poly_to_string(e_r->e_[i][j],
                                                            *encrypt_modulus_ctx(encryption_scheme));
        }
        proof->e_r.u[i] = utils_fmpz_mod_poly_to_string(e_r->u[i], *encrypt_modulus_ctx(encryption_scheme));
    }
    proof->e_r.c = utils_fmpz_mod_poly_to_string(e_r->c, *encrypt_modulus_ctx(encryption_scheme));
}

void cast(const PK pk, const VCK vck, poly_rep v) {
    flint_rand_t rand;
    uint64_t buf[2];

    getrandom(buf, sizeof(buf), GRND_RANDOM);
    flint_randinit(rand);
    flint_randseed(rand, buf[0], buf[1]);

    commitment_scheme_t commitment_scheme;
    commit_scheme_init(commitment_scheme);

    encryption_scheme_t encryption_scheme;
    encrypt_setup(encryption_scheme);

    // PK
    commitkey_t pk_C;
    publickey_t pk_V, pk_R;

    read_commitkey(&pk_C, pk.pk_c);
    read_publickey(&pk_V, pk.pk_v, encryption_scheme);
    read_publickey(&pk_R, pk.pk_r, encryption_scheme);

    // VCK
    nmod_poly_t a;
    commit_t c_a;
    pcrt_poly_t d_a[WIDTH];

    read_nmod_poly(a, vck.a);
    read_commitment(&c_a, vck.c_a);

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            read_nmod_poly(d_a[i][j], vck.d_a[i][j]);
        }
    }

    // vote
    nmod_poly_t vote;
    read_nmod_poly(vote, v);

    // computes (c, d) ← Com(pk_C , v)
    commit_t c;
    pcrt_poly_t d[WIDTH];
    wasm_commit_doit(commitment_scheme, &c, vote, &pk_C, d);

    // r ← a + v
    nmod_poly_t r;
    nmod_poly_init(r, MODP);
    nmod_poly_add(r, a, vote);

    // (c_r, d_r) ← Com(pk_C , r)
    commit_t c_r;
    pcrt_poly_t d_r[WIDTH];
    wasm_commit_doit(commitment_scheme, &c_r, r, &pk_C, d_r);

    // Π^sum is a proof that c, c_a and c_r satisfy the relation v + a = r
    SUM_PROOF psum;
    gen_sum_proof(commitment_scheme, &psum, &pk_C, c, c_a, c_r, d, d_a, d_r);

    veritext_t e, e_r;
    // e ← Enc_{VE} (pkV , d)
    encrypt_opening(commitment_scheme, encryption_scheme, &e, &pk_V, d, &c, &pk_C, rand);
    // e_r = (v_r , w_r , c_r , z_r ) ← Enc_{VE} (pk_R, d_r )
    encrypt_opening(commitment_scheme, encryption_scheme, &e_r, &pk_R, d_r, &c_r, &pk_C, rand);

    // The encrypted ballot is ev = (c, e.cipher, e.c)
    EV ev;
    build_ev(&ev, &c, &e, encryption_scheme);

    // the ballot proof is Π^v = (z, c_r , e_r , Π^lin_r )
    PROOF proof;
    build_proof(&proof, &e, &c_r, &e_r, &psum, encryption_scheme);

    flint_randclear(rand);

    // clear PK
    commit_keyfree(&pk_C);
    for (int i = 0; i < DIM; i++) {
        for (int j = 0; j < DIM; j++) {
            fmpz_mod_poly_clear(pk_V.t[i][j], encryption_scheme->ctx_q);
            fmpz_mod_poly_clear(pk_R.t[i][j], encryption_scheme->ctx_q);
            for (int k = 0; k < 2; k++) {
                fmpz_mod_poly_clear(pk_V.A[i][j][k], encryption_scheme->ctx_q);
                fmpz_mod_poly_clear(pk_R.A[i][j][k], encryption_scheme->ctx_q);
            }
        }
    }


    // clear VCK
    nmod_poly_clear(a);
    commit_free(&c_a);
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(d_a[i][j]);
        }
    }

    // clear vote
    nmod_poly_clear(vote);

    // clear c and d
    commit_free(&c);
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(d[i][j]);
        }
    }

    // clear r
    nmod_poly_clear(r);

    // clear c_r and d_r
    commit_free(&c_r);
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(d_r[i][j]);
        }
    }

    // clear e and e_r
    vericrypt_cipher_clear(&e, encryption_scheme);
    vericrypt_cipher_clear(&e_r, encryption_scheme);

    commit_scheme_finish(commitment_scheme);
    encrypt_finish(encryption_scheme);
}

int main() {
    PK pk;
    VCK vck;
    poly_rep v;
    cast(pk, vck, v);
    return 0;
}
