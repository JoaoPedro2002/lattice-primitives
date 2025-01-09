#include <math.h>

#include "param.h"
#include "sum.h"
#include "bench.h"
#include "test.h"
#include "assert.h"
#include "fastrandombytes.h"
#include "sha.h"

int rej_sampling(commitment_scheme_t commitment_scheme, nmod_poly_t z[WIDTH][2], nmod_poly_t v[WIDTH][2], uint64_t s2) {
    double r, M = 1.75;
    int64_t seed, dot, norm;
    mpf_t u;
    int64_t c0, c1;
    nmod_poly_t t0, t1;
    uint8_t buf[8];
    gmp_randstate_t state;
    int result;

    mpf_init(u);
    nmod_poly_init(t0, MODP);
    nmod_poly_init(t1, MODP);
    gmp_randinit_mt(state);

    getrandom(buf, sizeof(buf), 0);
    memcpy(&seed, buf, sizeof(buf));
    gmp_randseed_ui(state, seed);
    mpf_urandomb(u, state, mpf_get_default_prec());

    norm = dot = 0;
    for (int i = 0; i < WIDTH; i++) {
        pcrt_poly_rec(commitment_scheme, t0, z[i]);
        pcrt_poly_rec(commitment_scheme, t1, v[i]);
        for (int j = 0; j < DEGREE; j++) {
            c0 = nmod_poly_get_coeff_ui(t0, j);
            c1 = nmod_poly_get_coeff_ui(t1, j);
            if (c0 > MODP / 2)
                c0 -= MODP;
            if (c1 > MODP / 2)
                c1 -= MODP;
            dot += c0 * c1;
            norm += c1 * c1;
        }
    }

    r = -2.0 * dot + norm;
    r = r / (2.0 * s2);
    r = exp(r) / M;

    result = mpf_get_d(u) > r;

    mpf_clear(u);
    nmod_poly_clear(t0);
    nmod_poly_clear(t1);
    return result;
}

void sum_hash(nmod_poly_t d[2], commitment_scheme_t commitment_scheme, commitkey_t *key,
              commit_t x, commit_t y, commit_t z, nmod_poly_t alpha, nmod_poly_t beta,
              nmod_poly_t u[2], nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2]) {
    SHA256Context sha;
    uint8_t hash[SHA256HashSize];
    uint32_t buf;

    SHA256Reset(&sha);

    /* Hash public key. */
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            for (int k = 0; k < 2; k++) {
                SHA256Input(&sha, (const uint8_t *)key->B1[i][j][k]->coeffs,
                            key->B1[i][j][k]->alloc * sizeof(uint64_t));
                if (i == 0) {
                    SHA256Input(&sha, (const uint8_t *)key->b2[j][k]->coeffs,
                                key->b2[j][k]->alloc * sizeof(uint64_t));
                }
            }
        }
    }

    /* Hash alpha, beta from linear relation. */
    SHA256Input(&sha, (const uint8_t *)alpha->coeffs,
                alpha->alloc * sizeof(uint64_t));
    SHA256Input(&sha, (const uint8_t *)beta->coeffs,
                beta->alloc * sizeof(uint64_t));

    /* Hash [x1], [x2], [x3], t1, t2, t3 in CRT representation. */
    for (int i = 0; i < 2; i++) {
        SHA256Input(&sha, (const uint8_t *)x.c1[i]->coeffs,
                    x.c1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)x.c2[i]->coeffs,
                    x.c2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)y.c1[i]->coeffs,
                    y.c1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)y.c2[i]->coeffs,
                    y.c2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)z.c1[i]->coeffs,
                    z.c1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)z.c2[i]->coeffs,
                    z.c2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)u[i]->coeffs,
                    u[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)t1[i]->coeffs,
                    t1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)t2[i]->coeffs,
                    t2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)t3[i]->coeffs,
                    t3[i]->alloc * sizeof(uint64_t));
    }

    SHA256Result(&sha, hash);

    /* Sample challenge from RNG seeded with hash. */
    fastrandombytes_setseed(hash);
    for (int i = 0; i < 2; i++) {
        nmod_poly_fit_length(d[i], DEGREE);
        for (int j = 0; j < NONZERO; j++) {
            fastrandombytes((unsigned char *)&buf, sizeof(buf));
            buf = buf % DEGREE;
            while (nmod_poly_get_coeff_ui(d[i], buf) != 0) {
                fastrandombytes((unsigned char *)&buf, sizeof(buf));
                buf = buf % DEGREE;
            }
            nmod_poly_set_coeff_ui(d[i], buf, 1);
        }
    }
    nmod_poly_sub(d[1], d[0], d[1]);
    nmod_poly_rem(d[0], d[1], commitment_scheme->irred[0]);
    nmod_poly_rem(d[1], d[1], commitment_scheme->irred[1]);
}

// x3 = alpha * x1 + beta * x2
void sum_prover(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta, nmod_poly_t r1[WIDTH][2],
                nmod_poly_t r2[WIDTH][2], nmod_poly_t r3[WIDTH][2]) {
    nmod_poly_t tmp, d[2], dr1[WIDTH][2], dr2[WIDTH][2], dr3[WIDTH][2];
    int rej1, rej2, rej3;
    // Compute sigma^2 = (11 * v * beta * sqrt(k * N))^2.
    uint64_t sigma_sqr = 11 * NONZERO * BETA;
    sigma_sqr *= sigma_sqr * DEGREE * WIDTH;

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_init(dr1[i][j], MODP);
            nmod_poly_init(dr2[i][j], MODP);
            nmod_poly_init(dr3[i][j], MODP);
        }
    }
    nmod_poly_init(tmp, MODP);
    nmod_poly_init(d[0], MODP);
    nmod_poly_init(d[1], MODP);
    do {
        for (int i = 0; i < 2; i++) {
            nmod_poly_zero(t1[i]);
            nmod_poly_zero(t2[i]);
            nmod_poly_zero(t3[i]);
            nmod_poly_zero(u[i]);
            nmod_poly_zero(d[i]);
        }

        for (int i = 0; i < WIDTH; i++) {
            commit_sample_gauss_crt(commitment_scheme, y1[i]);
            commit_sample_gauss_crt(commitment_scheme, y2[i]);
            commit_sample_gauss_crt(commitment_scheme, y3[i]);
        }

        for (int i = 0; i < HEIGHT; i++) {
            for (int j = 0; j < WIDTH; j++) {
                for (int k = 0; k < 2; k++) {
                    nmod_poly_mulmod(tmp, key->B1[i][j][k], y1[j][k],
                                     *commit_irred(commitment_scheme, k));
                    nmod_poly_add(t1[k], t1[k], tmp);
                    nmod_poly_mulmod(tmp, key->B1[i][j][k], y2[j][k],
                                     *commit_irred(commitment_scheme, k));
                    nmod_poly_add(t2[k], t2[k], tmp);
                    nmod_poly_mulmod(tmp, key->B1[i][j][k], y3[j][k],
                                     *commit_irred(commitment_scheme, k));
                    nmod_poly_add(t3[k], t3[k], tmp);
                }
            }
        }

        for (int i = 0; i < WIDTH; i++) {
            for (int j = 0; j < 2; j++) {
                nmod_poly_mulmod(tmp, key->b2[i][j], y1[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_mulmod(tmp, tmp, alpha, *commit_irred(commitment_scheme, j));
                nmod_poly_add(u[j], u[j], tmp);

                nmod_poly_mulmod(tmp, key->b2[i][j], y2[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_mulmod(tmp, tmp, beta, *commit_irred(commitment_scheme, j));
                nmod_poly_add(u[j], u[j], tmp);

                nmod_poly_mulmod(tmp, key->b2[i][j], y3[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_sub(u[j], u[j], tmp);
            }
        }

        sum_hash(d, commitment_scheme, key, x1, x2, x3, alpha, beta, u, t1, t2, t3);

        /* Prover */
        for (int i = 0; i < WIDTH; i++) {
            for (int j = 0; j < 2; j++) {
                nmod_poly_mulmod(dr1[i][j], d[j], r1[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_add(y1[i][j], y1[i][j], dr1[i][j]);
                nmod_poly_mulmod(dr2[i][j], d[j], r2[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_add(y2[i][j], y2[i][j], dr2[i][j]);
                nmod_poly_mulmod(dr3[i][j], d[j], r3[i][j], *commit_irred(commitment_scheme, j));
                nmod_poly_add(y3[i][j], y3[i][j], dr3[i][j]);
            }
        }
        rej1 = rej_sampling(commitment_scheme, y1, dr1, sigma_sqr);
        rej2 = rej_sampling(commitment_scheme, y2, dr2, sigma_sqr);
        rej3 = rej_sampling(commitment_scheme, y3, dr3, sigma_sqr);
    } while (rej1 || rej2 || rej3);

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(dr1[i][j]);
            nmod_poly_clear(dr2[i][j]);
            nmod_poly_clear(dr3[i][j]);
        }
    }
    nmod_poly_clear(tmp);
    for (int i = 0; i < 2; i++) {
        nmod_poly_clear(d[i]);
    }
}

int sum_verifier(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                 nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                 commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                 commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta) {
    nmod_poly_t tmp, _d[2], v1[2], v2[2], v3[2], z1[WIDTH], z2[WIDTH], z3[WIDTH];
    int result = 1;

    nmod_poly_init(tmp, MODP);
    for (int i = 0; i < WIDTH; ++i) {
        nmod_poly_init(z1[i], MODP);
        nmod_poly_init(z2[i], MODP);
        nmod_poly_init(z3[i], MODP);
    }

    for (int i = 0; i < 2; i++) {
        nmod_poly_init(_d[i], MODP);
        nmod_poly_init(v1[i], MODP);
        nmod_poly_init(v2[i], MODP);
        nmod_poly_init(v3[i], MODP);
        nmod_poly_zero(v1[i]);
        nmod_poly_zero(v2[i]);
        nmod_poly_zero(v3[i]);
    }

    sum_hash(_d, commitment_scheme, key, x1, x2, x3, alpha, beta, u, t1, t2, t3);
    /* Verifier checks norm, reconstruct from CRT representation. */
    for (int i = 0; i < WIDTH; i++) {
        pcrt_poly_rec(commitment_scheme, z1[i], y1[i]);
        pcrt_poly_rec(commitment_scheme, z2[i], y2[i]);
        pcrt_poly_rec(commitment_scheme, z3[i], y3[i]);
        assert(commit_norm2_sqr(z1[i]) <= (uint64_t) 4 * DEGREE * SIGMA_C * SIGMA_C);
        assert(commit_norm2_sqr(z2[i]) <= (uint64_t) 4 * DEGREE * SIGMA_C * SIGMA_C);
        assert(commit_norm2_sqr(z3[i]) <= (uint64_t) 4 * DEGREE * SIGMA_C * SIGMA_C);
    }

    /* Verifier computes B1z1 and B1z2 B1z3. */
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            for (int k = 0; k < 2; k++) {
                nmod_poly_mulmod(tmp, key->B1[i][j][k], y1[j][k],
                                 *commit_irred(commitment_scheme, k));
                nmod_poly_add(v1[k], v1[k], tmp);
                nmod_poly_mulmod(tmp, key->B1[i][j][k], y2[j][k],
                                 *commit_irred(commitment_scheme, k));
                nmod_poly_add(v2[k], v2[k], tmp);
                nmod_poly_mulmod(tmp, key->B1[i][j][k], y3[j][k],
                                 *commit_irred(commitment_scheme, k));
                nmod_poly_add(v3[k], v3[k], tmp);
            }
        }
    }

    /*
     * Verifier checks that:
     *      B_1z1 = t1 + dc1_1;
     *      B_1z2 = t2 + dc1_2.
     *      B_1z3 = t3 + dc1_3.
     */
    for (int j = 0; j < 2; j++) {
        nmod_poly_mulmod(tmp, _d[j], x1.c1[j], *commit_irred(commitment_scheme, j));
        nmod_poly_add(t1[j], t1[j], tmp);
        nmod_poly_mulmod(tmp, _d[j], x2.c1[j], *commit_irred(commitment_scheme, j));
        nmod_poly_add(t2[j], t2[j], tmp);
        nmod_poly_mulmod(tmp, _d[j], x3.c1[j], *commit_irred(commitment_scheme, j));
        nmod_poly_add(t3[j], t3[j], tmp);

        result &= nmod_poly_equal(t1[j], v1[j]);
        result &= nmod_poly_equal(t2[j], v2[j]);
        result &= nmod_poly_equal(t3[j], v3[j]);
    }

    //    (αc2_1 + βc2_2 − c2_3)d + u
    for (int j = 0; j < 2; j++) {
        nmod_poly_mulmod(t1[j], alpha, x1.c2[j], *commit_irred(commitment_scheme, j));
        nmod_poly_mulmod(t2[j], beta, x2.c2[j], *commit_irred(commitment_scheme, j));
        nmod_poly_add(t1[j], t1[j], t2[j]);
        nmod_poly_sub(t1[j], t1[j], x3.c2[j]);
        nmod_poly_mulmod(t1[j], t1[j], _d[j], *commit_irred(commitment_scheme, j));
        nmod_poly_add(t1[j], t1[j], u[j]);
        nmod_poly_rem(t1[j], t1[j], *commit_irred(commitment_scheme, j));
    }

    nmod_poly_zero(v1[0]);
    nmod_poly_zero(v1[1]);

    //  α⟨b2, z1⟩ + β⟨b2, z2⟩ − ⟨b2, z3⟩
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_mulmod(tmp, key->b2[i][j], y1[i][j], *commit_irred(commitment_scheme, j));
            nmod_poly_mulmod(tmp, alpha, tmp, *commit_irred(commitment_scheme, j));
            nmod_poly_add(v1[j], v1[j], tmp);
            nmod_poly_mulmod(tmp, key->b2[i][j], y2[i][j], *commit_irred(commitment_scheme, j));
            nmod_poly_mulmod(tmp, beta, tmp, *commit_irred(commitment_scheme, j));
            nmod_poly_add(v1[j], v1[j], tmp);
            nmod_poly_mulmod(tmp, key->b2[i][j], y3[i][j], *commit_irred(commitment_scheme, j));
            nmod_poly_sub(v1[j], v1[j], tmp);
        }
    }
    for (int j = 0; j < 2; j++) {
        result &= nmod_poly_equal(t1[j], v1[j]);
    }

    nmod_poly_clear(tmp);
    for (int i = 0; i < WIDTH; i++) {
        nmod_poly_clear(z1[i]);
        nmod_poly_clear(z2[i]);
        nmod_poly_clear(z3[i]);
    }
    for (int i = 0; i < 2; i++) {
        nmod_poly_clear(_d[i]);
        nmod_poly_clear(v1[i]);
        nmod_poly_clear(v2[i]);
        nmod_poly_clear(v3[i]);
    }

    return result;
}

int sum_run(commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
            commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta, pcrt_poly_t r1[WIDTH],
            pcrt_poly_t r2[WIDTH], pcrt_poly_t r3[WIDTH]) {
    nmod_poly_t y1[WIDTH][2], y2[WIDTH][2], y3[WIDTH][2];
    nmod_poly_t t1[2], t2[2], t3[2], u[2];
    int result;

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

    sum_prover(y1, y2, y3, t1, t2, t3, u, commitment_scheme, x1, x2, x3, key, alpha, beta, r1, r2, r3);
    result = sum_verifier(y1, y2, y3, t1, t2, t3, u, commitment_scheme, x1, x2, x3, key, alpha, beta);

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

    return result;
}

#ifdef MAIN

static void test(flint_rand_t rand) {
    commitment_scheme_t commitment_scheme;
	commitkey_t key;

	nmod_poly_t alpha, beta;
    nmod_poly_t m1, m2, m3;
    nmod_poly_t aux;
    pcrt_poly_t r1[WIDTH], r2[WIDTH], r3[WIDTH];

    commit_t com1, com2, com3;

	/* Generate commitment key-> */
    commit_scheme_init(commitment_scheme);
	commit_keygen(&key, rand);

	nmod_poly_init(alpha, MODP);
    nmod_poly_init(beta, MODP);
    nmod_poly_init(m1, MODP);
    nmod_poly_init(m2, MODP);
    nmod_poly_init(m3, MODP);
    nmod_poly_init(aux, MODP);

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_init(r1[i][j], MODP);
            nmod_poly_init(r2[i][j], MODP);
            nmod_poly_init(r3[i][j], MODP);
        }
    }

    commit_sample_short(alpha);
    commit_sample_short(beta);

    nmod_poly_randtest(m1, rand, DEGREE);
    nmod_poly_randtest(m2, rand, DEGREE);

    // m3 = alpha * m1 + beta * m2
    nmod_poly_mul(m3, alpha, m1);
    nmod_poly_mul(aux, beta, m2);
    nmod_poly_add(m3, m3, aux);

    for (int i = 0; i < WIDTH; i++) {
		commit_sample_short_crt(commitment_scheme, r1[i]);
        commit_sample_short_crt(commitment_scheme, r2[i]);
        commit_sample_short_crt(commitment_scheme, r3[i]);
	}



    commit_doit(commitment_scheme, &com1, m1, &key, r1);
    commit_doit(commitment_scheme, &com2, m2, &key, r2);
    commit_doit(commitment_scheme, &com3, m3, &key, r3);

    TEST_ONCE("sum proof is consistent") {
        TEST_ASSERT(sum_run(commitment_scheme, com1, com2, com3, &key, alpha, beta, r1, r2, r3)== 1, end);
    } TEST_END;

  end:
    commit_scheme_finish(commitment_scheme);
    commit_free(&com1);
    commit_free(&com2);
    commit_free(&com3);
    nmod_poly_clear(alpha);
    nmod_poly_clear(beta);
    nmod_poly_clear(m1);
    nmod_poly_clear(m2);
    nmod_poly_clear(m3);
    nmod_poly_clear(aux);
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(r1[i][j]);
            nmod_poly_clear(r2[i][j]);
            nmod_poly_clear(r3[i][j]);
        }
    }
	commit_keyfree(&key);
}

static void bench(flint_rand_t rand) {
    commitment_scheme_t commitment_scheme;
	commitkey_t key;

	nmod_poly_t alpha, beta;
    nmod_poly_t m1, m2, m3;
    nmod_poly_t aux;
    pcrt_poly_t r1[WIDTH], r2[WIDTH], r3[WIDTH];

    commit_t com1, com2, com3;

	/* Generate commitment key-> */
    commit_scheme_init(commitment_scheme);
	commit_keygen(&key, rand);

	nmod_poly_init(alpha, MODP);
    nmod_poly_init(beta, MODP);
    nmod_poly_init(m1, MODP);
    nmod_poly_init(m2, MODP);
    nmod_poly_init(m3, MODP);
    nmod_poly_init(aux, MODP);

    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_init(r1[i][j], MODP);
            nmod_poly_init(r2[i][j], MODP);
            nmod_poly_init(r3[i][j], MODP);
        }
    }

    commit_sample_short(alpha);
    commit_sample_short(beta);

    nmod_poly_randtest(m1, rand, DEGREE);
    nmod_poly_randtest(m2, rand, DEGREE);

    // m3 = alpha * m1 + beta * m2
    nmod_poly_mul(m3, alpha, m1);
    nmod_poly_mul(aux, beta, m2);
    nmod_poly_add(m3, m3, aux);

    for (int i = 0; i < WIDTH; i++) {
		commit_sample_short_crt(commitment_scheme, r1[i]);
        commit_sample_short_crt(commitment_scheme, r2[i]);
        commit_sample_short_crt(commitment_scheme, r3[i]);
	}



    commit_doit(commitment_scheme, &com1, m1, &key, r1);
    commit_doit(commitment_scheme, &com2, m2, &key, r2);
    commit_doit(commitment_scheme, &com3, m3, &key, r3);

	BENCH_BEGIN("sum-proof") {
		BENCH_ADD(sum_run(commitment_scheme, com1, com2, com3, &key, alpha, beta, r1, r2, r3));
	} BENCH_END;

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

    BENCH_BEGIN("gen-sum-proof") {
		BENCH_ADD(sum_prover(y1, y2, y3, t1, t2, t3, u, commitment_scheme, com1, com2, com3, &key, alpha, beta, r1, r2, r3));
	} BENCH_END;

    BENCH_BEGIN("ver-sum-proof") {
        BENCH_ADD(sum_verifier(y1, y2, y3, t1, t2, t3, u, commitment_scheme, com1, com2, com3, &key, alpha, beta));
    } BENCH_END;


    BENCH_BEGIN("com-message-rec") {
        BENCH_ADD(commit_message_rec(commitment_scheme, aux, &com1, &key, r1));
    } BENCH_END;

	commit_scheme_finish(commitment_scheme);
    commit_free(&com1);
    commit_free(&com2);
    commit_free(&com3);
    nmod_poly_clear(alpha);
    nmod_poly_clear(beta);
    nmod_poly_clear(m1);
    nmod_poly_clear(m2);
    nmod_poly_clear(m3);
    nmod_poly_clear(aux);
    for (int i = 0; i < WIDTH; i++) {
        for (int j = 0; j < 2; j++) {
            nmod_poly_clear(r1[i][j]);
            nmod_poly_clear(r2[i][j]);
            nmod_poly_clear(r3[i][j]);
        }
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

	commit_keyfree(&key);
}

int main(int argc, char *argv[]) {
	flint_rand_t rand;

	flint_randinit(rand);

	printf("\n** Tests for lattice-based sum proof:\n\n");
	test(rand);

	printf("\n** Benchmarks for lattice-based sum proof:\n\n");
	bench(rand);

	flint_randclear(rand);
}

#endif