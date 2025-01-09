#include <math.h>

#include "param.h"
#include "shuffle.h"
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

void lin_hash(nmod_poly_t d[2], commitment_scheme_t commitment_scheme, commitkey_t *key, commit_t x, commit_t y,
              nmod_poly_t alpha, nmod_poly_t beta, nmod_poly_t u[2],
              nmod_poly_t t[2], nmod_poly_t _t[2]) {
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

    /* Hash [x], [_x], t, _t in CRT representation. */
    for (int i = 0; i < 2; i++) {
        SHA256Input(&sha, (const uint8_t *)x.c1[i]->coeffs,
                    x.c1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)x.c2[i]->coeffs,
                    x.c2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)y.c1[i]->coeffs,
                    y.c1[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)y.c2[i]->coeffs,
                    y.c2[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)u[i]->coeffs,
                    u[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)t[i]->coeffs,
                    t[i]->alloc * sizeof(uint64_t));
        SHA256Input(&sha, (const uint8_t *)_t[i]->coeffs,
                    _t[i]->alloc * sizeof(uint64_t));
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

void lin_prover(nmod_poly_t y[WIDTH][2], nmod_poly_t _y[WIDTH][2],
		nmod_poly_t t[2], nmod_poly_t _t[2], nmod_poly_t u[2], commitment_scheme_t commitment_scheme,
		commit_t x, commit_t _x, commitkey_t *key, nmod_poly_t alpha,
		nmod_poly_t beta, nmod_poly_t r[WIDTH][2], nmod_poly_t _r[WIDTH][2],
		int l) {
	nmod_poly_t tmp, d[2], dr[WIDTH][2], _dr[WIDTH][2];
	int rej0, rej1;
	// Compute sigma^2 = (11 * v * beta * sqrt(k * N))^2.
	uint64_t sigma_sqr = 11 * NONZERO * BETA;
	sigma_sqr *= sigma_sqr * DEGREE * WIDTH;

	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_init(dr[i][j], MODP);
			nmod_poly_init(_dr[i][j], MODP);
		}
	}
	nmod_poly_init(tmp, MODP);
	nmod_poly_init(d[0], MODP);
	nmod_poly_init(d[1], MODP);

	do {
		for (int i = 0; i < 2; i++) {
			nmod_poly_zero(t[i]);
			nmod_poly_zero(_t[i]);
			nmod_poly_zero(u[i]);
			nmod_poly_zero(d[i]);
		}

		for (int i = 0; i < WIDTH; i++) {
			commit_sample_gauss_crt(commitment_scheme, y[i]);
			commit_sample_gauss_crt(commitment_scheme, _y[i]);
		}
		for (int i = 0; i < HEIGHT; i++) {
			for (int j = 0; j < WIDTH; j++) {
				for (int k = 0; k < 2; k++) {
					nmod_poly_mulmod(tmp, key->B1[i][j][k], y[j][k],
                                     *commit_irred(commitment_scheme, k));
					nmod_poly_add(t[k], t[k], tmp);
					nmod_poly_mulmod(tmp, key->B1[i][j][k], _y[j][k],
                                     *commit_irred(commitment_scheme, k));
					nmod_poly_add(_t[k], _t[k], tmp);
				}
			}
		}

		for (int i = 0; i < WIDTH; i++) {
			for (int j = 0; j < 2; j++) {
				nmod_poly_mulmod(tmp, key->b2[i][j], y[i][j], *commit_irred(commitment_scheme, j));
				nmod_poly_mulmod(tmp, tmp, alpha, *commit_irred(commitment_scheme, j));
				nmod_poly_add(u[j], u[j], tmp);
				nmod_poly_mulmod(tmp, key->b2[i][j], _y[i][j],
						commitment_scheme->irred[j]);
				nmod_poly_sub(u[j], u[j], tmp);
			}
		}

		/* Sample challenge. */
		lin_hash(d, commitment_scheme, key, x, _x, alpha, beta, u, t, _t);

		/* Prover */
		for (int i = 0; i < WIDTH; i++) {
			for (int j = 0; j < 2; j++) {
				nmod_poly_mulmod(dr[i][j], d[j], r[i][j], *commit_irred(commitment_scheme, j));
				nmod_poly_add(y[i][j], y[i][j], dr[i][j]);
				nmod_poly_mulmod(_dr[i][j], d[j], _r[i][j], *commit_irred(commitment_scheme, j));
				nmod_poly_add(_y[i][j], _y[i][j], _dr[i][j]);
			}
		}
		rej0 = rej_sampling(commitment_scheme, y, dr, sigma_sqr);
		rej1 = rej_sampling(commitment_scheme, _y, _dr, sigma_sqr);
	} while (rej0 || rej1);

	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_clear(dr[i][j]);
			nmod_poly_clear(_dr[i][j]);
		}
	}
	nmod_poly_clear(tmp);
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(d[i]);
	}
}

int lin_verifier(nmod_poly_t y[WIDTH][2], nmod_poly_t _y[WIDTH][2],
		nmod_poly_t t[2], nmod_poly_t _t[2], nmod_poly_t u[2], commitment_scheme_t commitment_scheme,
		commit_t com, commit_t x, commitkey_t *key,
		nmod_poly_t alpha, nmod_poly_t beta, int l, int len) {
	nmod_poly_t tmp, _d[2], v[2], _v[2], z[WIDTH], _z[WIDTH];
	int result = 1;

	nmod_poly_init(tmp, MODP);
	for (int i = 0; i < WIDTH; i++) {
		nmod_poly_init(z[i], MODP);
		nmod_poly_init(_z[i], MODP);
	}
	for (int i = 0; i < 2; i++) {
		nmod_poly_init(_d[i], MODP);
		nmod_poly_init(v[i], MODP);
		nmod_poly_init(_v[i], MODP);
		nmod_poly_zero(v[i]);
		nmod_poly_zero(_v[i]);
	}

	/* Sample challenge. */
	lin_hash(_d, commitment_scheme, key, com, x, alpha, beta, u, t, _t);

	/* Verifier checks norm, reconstruct from CRT representation. */
	for (int i = 0; i < WIDTH; i++) {
		pcrt_poly_rec(commitment_scheme, z[i], y[i]);
		pcrt_poly_rec(commitment_scheme, _z[i], _y[i]);
		assert(commit_norm2_sqr(z[i]) <=
				(uint64_t) 4 * DEGREE * SIGMA_C * SIGMA_C);
		assert(commit_norm2_sqr(_z[i]) <=
				(uint64_t) 4 * DEGREE * SIGMA_C * SIGMA_C);
	}
	/* Verifier computes B1z and B1z'. */
	for (int i = 0; i < HEIGHT; i++) {
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_mulmod(tmp, key->B1[i][j][k], y[j][k],
                                 *commit_irred(commitment_scheme, k));
				nmod_poly_add(v[k], v[k], tmp);
				nmod_poly_mulmod(tmp, key->B1[i][j][k], _y[j][k],
                                 *commit_irred(commitment_scheme, k));
				nmod_poly_add(_v[k], _v[k], tmp);
			}
		}
	}
	/* Verifier checks that B_1z = t + dc1, B_1z' = t' + dc1'. */
	for (int j = 0; j < 2; j++) {
		nmod_poly_mulmod(tmp, _d[j], com.c1[j], *commit_irred(commitment_scheme, j));
		nmod_poly_add(t[j], t[j], tmp);
		nmod_poly_mulmod(tmp, _d[j], x.c1[j], *commit_irred(commitment_scheme, j));
		nmod_poly_add(_t[j], _t[j], tmp);
		result &= nmod_poly_equal(t[j], v[j]);
		result &= nmod_poly_equal(_t[j], _v[j]);
	}

	if (l == 0) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_mulmod(t[j], alpha, com.c2[j], *commit_irred(commitment_scheme, j));
			nmod_poly_add(t[j], t[j], beta);
			nmod_poly_sub(t[j], t[j], x.c2[j]);
			nmod_poly_mulmod(t[j], t[j], _d[j], *commit_irred(commitment_scheme, j));
			nmod_poly_add(t[j], t[j], u[j]);
			nmod_poly_rem(t[j], t[j], *commit_irred(commitment_scheme, j));
		}
	}
	if (l > 0 && l < len - 1) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_mulmod(t[j], alpha, com.c2[j], *commit_irred(commitment_scheme, j));
			nmod_poly_add(t[j], t[j], beta);
			nmod_poly_sub(t[j], t[j], x.c2[j]);
			nmod_poly_mulmod(t[j], t[j], _d[j], *commit_irred(commitment_scheme, j));
			nmod_poly_add(t[j], t[j], u[j]);
		}
	}
	if (l == len - 1) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_mulmod(t[j], alpha, com.c2[j], *commit_irred(commitment_scheme, j));
			if (len & 1) {
				nmod_poly_sub(t[j], t[j], beta);
			} else {
				nmod_poly_add(t[j], t[j], beta);
			}
			nmod_poly_sub(t[j], t[j], x.c2[j]);
			nmod_poly_mulmod(t[j], t[j], _d[j], *commit_irred(commitment_scheme, j));
			nmod_poly_add(t[j], t[j], u[j]);
		}
	}

	nmod_poly_zero(v[0]);
	nmod_poly_zero(v[1]);
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_mulmod(tmp, key->b2[i][j], y[i][j], *commit_irred(commitment_scheme, j));
			nmod_poly_mulmod(tmp, alpha, tmp, *commit_irred(commitment_scheme, j));
			nmod_poly_add(v[j], v[j], tmp);
			nmod_poly_mulmod(tmp, key->b2[i][j], _y[i][j], *commit_irred(commitment_scheme, j));
			nmod_poly_sub(v[j], v[j], tmp);
		}
	}
	for (int j = 0; j < 2; j++) {
		result &= nmod_poly_equal(t[j], v[j]);
	}

	nmod_poly_clear(tmp);
	for (int i = 0; i < WIDTH; i++) {
		nmod_poly_clear(z[i]);
		nmod_poly_clear(_z[i]);
	}
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(_d[i]);
		nmod_poly_clear(v[i]);
		nmod_poly_clear(_v[i]);
	}
	return result;
}

void shuffle_hash(nmod_poly_t beta, commit_t **c, commit_t *d,
		nmod_poly_t *_m, nmod_poly_t rho, int len) {
	flint_rand_t rand;
	SHA256Context sha;
	uint8_t hash[SHA256HashSize];
	uint64_t seed0, seed1, seed2, seed3;

	SHA256Reset(&sha);

	for (int i = 0; i < len; i++) {
		SHA256Input(&sha, (const uint8_t *)_m[i]->coeffs,
				_m[i]->alloc * sizeof(uint64_t));
		for (int j = 0; j < 2; j++) {
			SHA256Input(&sha, (const uint8_t *)c[i]->c1[j]->coeffs,
					c[i]->c1[j]->alloc * sizeof(uint64_t));
			SHA256Input(&sha, (const uint8_t *)c[i]->c2[j]->coeffs,
					c[i]->c2[j]->alloc * sizeof(uint64_t));
			SHA256Input(&sha, (const uint8_t *)d[i].c1[j]->coeffs,
					d[i].c1[j]->alloc * sizeof(uint64_t));
			SHA256Input(&sha, (const uint8_t *)d[i].c2[j]->coeffs,
					d[i].c2[j]->alloc * sizeof(uint64_t));
		}
	}
	SHA256Input(&sha, (const uint8_t *)rho->coeffs,
			rho->alloc * sizeof(uint64_t));
	SHA256Result(&sha, hash);

	flint_randinit(rand);
	memcpy(&seed0, hash, sizeof(uint64_t));
	memcpy(&seed1, hash + sizeof(uint64_t), sizeof(uint64_t));
	memcpy(&seed2, hash + 2 * sizeof(uint64_t), sizeof(uint64_t));
	memcpy(&seed3, hash + 3 * sizeof(uint64_t), sizeof(uint64_t));
	seed0 ^= seed2;
	seed1 ^= seed3;
	flint_randseed(rand, seed0, seed1);
	commit_sample_rand(beta, rand, DEGREE);
	flint_randclear(rand);
}

void shuffle_prover(opening_t *y, opening_t *_y, pcrt_poly_t *t,
		pcrt_poly_t *_t, pcrt_poly_t *u, commitment_scheme_t commitment_scheme,
        commit_t *d, nmod_poly_t *s, commit_t **com, nmod_poly_t *m,
		nmod_poly_t *_m, opening_t *r, nmod_poly_t rho,
		commitkey_t *key, flint_rand_t rng, int len) {
	nmod_poly_t beta, t0, t1;
    nmod_poly_t *theta = (nmod_poly_t *)flint_malloc(len * sizeof(nmod_poly_t));
    opening_t *_r = (opening_t *)flint_malloc(len * sizeof(opening_t));

	nmod_poly_init(t0, MODP);
	nmod_poly_init(t1, MODP);
	nmod_poly_init(beta, MODP);
	for (int i = 0; i < len; i++) {
		nmod_poly_init(theta[i], MODP);
		for (int k = 0; k < 2; k++) {
			for (int j = 0; j < WIDTH; j++) {
				nmod_poly_init(_r[i][j][k], MODP);
			}
		}
	}

	/* Prover shifts the messages by rho. */
	for (int i = 0; i < len; i++) {
		nmod_poly_sub(m[i], m[i], rho);
		nmod_poly_sub(_m[i], _m[i], rho);
	}

	/* Prover samples theta_i and computes commitments D_i. */
	commit_sample_rand(theta[0], rng, DEGREE);
	nmod_poly_mulmod(t0, theta[0], _m[0], commitment_scheme->cyclo_poly);
	for (int j = 0; j < WIDTH; j++) {
		commit_sample_short_crt(commitment_scheme, _r[0][j]);
	}

	commit_doit(commitment_scheme, &d[0], t0, key, _r[0]);
	for (int i = 1; i < len - 1; i++) {
		commit_sample_rand(theta[i], rng, DEGREE);
		nmod_poly_mulmod(t0, theta[i - 1], m[i], commitment_scheme->cyclo_poly);
		nmod_poly_mulmod(t1, theta[i], _m[i], commitment_scheme->cyclo_poly);
		nmod_poly_add(t0, t0, t1);
		for (int j = 0; j < WIDTH; j++) {
			commit_sample_short_crt(commitment_scheme, _r[i][j]);
		}
		commit_doit(commitment_scheme, &d[i], t0, key, _r[i]);
	}
	nmod_poly_mulmod(t0, theta[len - 2], m[len - 1], commitment_scheme->cyclo_poly);
	for (int j = 0; j < WIDTH; j++) {
		commit_sample_short_crt(commitment_scheme, _r[len - 1][j]);
	}
	commit_doit(commitment_scheme, &d[len - 1], t0, key, _r[len - 1]);

	shuffle_hash(beta, com, d, _m, rho, len);
	nmod_poly_mulmod(s[0], theta[0], _m[0], commitment_scheme->cyclo_poly);
	nmod_poly_mulmod(t0, beta, m[0], commitment_scheme->cyclo_poly);
	nmod_poly_sub(s[0], s[0], t0);
	nmod_poly_invmod(t0, _m[0], commitment_scheme->cyclo_poly);
	nmod_poly_mulmod(s[0], s[0], t0, commitment_scheme->cyclo_poly);
	for (int i = 1; i < len - 1; i++) {
		nmod_poly_mulmod(s[i], theta[i - 1], m[i], commitment_scheme->cyclo_poly);
		nmod_poly_mulmod(t0, theta[i], _m[i], commitment_scheme->cyclo_poly);
		nmod_poly_add(s[i], s[i], t0);
		nmod_poly_mulmod(t0, s[i - 1], m[i], commitment_scheme->cyclo_poly);
		nmod_poly_sub(s[i], s[i], t0);
		nmod_poly_invmod(t0, _m[i], commitment_scheme->cyclo_poly);
		nmod_poly_mulmod(s[i], s[i], t0, commitment_scheme->cyclo_poly);
	}

	for (int l = 0; l < len; l++) {
		if (l < len - 1) {
			nmod_poly_mulmod(t0, s[l], _m[l], commitment_scheme->cyclo_poly);
		} else {
			nmod_poly_mulmod(t0, beta, _m[l], commitment_scheme->cyclo_poly);
		}

		if (l == 0) {
			lin_prover(y[l], _y[l], t[l], _t[l], u[l], commitment_scheme, com[l][0], d[l], key, beta,
					t0, r[l], _r[l], l);
		} else {
			lin_prover(y[l], _y[l], t[l], _t[l], u[l], commitment_scheme, com[l][0], d[l], key,
					s[l - 1], t0, r[l], _r[l], l);
		}
	}

	nmod_poly_clear(t0);
	nmod_poly_clear(t1);
	nmod_poly_clear(beta);
	for (int i = 0; i < len; i++) {
		nmod_poly_clear(theta[i]);
		for (int k = 0; k < 2; k++) {
			for (int j = 0; j < WIDTH; j++) {
				nmod_poly_clear(_r[i][j][k]);
			}
		}
	}
    flint_free(theta);
    flint_free(_r);
}

int shuffle_verifier(opening_t *y, opening_t *_y, pcrt_poly_t *t,
		pcrt_poly_t *_t, pcrt_poly_t *u, commitment_scheme_t commitment_scheme,
        commit_t *d, nmod_poly_t *s, commit_t **com, nmod_poly_t *_m,
		nmod_poly_t rho, commitkey_t *key, int len) {
	int result = 1;
	nmod_poly_t beta, t0;

	nmod_poly_init(t0, MODP);
	nmod_poly_init(beta, MODP);

	shuffle_hash(beta, com, d, _m, rho, len);
	/* Now verify each \Prod_LIN instance, one for each commitment. */
	for (int l = 0; l < len; l++) {
		if (l < len - 1) {
			nmod_poly_mulmod(t0, s[l], _m[l], commitment_scheme->cyclo_poly);
		} else {
			nmod_poly_mulmod(t0, beta, _m[l], commitment_scheme->cyclo_poly);
		}

		if (l == 0) {
			result &=
					lin_verifier(y[l], _y[l], t[l], _t[l], u[l], commitment_scheme, com[l][0], d[l],
					key, beta, t0, l, len);
		} else {
			result &=
					lin_verifier(y[l], _y[l], t[l], _t[l], u[l], commitment_scheme, com[l][0], d[l],
					key, s[l - 1], t0, l, len);
		}
	}

	nmod_poly_clear(t0);
	nmod_poly_clear(beta);
	return result;
}

int shuffle_run(commitment_scheme_t commitment_scheme, commit_t **com, nmod_poly_t *m,
                nmod_poly_t *_m, opening_t *r, commitkey_t *key, flint_rand_t rng, int len) {
	int flag, result;
	commit_t d[len];
	nmod_poly_t t0, t1, rho;
    nmod_poly_t *s = (nmod_poly_t *)flint_malloc(len * sizeof(nmod_poly_t));
    pcrt_poly_t *u = (pcrt_poly_t *)flint_malloc(len * sizeof(pcrt_poly_t));

    opening_t *y = (opening_t *)flint_malloc(len * sizeof(opening_t));
    opening_t *_y = (opening_t *)flint_malloc(len * sizeof(opening_t));
    pcrt_poly_t *t = (pcrt_poly_t *)flint_malloc(len * sizeof(pcrt_poly_t));
    pcrt_poly_t *_t = (pcrt_poly_t *)flint_malloc(len * sizeof(pcrt_poly_t));

	nmod_poly_init(t0, MODP);
	nmod_poly_init(t1, MODP);
	nmod_poly_init(rho, MODP);
	for (int i = 0; i < len; i++) {
		nmod_poly_init(s[i], MODP);
		for (int k = 0; k < 2; k++) {
			nmod_poly_init(t[i][k], MODP);
			nmod_poly_init(_t[i][k], MODP);
			nmod_poly_init(u[i][k], MODP);
			for (int j = 0; j < WIDTH; j++) {
				nmod_poly_init(y[i][j][k], MODP);
				nmod_poly_init(_y[i][j][k], MODP);
			}
		}
	}

	/* Verifier samples \rho that is different from the messages, and \beta. */
	do {
		flag = 1;
		commit_sample_rand(rho, rng, DEGREE);
		for (int i = 0; i < len; i++) {
			if (nmod_poly_equal(rho, _m[i]) == 1) {
				flag = 0;
			}
		}
	} while (flag == 0);

	/* Verifier shifts the commitments by rho. */
	nmod_poly_rem(t0, rho, *commit_irred(commitment_scheme, 0));
	nmod_poly_rem(t1, rho, *commit_irred(commitment_scheme, 1));
	for (int i = 0; i < len; i++) {
		nmod_poly_sub(com[i]->c2[0], com[i]->c2[0], t0);
		nmod_poly_sub(com[i]->c2[1], com[i]->c2[1], t1);
	}

	shuffle_prover(y, _y, t, _t, u, commitment_scheme, d, s, com, m, _m, r, rho, key, rng, len);

	result = shuffle_verifier(y, _y, t, _t, u, commitment_scheme, d, s, com, _m, rho, key, len);

	nmod_poly_clear(t0);
	nmod_poly_clear(t1);
	nmod_poly_clear(rho);
	for (int i = 0; i < len; i++) {
		nmod_poly_clear(s[i]);
		for (int k = 0; k < 2; k++) {
			nmod_poly_clear(t[i][k]);
			nmod_poly_clear(_t[i][k]);
			nmod_poly_clear(u[i][k]);
			for (int j = 0; j < WIDTH; j++) {
				nmod_poly_clear(y[i][j][k]);
				nmod_poly_clear(_y[i][j][k]);
			}
		}
	}

    flint_free(s);
    flint_free(u);
    flint_free(y);
    flint_free(_y);
    flint_free(t);
    flint_free(_t);

	return result;
}

#ifdef MAIN

static void test(flint_rand_t rand) {
    commitment_scheme_t commitment_scheme;
	commitkey_t key;
	commit_t *com[MSGS];
	nmod_poly_t m[MSGS], _m[MSGS], r[MSGS][WIDTH][2];

	for (int i = 0; i < MSGS; i++) {
		nmod_poly_init(m[i], MODP);
		nmod_poly_init(_m[i], MODP);
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_init(r[i][j][k], MODP);
			}
		}
	}

    /* Initialize commitments. */
    for (int i = 0; i < MSGS; i++) {
        com[i] = (commit_t *) malloc(sizeof(commit_t));
    }

	/* Generate commitment key-> */
    commit_scheme_init(commitment_scheme);
	commit_keygen(&key, rand);

	for (int i = 0; i < MSGS; i++) {
		for (int j = 0; j < WIDTH; j++) {
			commit_sample_short_crt(commitment_scheme, r[i][j]);
		}
		commit_sample_short(m[i]);
		commit_doit(commitment_scheme, com[i], m[i], &key, r[i]);
	}

	/* Prover shuffles messages (only a circular shift for simplicity). */
	for (int i = 0; i < MSGS; i++) {
		nmod_poly_set(_m[i], m[(i + 1) % MSGS]);
	}

	TEST_ONCE("shuffle proof is consistent") {
		TEST_ASSERT(shuffle_run(commitment_scheme, com, m, _m, r, &key, rand, MSGS) == 1, end);
	} TEST_END;

  end:
    commit_scheme_finish(commitment_scheme);

	for (int i = 0; i < MSGS; i++) {
		commit_free(com[i]);
        free(com[i]);
		nmod_poly_clear(m[i]);
		nmod_poly_clear(_m[i]);
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_clear(r[i][j][k]);
			}
		}
	}
	commit_keyfree(&key);
}

static void bench(flint_rand_t rand) {
    commitment_scheme_t commitment_scheme;
	commitkey_t key;
	commit_t *com[MSGS];
	nmod_poly_t m[MSGS], _m[MSGS];
	nmod_poly_t alpha, beta, s[MSGS - 1];
	nmod_poly_t r[MSGS][WIDTH][2], y[WIDTH][2], _y[WIDTH][2];
	nmod_poly_t t[2], _t[2], u[2], v[2], _v[2];

	nmod_poly_init(alpha, MODP);
	nmod_poly_init(beta, MODP);
	for (int i = 0; i < MSGS; i++) {
		nmod_poly_init(m[i], MODP);
		nmod_poly_init(_m[i], MODP);
		if (i != MSGS - 1)
			nmod_poly_init(s[i], MODP);
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_init(r[i][j][k], MODP);
			}
		}
	}

    /* Initialize commitments. */
    for (int i = 0; i < MSGS; i++) {
        com[i] = (commit_t *) malloc(sizeof(commit_t));
    }

	/* Generate commitment key-> */
    commit_scheme_init(commitment_scheme);
	commit_keygen(&key, rand);

	for (int i = 0; i < MSGS; i++) {
		for (int j = 0; j < WIDTH; j++) {
			commit_sample_short_crt(commitment_scheme, r[i][j]);
		}
		commit_sample_short(m[i]);
		commit_doit(commitment_scheme, com[i], m[i], &key, r[i]);
	}

	/* Prover shuffles messages (only a circular shift for simplicity). */
	for (int i = 0; i < MSGS; i++) {
		nmod_poly_set(_m[i], m[(i + 1) % MSGS]);
	}

	BENCH_BEGIN("shuffle-proof (N messages)") {
		BENCH_ADD(shuffle_run(commitment_scheme, com, m, _m, r, &key, rand, MSGS));
	} BENCH_END;

	for (int i = 0; i < 2; i++) {
		nmod_poly_init(t[i], MODP);
		nmod_poly_init(_t[i], MODP);
		nmod_poly_init(u[i], MODP);
		nmod_poly_init(v[i], MODP);
		nmod_poly_init(_v[i], MODP);
	}
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_init(y[i][j], MODP);
			nmod_poly_init(_y[i][j], MODP);
		}
	}

	for (int i = 0; i < MSGS; i++) {
		for (int j = 0; j < WIDTH; j++) {
			commit_sample_short_crt(commitment_scheme, r[i][j]);
		}
	}
	commit_sample_rand(beta, rand, DEGREE);
	commit_sample_rand(alpha, rand, DEGREE);

	BENCH_BEGIN("linear proof") {
		BENCH_ADD(lin_prover(y, _y, t, _t, u, commitment_scheme, com[0][0], com[1][0], &key, alpha, beta,
						r[0], r[0], 0));
	} BENCH_END;

	BENCH_BEGIN("linear verifier") {
		BENCH_ADD(lin_verifier(y, _y, t, _t, u, commitment_scheme, com[0][0], com[1][0], &key, alpha,
						beta, 0, MSGS));
	} BENCH_END;

    commit_scheme_finish(commitment_scheme);

	nmod_poly_clear(alpha);
	nmod_poly_clear(beta);
	for (int i = 0; i < MSGS; i++) {
		commit_free(com[i]);
        free(com[i]);
		nmod_poly_clear(m[i]);
		nmod_poly_clear(_m[i]);
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_clear(r[i][j][k]);
			}
		}
	}
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(t[i]);
		nmod_poly_clear(_t[i]);
		nmod_poly_clear(u[i]);
		nmod_poly_clear(v[i]);
		nmod_poly_clear(_v[i]);
	}
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_clear(y[i][j]);
			nmod_poly_clear(_y[i][j]);
		}
	}

	commit_keyfree(&key);
}

int main(int argc, char *argv[]) {
	flint_rand_t rand;

	flint_randinit(rand);

	printf("\n** Tests for lattice-based shuffle proof:\n\n");
	test(rand);

	printf("\n** Benchmarks for lattice-based shuffle proof:\n\n");
	bench(rand);

	flint_randclear(rand);
}

#endif

# ifdef SHARED
opening_t * malloc_opening(size_t len) {
    return (opening_t *)flint_malloc(len * sizeof(opening_t));
}

pcrt_poly_t * malloc_pcrt_poly(size_t len) {
    return (pcrt_poly_t *)flint_malloc(len * sizeof(pcrt_poly_t));
}

nmod_poly_t * malloc_poly(size_t len) {
    return (nmod_poly_t *)flint_malloc(len * sizeof(nmod_poly_t));
}

commit_t * malloc_commit(size_t len) {
    return (commit_t *)flint_malloc(len * sizeof(commit_t));
}
#endif
