/**
 * @file
 *
 * Implementation of the lattice-based commitment scheme.
 *
 * @ingroup commit
 */

#include "param.h"
#include "commit.h"
#include "test.h"
#include "bench.h"
#include "gaussian.h"
#include "fastrandombytes.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* The first square root of -1. */
#define	P0		3153606543
/* The second square root of -1. */
#define P1		752843710

/**
 * Test if the l2-norm is within bounds (4 * sigma * sqrt(N)).
 *
 * @param[in] r 			- the polynomial to compute the l2-norm.
 * @return the computed norm.
 */
static int test_norm(nmod_poly_t r) {
	// Compute squared norm to save sqrt() and simplify comparison.
	uint64_t norm = commit_norm2_sqr(r);

	// Compute sigma^2 = (11 * v * beta * sqrt(k * N))^2.
	uint64_t sigma_sqr = 11 * NONZERO * BETA;
	sigma_sqr *= sigma_sqr * DEGREE * WIDTH;

	// Compare to (4 * sigma * sqrt(N))^2 = 16 * sigma^2 * N.
	return norm <= (uint64_t) 16 * sigma_sqr * DEGREE;
}

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

// Initialize commitment_scheme scheme.
void commit_scheme_init(commitment_scheme_t commitment_scheme) {
	nmod_poly_init(commitment_scheme->cyclo_poly, MODP);
	for (int i = 0; i < 2; i++) {
		nmod_poly_init(commitment_scheme->irred[i], MODP);
		nmod_poly_init(commitment_scheme->inv[i], MODP);
	}

	// Initialize polynomial as x^N + 1. */
	nmod_poly_set_coeff_ui(commitment_scheme->cyclo_poly, DEGREE, 1);
	nmod_poly_set_coeff_ui(commitment_scheme->cyclo_poly, 0, 1);

	// Initialize two factors of the polynomial for CRT representation.
	nmod_poly_set_coeff_ui(commitment_scheme->irred[0], DEGCRT, 1);
	nmod_poly_set_coeff_ui(commitment_scheme->irred[0], 0, 3153606543);
	nmod_poly_set_coeff_ui(commitment_scheme->irred[1], DEGCRT, 1);
	nmod_poly_set_coeff_ui(commitment_scheme->irred[1], 0, 752843710);

	nmod_poly_invmod(commitment_scheme->inv[0], commitment_scheme->irred[0], commitment_scheme->irred[1]);
	nmod_poly_invmod(commitment_scheme->inv[1], commitment_scheme->irred[1], commitment_scheme->irred[0]);
	nmod_poly_mul(commitment_scheme->inv[1], commitment_scheme->inv[1], commitment_scheme->irred[1]);
}

// Finalize commitment_scheme scheme.
void commit_scheme_finish(commitment_scheme_t commitment_scheme) {
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(commitment_scheme->irred[i]);
		nmod_poly_clear(commitment_scheme->inv[i]);
	}
	nmod_poly_clear(commitment_scheme->cyclo_poly);
}

// Return polynomial defining Rp.
nmod_poly_t *commit_poly(commitment_scheme_t commitment_scheme) {
	return &commitment_scheme->cyclo_poly;
}

// Return irreducible polynomials defining CRT representation.
nmod_poly_t *commit_irred(commitment_scheme_t commitment_scheme, int i) {
	return &commitment_scheme->irred[i];
}

// Recover polynomial from CRT representation.
void pcrt_poly_rec(const commitment_scheme_t commitment, nmod_poly_t c, pcrt_poly_t a) {
	nmod_poly_sub(c, a[0], a[1]);
	nmod_poly_mul(c, c, commitment->inv[1]);
	nmod_poly_add(c, c, a[1]);
	nmod_poly_rem(c, c, commitment->cyclo_poly);
}

// Convert to polynomial from CRT representation.
void pcrt_poly_conv(const commitment_scheme_t commitment_scheme, pcrt_poly_t c, const nmod_poly_t a) {
    for (int i = 0; i < 2; ++i) {
        nmod_poly_rem(c[i], a, commitment_scheme->irred[i]);
    }
}

// Compute squared l2-norm.
uint64_t commit_norm2_sqr(nmod_poly_t r) {
	int64_t coeff, norm = 0;

	/* Compute norm^2. */
	for (int i = 0; i < DEGREE; i++) {
		coeff = nmod_poly_get_coeff_ui(r, i);
		if (coeff > MODP / 2)
			coeff -= MODP;
		norm += coeff * coeff;
	}
	return norm;
}

// Generate a key pair.
void commit_keygen(commitkey_t *key, flint_rand_t rand) {
	for (int i = 0; i < HEIGHT; i++) {
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_init(key->B1[i][j][k], MODP);
				nmod_poly_zero(key->B1[i][j][k]);
				if (i == j) {
					nmod_poly_set_coeff_ui(key->B1[i][j][k], 0, 1);
				}
			}
		}
	}

	for (int i = 0; i < HEIGHT; i++) {
		for (int j = HEIGHT; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				commit_sample_rand(key->B1[i][j][k], rand, DEGCRT);
			}
		}
	}
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_init(key->b2[i][j], MODP);
			nmod_poly_zero(key->b2[i][j]);
			if (i == HEIGHT) {
				nmod_poly_set_coeff_ui(key->b2[i][j], 0, 1);
			}
			if (i > HEIGHT) {
				commit_sample_rand(key->b2[i][j], rand, DEGCRT);
			}
		}
	}
}

// Free a commitment key pair.
void commit_keyfree(commitkey_t *key) {
	for (int i = 0; i < HEIGHT; i++) {
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_clear(key->B1[i][j][k]);
			}
		}
	}
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_clear(key->b2[i][j]);
		}
	}
}

// Sample a short polynomial.
void commit_sample_short(nmod_poly_t r) {
	uint64_t buf;
	uint32_t coeff;
	int i, j, s;

	nmod_poly_zero(r);
	nmod_poly_fit_length(r, DEGREE);
	i = 0;
	s = 8 * sizeof(buf);
	j = s;

	do {
		if (j == s) {
			getrandom(&buf, sizeof(buf), 0);
			j = 0;
		}

		if (((buf >> j) & 1) & ((buf >> (j + 1)) & 1)) {
			j += 2;
		} else {
			coeff = MODP - 1 + ((buf >> j) & 3);
			nmod_poly_set_coeff_ui(r, i, coeff);
			i++;
			j += 2;
		}
	} while (i < DEGREE);
}

// Sample a short polynomial in CRT representation.
void commit_sample_short_crt(commitment_scheme_t commitment_scheme, pcrt_poly_t r) {
	nmod_poly_t t;

	nmod_poly_init(t, MODP);
	commit_sample_short(t);
	for (int j = 0; j < 2; j++) {
		nmod_poly_rem(r[j], t, commitment_scheme->irred[j]);
	}
	nmod_poly_clear(t);
}

// Sample a random polynomial.
void commit_sample_rand(nmod_poly_t r, flint_rand_t rand, int degree) {
	nmod_poly_fit_length(r, degree);
	for (int i = 0; i < degree; i++) {
		r->coeffs[i] = n_randtest(rand) % MODP;
	}
	r->length = degree;
	_nmod_poly_normalise(r);
}

// Sample a random polynomial in CRT representation.
void commit_sample_rand_crt(commitment_scheme_t commitment_scheme, pcrt_poly_t r, flint_rand_t rand) {
	nmod_poly_t t;

	nmod_poly_init(t, MODP);
	commit_sample_rand(t, rand, DEGREE);
	for (int i = 0; i < 2; i++) {
		nmod_poly_rem(r[i], t, commitment_scheme->irred[i]);
	}
	nmod_poly_clear(t);
}

// Sample a challenge.
void commit_sample_chall(nmod_poly_t f) {
	nmod_poly_zero(f);
	nmod_poly_t c[2];
	uint32_t buf;

	for (int i = 0; i < 2; i++) {
		nmod_poly_init(c[i], MODP);
		nmod_poly_fit_length(c[i], DEGREE);
		for (int j = 0; j < NONZERO; j++) {
			getrandom(&buf, sizeof(buf), 0);
			buf = buf % DEGREE;
			while (nmod_poly_get_coeff_ui(c[i], buf) != 0) {
				getrandom(&buf, sizeof(buf), 0);
				buf = buf % DEGREE;
			}
			nmod_poly_set_coeff_ui(c[i], buf, 1);
		}
	}
	nmod_poly_sub(f, c[0], c[1]);

	nmod_poly_clear(c[0]);
	nmod_poly_clear(c[1]);
}

// Sample a challenge in CRT representation.
void commit_sample_chall_crt(commitment_scheme_t commitment, pcrt_poly_t f) {
	nmod_poly_t t;

	nmod_poly_init(t, MODP);
	commit_sample_chall(t);
	nmod_poly_rem(f[0], t, commitment->irred[0]);
	nmod_poly_rem(f[1], t, commitment->irred[1]);
	nmod_poly_clear(t);
}

// Sample a polynomial according to a Gaussian distribution.
void commit_sample_gauss(nmod_poly_t r) {
	int64_t coeff;
	for (int i = 0; i < DEGREE; i++) {
		coeff = discrete_gaussian(0.0);
		if (coeff < 0)
			coeff += MODP;
		nmod_poly_set_coeff_ui(r, i, coeff);
	}
}

// Sample a polynomial according to a Gaussian distribution in CRT rep.
void commit_sample_gauss_crt(commitment_scheme_t commitment, nmod_poly_t r[2]) {
	nmod_poly_t t;

	nmod_poly_init(t, MODP);
	commit_sample_gauss(t);
	nmod_poly_rem(r[0], t, commitment->irred[0]);
	nmod_poly_rem(r[1], t, commitment->irred[1]);

	nmod_poly_clear(t);
}

// Commit to a message.
void commit_doit(commitment_scheme_t commitment, commit_t *com, nmod_poly_t m, commitkey_t *key,
                 pcrt_poly_t r[WIDTH]) {
	nmod_poly_t t;

	nmod_poly_init(t, MODP);
	for (int i = 0; i < 2; i++) {
		nmod_poly_init(com->c1[i], MODP);
		nmod_poly_init(com->c2[i], MODP);
		nmod_poly_zero(com->c1[i]);
		nmod_poly_zero(com->c2[i]);
	}

	// Compute B = [ B1 b2 ]^t * r_m.
	for (int i = 0; i < HEIGHT; i++) {
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_mulmod(t, key->B1[i][j][k], r[j][k], commitment->irred[k]);
				nmod_poly_add(com->c1[k], com->c1[k], t);
				if (i == 0) {
					nmod_poly_mulmod(t, key->b2[j][k], r[j][k], commitment->irred[k]);
					nmod_poly_add(com->c2[k], com->c2[k], t);
				}
			}
		}
	}

	// Convert m to CRT representation and accumulate.
	for (int i = 0; i < 2; i++) {
		nmod_poly_rem(t, m, commitment->irred[i]);
		nmod_poly_add(com->c2[i], com->c2[i], t);
	}

	nmod_poly_clear(t);
}

// Open a commitment on a message, randomness, factor.
int commit_open(commitment_scheme_t commitment, commit_t *com, nmod_poly_t m, commitkey_t *key,
                pcrt_poly_t r[WIDTH], pcrt_poly_t f) {
	nmod_poly_t t;
	pcrt_poly_t c1, c2, _c1, _c2;
	int result = 0;

	nmod_poly_init(t, MODP);
	for (int i = 0; i < 2; i++) {
		nmod_poly_init(c1[i], MODP);
		nmod_poly_init(c2[i], MODP);
		nmod_poly_init(_c1[i], MODP);
		nmod_poly_init(_c2[i], MODP);
		nmod_poly_zero(c1[i]);
		nmod_poly_zero(c2[i]);
	}

	// Compute B = [ B1 b2 ]^t * r_m.
	for (int i = 0; i < HEIGHT; i++) {
		for (int j = 0; j < WIDTH; j++) {
			for (int k = 0; k < 2; k++) {
				nmod_poly_mulmod(t, key->B1[i][j][k], r[j][k], commitment->irred[k]);
				nmod_poly_add(c1[k], c1[k], t);
				if (i == 0) {
					nmod_poly_mulmod(t, key->b2[j][k], r[j][k], commitment->irred[k]);
					nmod_poly_add(c2[k], c2[k], t);
				}
			}
		}
	}

	// Convert m to CRT representation before multiplication.
	for (int i = 0; i < 2; i++) {
		nmod_poly_rem(t, m, commitment->irred[i]);
		nmod_poly_mulmod(t, t, f[i], commitment->irred[i]);
		nmod_poly_add(c2[i], c2[i], t);
	}

	for (int i = 0; i < 2; i++) {
		nmod_poly_mulmod(_c1[i], com->c1[i], f[i], commitment->irred[i]);
		nmod_poly_mulmod(_c2[i], com->c2[i], f[i], commitment->irred[i]);
	}

	pcrt_poly_rec(commitment, t, r[0]);
	if (test_norm(t)) {
		pcrt_poly_rec(commitment, t, r[1]);
		if (test_norm(t)) {
			pcrt_poly_rec(commitment, t, r[2]);
			if (test_norm(t)) {
				if (nmod_poly_equal(_c1[0], c1[0]) &&
						nmod_poly_equal(_c2[0], c2[0])) {
					if (nmod_poly_equal(_c1[1], c1[1]) &&
							nmod_poly_equal(_c2[1], c2[1])) {
						result = 1;
					}
				}
			}
		}
	}

	nmod_poly_clear(t);
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(c1[i]);
		nmod_poly_clear(c2[i]);
	}
	return result;
}

int commit_message_rec(commitment_scheme_t commitment_scheme, nmod_poly_t message, commit_t *com, commitkey_t *key,
                        pcrt_poly_t r[WIDTH]) {
    nmod_poly_t t;
    pcrt_poly_t c1, c2;

    nmod_poly_init(t, MODP);
    for (int i = 0; i < 2; i++) {
        nmod_poly_init(c1[i], MODP);
        nmod_poly_init(c2[i], MODP);
        nmod_poly_zero(c1[i]);
        nmod_poly_zero(c2[i]);
    }

    // Compute B = [ B1 b2 ] * r_m.
    for (int i = 0; i < HEIGHT; i++) {
        for (int j = 0; j < WIDTH; j++) {
            for (int k = 0; k < 2; k++) {
                nmod_poly_mulmod(t, key->B1[i][j][k], r[j][k], commitment_scheme->irred[k]);
                nmod_poly_add(c1[k], c1[k], t);
                if (i == 0) {
                    nmod_poly_mulmod(t, key->b2[j][k], r[j][k], commitment_scheme->irred[k]);
                    nmod_poly_add(c2[k], c2[k], t);
                }
            }
        }
    }

    // compute [c1 c2] - B
    for (int i = 0; i < 2; i++) {
        nmod_poly_sub(c1[i], com->c1[i], c1[i]);
        nmod_poly_sub(c2[i], com->c2[i], c2[i]);
    }

    pcrt_poly_rec(commitment_scheme, t, c1);
    int is_zero = nmod_poly_is_zero(t);
    if (!is_zero) {
        return 0;
    }

    pcrt_poly_rec(commitment_scheme, message, c2);

    nmod_poly_clear(t);
    for (int i = 0; i < 2; i++) {
        nmod_poly_clear(c1[i]);
        nmod_poly_clear(c2[i]);
    }
    return 1;
}

// Free a commitment.
void commit_free(commit_t *com) {
	for (int i = 0; i < 2; i++) {
		nmod_poly_clear(com->c1[i]);
		nmod_poly_clear(com->c2[i]);
	}
}

commit_t *commit_ptr_init() {
    return (commit_t *) malloc(sizeof(commit_t));
}

void commit_ptr_free(commit_t *com) {
    free(com);
}

#ifdef MAIN
// Tests and benchmarks below.
static void test(commitment_scheme_t commitment_scheme, flint_rand_t rand) {
	commitkey_t key;
	commit_t com, _com;
	nmod_poly_t m, rho;
	pcrt_poly_t r[WIDTH], s[WIDTH], f;

	nmod_poly_init(m, MODP);
	nmod_poly_init(rho, MODP);
	nmod_poly_init(f[0], MODP);
	nmod_poly_init(f[1], MODP);
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_init(r[i][j], MODP);
			nmod_poly_init(s[i][j], MODP);
		}
	}

	/* Generate a random message. */
	nmod_poly_randtest(m, rand, DEGREE);

	/* Generate commitment_scheme key. */
	commit_keygen(&key, rand);
	for (int i = 0; i < WIDTH; i++) {
		commit_sample_short_crt(commitment_scheme, r[i]);
	}

	TEST_BEGIN("commitment_scheme can be generated and opened") {

		commit_doit(commitment_scheme, &com, m, &key, r);

		commit_sample_chall_crt(commitment_scheme, f);
		commit_sample_chall(rho);

        for (int i = 0; i < WIDTH; ++i) {
            for (int j = 0; j < 2; ++j) {
                nmod_poly_mulmod(s[i][j], r[i][j], f[j], commitment_scheme->irred[j]);
            }
        }

		TEST_ASSERT(commit_open(commitment_scheme, &com, m, &key, s, f) == 1, end);
	} TEST_END;

	TEST_BEGIN("commitments are linearly homomorphic") {
		/* Test linearity. */
		for (int i = 0; i < WIDTH; i++) {
			for (int j = 0; j < 2; j++) {
				nmod_poly_zero(r[i][j]);
			}
		}
		commit_doit(commitment_scheme, &_com, rho, &key, r);
		for (int i = 0; i < 2; i++) {
			nmod_poly_sub(com.c1[i], com.c1[i], _com.c1[i]);
			nmod_poly_sub(com.c2[i], com.c2[i], _com.c2[i]);
		}
		nmod_poly_sub(m, m, rho);
		TEST_ASSERT(commit_open(commitment_scheme, &com, m, &key, s, f) == 1, end);
	} TEST_END;

  end:
	commit_keyfree(&key);
	commit_free(&com);
	nmod_poly_clear(m);
	nmod_poly_clear(rho);
	nmod_poly_clear(f[0]);
	nmod_poly_clear(f[1]);
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_clear(r[i][j]);
			nmod_poly_clear(s[i][j]);
		}
	}
}

static void bench(commitment_scheme_t commitment_scheme, flint_rand_t rand) {
	commitkey_t key;
	commit_t com;
	nmod_poly_t m;
	pcrt_poly_t f, r[WIDTH], s[WIDTH];

	nmod_poly_init(m, MODP);
	nmod_poly_init(f[0], MODP);
	nmod_poly_init(f[1], MODP);
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_init(r[i][j], MODP);
			nmod_poly_init(s[i][j], MODP);
		}
	}

	commit_keygen(&key, rand);
	nmod_poly_randtest(m, rand, DEGREE);

	for (int i = 0; i < WIDTH; i++) {
		commit_sample_short_crt(commitment_scheme, r[i]);
	}

	BENCH_BEGIN("commit_sample") {
		BENCH_ADD(commit_sample_short_crt(commitment_scheme, r[0]));
	} BENCH_END;

	BENCH_BEGIN("commit_doit") {
		BENCH_ADD(commit_doit(commitment_scheme, &com, m, &key, r));
		commit_free(&com);
	} BENCH_END;

	BENCH_BEGIN("commit_open") {
		commit_sample_chall_crt(commitment_scheme, f);
		commit_doit(commitment_scheme, &com, m, &key, r);
		BENCH_ADD(commit_open(commitment_scheme, &com, m, &key, r, f));
	} BENCH_END;

	commit_keyfree(&key);
	commit_free(&com);
	nmod_poly_clear(m);
	nmod_poly_clear(f[0]);
	nmod_poly_clear(f[1]);
	for (int i = 0; i < WIDTH; i++) {
		for (int j = 0; j < 2; j++) {
			nmod_poly_clear(r[i][j]);
			nmod_poly_clear(s[i][j]);
		}
	}
}

static void microbench(commitment_scheme_t commitment_scheme, flint_rand_t rand) {
	nmod_poly_t alpha, beta, t[2], u[2];

	nmod_poly_init(alpha, MODP);
	nmod_poly_init(beta, MODP);
	for (int i = 0; i < 2; i++) {
		nmod_poly_init(t[i], MODP);
		nmod_poly_init(u[i], MODP);
	}

	commit_sample_rand(beta, rand, DEGREE);
	commit_sample_rand(alpha, rand, DEGREE);

	BENCH_BEGIN("Polynomial addition") {
		BENCH_ADD(nmod_poly_add(alpha, alpha, beta));
	} BENCH_END;

	BENCH_BEGIN("Polynomial multiplication") {
		BENCH_ADD(nmod_poly_mulmod(alpha, alpha, beta, commitment_scheme->cyclo_poly));
	} BENCH_END;

	commit_sample_rand_crt(commitment_scheme, t, rand);
	commit_sample_rand_crt(commitment_scheme, u, rand);

	BENCH_BEGIN("Polynomial mult in CRT form") {
		BENCH_ADD(nmod_poly_mulmod(t[0], t[0], u[0], commitment_scheme->irred[0]));
		BENCH_ADD(nmod_poly_mulmod(t[1], t[1], u[1], commitment_scheme->irred[1]));
	} BENCH_END;

nmod_poly_clear(alpha);
nmod_poly_clear(beta);
for (int i = 0; i < 2; i++) {
	nmod_poly_clear(t[i]);
	nmod_poly_clear(u[i]);
}
}

int main(int argc, char *arv[]) {
    commitment_scheme_t commitment_scheme;
	flint_rand_t rand;
	uint64_t buf[2];

	getrandom(buf, sizeof(buf), GRND_RANDOM);
	flint_randinit(rand);
	flint_randseed(rand, buf[0], buf[1]);

    commit_scheme_init(commitment_scheme);

	printf("\n** Tests for lattice-based commitments:\n\n");
	test(commitment_scheme, rand);

	printf("\n** Microbenchmarks for polynomial arithmetic:\n\n");
	microbench(commitment_scheme, rand);

	printf("\n** Benchmarks for lattice-based commitments:\n\n");
	bench(commitment_scheme, rand);

    commit_scheme_finish(commitment_scheme);
	flint_randclear(rand);
}
#endif
