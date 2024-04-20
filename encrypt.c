/**
 * @file
 *
 * Implementation of the lattice-based encryption scheme.
 *
 * @ingroup commit
 */

#include "param.h"
#include "test.h"
#include "bench.h"
#include "encrypt.h"

/*============================================================================*/
/* Private definitions                                                        */
/*============================================================================*/

/* The large modulus for the encryption scheme. */
#define Q		"72057594037928893"
#define Q0		"29973109198516688"
#define Q1		"42084484839412205"
#define Q2		"36028797018964446"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/

/* Recover polynomial from CRT representation. */
void qcrt_poly_rec(encryption_scheme_t encryption_scheme,fmpz_mod_poly_t c, qcrt_poly_t a) {
	fmpz_mod_poly_t t;

	fmpz_mod_poly_init(t, encryption_scheme->ctx_q);

	fmpz_mod_poly_sub(t, a[0], a[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_mul(t, t, encryption_scheme->inv[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_mul(c, t, encryption_scheme->irred[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_add(c, c, a[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_mul(t, encryption_scheme->irred[0], encryption_scheme->irred[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_rem(c, c, t, encryption_scheme->ctx_q);

	fmpz_mod_poly_clear(t, encryption_scheme->ctx_q);
}

// Sample short element.
void encrypt_sample_short(fmpz_mod_poly_t r, fmpz_mod_ctx_t ctx) {
	uint64_t buf;
	fmpz_t coeff;

	fmpz_init(coeff);
	fmpz_mod_poly_zero(r, ctx);
	fmpz_mod_poly_fit_length(r, DEGREE, ctx);
	for (int i = 0; i < DEGREE; i += 32) {
		getrandom(&buf, sizeof(buf), 0);
		for (int j = 0; j < 64; j += 2) {
			fmpz_set_ui(coeff, ((buf >> (j + 1)) & 1));
			if ((buf >> j) & 1) {
				fmpz_neg(coeff, coeff);
			}
			fmpz_mod_poly_set_coeff_fmpz(r, (i + j / 2) % DEGREE, coeff, ctx);
		}
	}

	fmpz_clear(coeff);
}

// Sample short element in CRT representation.
void encrypt_sample_short_crt(encryption_scheme_t encryption_scheme, fmpz_mod_poly_t r[2], fmpz_mod_ctx_t ctx) {
	fmpz_mod_poly_t t;

	fmpz_mod_poly_init(t, ctx);
	encrypt_sample_short(t, ctx);
	fmpz_mod_poly_rem(r[0], t, encryption_scheme->irred[0], ctx);
	fmpz_mod_poly_rem(r[1], t, encryption_scheme->irred[1], ctx);

	fmpz_mod_poly_clear(t, ctx);
}

// Initialize encryption scheme.
void encrypt_setup(encryption_scheme_t encryption_scheme) {
	fmpz_t q0, q1;

	fmpz_init(encryption_scheme->p);
	fmpz_init(encryption_scheme->q);
	fmpz_init(q0);
	fmpz_init(q1);

	fmpz_set_ui(encryption_scheme->p, MODP);
	fmpz_set_str(encryption_scheme->q, Q, 10);
	fmpz_set_str(q0, Q0, 10);
	fmpz_set_str(q1, Q1, 10);

	fmpz_mod_ctx_init(encryption_scheme->ctx_p, encryption_scheme->p);
	fmpz_mod_ctx_init(encryption_scheme->ctx_q, encryption_scheme->q);

	fmpz_mod_poly_init(encryption_scheme->poly, encryption_scheme->ctx_p);
	fmpz_mod_poly_init(encryption_scheme->large_poly, encryption_scheme->ctx_q);
	for (int i = 0; i < 2; i++) {
		fmpz_mod_poly_init(encryption_scheme->irred[i], encryption_scheme->ctx_q);
		fmpz_mod_poly_init(encryption_scheme->inv[i], encryption_scheme->ctx_q);
	}

	// Initialize cyclotomic polynomial (x^N + 1) over F_p
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->poly, DEGREE, 1, encryption_scheme->ctx_p);
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->poly, 0, 1, encryption_scheme->ctx_p);

	// Initialize cyclotomic polynomial (x^N + 1) over F_q
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->large_poly, DEGREE, 1, encryption_scheme->ctx_q);
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->large_poly, 0, 1, encryption_scheme->ctx_q);

	// Initialize each factor as well.
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->irred[0], DEGCRT, 1, encryption_scheme->ctx_q);
	fmpz_mod_poly_set_coeff_fmpz(encryption_scheme->irred[0], 0, q0, encryption_scheme->ctx_q);
	fmpz_mod_poly_set_coeff_ui(encryption_scheme->irred[1], DEGCRT, 1, encryption_scheme->ctx_q);
	fmpz_mod_poly_set_coeff_fmpz(encryption_scheme->irred[1], 0, q1, encryption_scheme->ctx_q);

	fmpz_mod_poly_invmod(encryption_scheme->inv[0], encryption_scheme->irred[0],
                         encryption_scheme->irred[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_invmod(encryption_scheme->inv[1],
                         encryption_scheme->irred[1],
                         encryption_scheme->irred[0],
                         encryption_scheme->ctx_q);

	fmpz_clear(q0);
	fmpz_clear(q1);
}

// Return small modulus p.
fmpz_t *encrypt_modulus(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->p;
}

// Return large modulus q.
fmpz_t *encrypt_large_modulus(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->q;
}

// Return small modulus p.
fmpz_mod_ctx_t *encrypt_modulus_ctx(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->ctx_p;
}

// Return large modulus q.
fmpz_mod_ctx_t *encrypt_large_modulus_ctx(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->ctx_q;
}

// Return cyclotomic polynomial.
fmpz_mod_poly_t *encrypt_large_poly(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->large_poly;
}

// Return cyclotomic polynomial.
fmpz_mod_poly_t *encrypt_poly(encryption_scheme_t encryption_scheme) {
	return &encryption_scheme->poly;
}

// Return irreducible polynomials for CRT representation.
fmpz_mod_poly_t *encrypt_irred(encryption_scheme_t encryption_scheme, int i) {
	return &encryption_scheme->irred[i];
}

// Finalize encryption scheme.
void encrypt_finish(encryption_scheme_t encryption_scheme) {
	fmpz_mod_poly_clear(encryption_scheme->poly, encryption_scheme->ctx_p);
	fmpz_mod_poly_clear(encryption_scheme->large_poly, encryption_scheme->ctx_q);
	for (int i = 0; i < 2; i++) {
		fmpz_mod_poly_clear(encryption_scheme->irred[i], encryption_scheme->ctx_q);
		fmpz_mod_poly_clear(encryption_scheme->inv[i], encryption_scheme->ctx_q);
	}
	fmpz_mod_ctx_clear(encryption_scheme->ctx_p);
	fmpz_mod_ctx_clear(encryption_scheme->ctx_q);
	fmpz_clear(encryption_scheme->p);
	fmpz_clear(encryption_scheme->q);
}

// Generate a key pair.
void encrypt_keygen(encryption_scheme_t encryption_scheme, publickey_t *pk, privatekey_t *sk, flint_rand_t rand) {
	fmpz_mod_poly_t t;

	fmpz_mod_poly_init(t, encryption_scheme->ctx_q);
	for (int i = 0; i < DIM; i++) {
		for (int j = 0; j < 2; j++) {
			fmpz_mod_poly_init(sk->s1[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_init(sk->s2[i][j], encryption_scheme->ctx_q);
		}
		encrypt_sample_short_crt(encryption_scheme, sk->s1[i], encryption_scheme->ctx_q);
		encrypt_sample_short_crt(encryption_scheme, sk->s2[i], encryption_scheme->ctx_q);
	}
	for (int i = 0; i < DIM; i++) {
		for (int j = 0; j < DIM; j++) {
			fmpz_mod_poly_init(pk->t[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_zero(pk->t[i][j], encryption_scheme->ctx_q);
			for (int k = 0; k < 2; k++) {
				fmpz_mod_poly_init(pk->A[i][j][k], encryption_scheme->ctx_q);
				fmpz_mod_poly_randtest(pk->A[i][j][k], rand, DEGCRT, encryption_scheme->ctx_q);
			}
		}
		for (int k = 0; k < 2; k++) {
			fmpz_mod_poly_add(pk->t[i][k], pk->t[i][k], sk->s2[i][k], encryption_scheme->ctx_q);
		}
	}

	// Compute (A, t = As_1 + s_2).
	for (int i = 0; i < DIM; i++) {
		for (int j = 0; j < DIM; j++) {
			for (int k = 0; k < 2; k++) {
				fmpz_mod_poly_mulmod(t, pk->A[i][j][k], sk->s1[j][k], encryption_scheme->irred[k],
                                     encryption_scheme->ctx_q);
				fmpz_mod_poly_add(pk->t[i][k], pk->t[i][k], t, encryption_scheme->ctx_q);
			}
		}
	}
	fmpz_mod_poly_clear(t, encryption_scheme->ctx_q);
}

// Free key pair.
void encrypt_keyfree(encryption_scheme_t encryption_scheme, publickey_t *pk, privatekey_t *sk) {
	for (int i = 0; i < DIM; i++) {
		for (int j = 0; j < DIM; j++) {
			fmpz_mod_poly_clear(pk->t[i][j], encryption_scheme->ctx_q);
			for (int k = 0; k < 2; k++) {
				fmpz_mod_poly_clear(pk->A[i][j][k], encryption_scheme->ctx_q);
			}
		}
		for (int k = 0; k < 2; k++) {
			fmpz_mod_poly_clear(sk->s1[i][k], encryption_scheme->ctx_q);
			fmpz_mod_poly_clear(sk->s2[i][k], encryption_scheme->ctx_q);
		}
	}
}

// Internal encryption function.
void encrypt_make(encryption_scheme_t encryption_scheme, ciphertext_t *c, qcrt_poly_t r[DIM], qcrt_poly_t e[DIM],
		qcrt_poly_t e_, fmpz_mod_poly_t m, publickey_t *pk) {
	fmpz_poly_t s;
	fmpz_mod_poly_t _m, t;
	fmpz_t coeff, p2;

	fmpz_init(coeff);
	fmpz_init(p2);

	fmpz_poly_init(s);
	fmpz_mod_poly_init(_m, encryption_scheme->ctx_q);
	for (int i = 0; i < DIM; i++) {
		fmpz_mod_poly_init(c->w[i], encryption_scheme->ctx_q);
		for (int j = 0; j < 2; j++) {
			fmpz_mod_poly_init(c->v[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_zero(c->v[i][j], encryption_scheme->ctx_q);
		}
	}

	fmpz_mod_poly_init(t, encryption_scheme->ctx_q);
	for (int i = 0; i < DIM; i++) {
		for (int j = 0; j < DIM; j++) {
			for (int k = 0; k < 2; k++) {
				fmpz_mod_poly_mulmod(t, pk->A[j][i][k], r[j][k], encryption_scheme->irred[k],
                                     encryption_scheme->ctx_q);
				fmpz_mod_poly_add(c->v[i][k], c->v[i][k], t, encryption_scheme->ctx_q);
			}
		}
	}

	// Lift m from Rp to Rq. */
	fmpz_mod_poly_get_fmpz_poly(s, m, encryption_scheme->ctx_p);
	fmpz_set_ui(p2, MODP >> 1);
	for (int i = 0; i < DEGREE; i++) {
		fmpz_poly_get_coeff_fmpz(coeff, s, i);
		if (fmpz_cmp(coeff, p2) >= 0) {
			fmpz_sub(coeff, coeff, encryption_scheme->p);
		}
		fmpz_mod_poly_set_coeff_fmpz(_m, i, coeff, encryption_scheme->ctx_q);
	}

	for (int i = 0; i < DIM; i++) {
		fmpz_mod_poly_zero(c->w[i], encryption_scheme->ctx_q);
		for (int j = 0; j < 2; j++) {
			fmpz_mod_poly_add(c->v[i][j], c->v[i][j], e[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_scalar_mul_fmpz(c->v[i][j], c->v[i][j], encryption_scheme->p, encryption_scheme->ctx_q);

			fmpz_mod_poly_mulmod(t, pk->t[j][i], r[j][i], encryption_scheme->irred[i], encryption_scheme->ctx_q);
			fmpz_mod_poly_add(c->w[i], c->w[i], t, encryption_scheme->ctx_q);
		}
		fmpz_mod_poly_add(c->w[i], c->w[i], e_[i], encryption_scheme->ctx_q);
		fmpz_mod_poly_scalar_mul_fmpz(c->w[i], c->w[i], encryption_scheme->p, encryption_scheme->ctx_q);
		fmpz_mod_poly_rem(t, _m, encryption_scheme->irred[i], encryption_scheme->ctx_q);
		fmpz_mod_poly_add(c->w[i], c->w[i], t, encryption_scheme->ctx_q);
	}
	fmpz_mod_poly_clear(_m, encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(t, encryption_scheme->ctx_q);
	fmpz_clear(p2);
	fmpz_clear(coeff);
	fmpz_poly_clear(s);
}

// Encrypt a message under a public key.
void encrypt_doit(encryption_scheme_t encryption_scheme, ciphertext_t *c, fmpz_mod_poly_t m, publickey_t *pk,
		flint_rand_t rand) {
	qcrt_poly_t r[DIM], e[DIM], e_;

	for (int i = 0; i < DIM; i++) {
		fmpz_mod_poly_init(e_[i], encryption_scheme->ctx_q);
		for (int j = 0; j < 2; j++) {
			fmpz_mod_poly_init(r[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_init(e[i][j], encryption_scheme->ctx_q);
		}
		encrypt_sample_short_crt(encryption_scheme, r[i], encryption_scheme->ctx_q);
		encrypt_sample_short_crt(encryption_scheme, e[i], encryption_scheme->ctx_q);
	}
	encrypt_sample_short_crt(encryption_scheme, e_, encryption_scheme->ctx_q);

	encrypt_make(encryption_scheme, c, r, e, e_, m, pk);

	for (int i = 0; i < DIM; i++) {
		fmpz_mod_poly_clear(e_[i], encryption_scheme->ctx_q);
		for (int j = 0; j < 2; j++) {
			fmpz_mod_poly_clear(r[i][j], encryption_scheme->ctx_q);
			fmpz_mod_poly_clear(e[i][j], encryption_scheme->ctx_q);
		}
	}
}

// Decrypt ciphertext to the original plaintext message.
int encrypt_undo(encryption_scheme_t encryption_scheme, fmpz_mod_poly_t m, fmpz_mod_poly_t chall, ciphertext_t *c,
		privatekey_t *sk) {
	fmpz_poly_t s;
	fmpz_mod_poly_t t, _t, u[2];
	fmpz_t coeff, q2;
	int result = 1;
	fmpz_init(coeff);
	fmpz_init(q2);

	fmpz_poly_init(s);
	fmpz_mod_poly_init(t, encryption_scheme->ctx_q);
	fmpz_mod_poly_init(_t, encryption_scheme->ctx_q);

	for (int i = 0; i < 2; i++) {
		fmpz_mod_poly_init(u[i], encryption_scheme->ctx_q);
		fmpz_mod_poly_zero(u[i], encryption_scheme->ctx_q);
		for (int j = 0; j < DIM; j++) {
			fmpz_mod_poly_mulmod(t, c->v[j][i], sk->s1[j][i], encryption_scheme->irred[i], encryption_scheme->ctx_q);
			fmpz_mod_poly_add(u[i], u[i], t, encryption_scheme->ctx_q);
		}
		fmpz_mod_poly_sub(u[i], c->w[i], u[i], encryption_scheme->ctx_q);
	}
	qcrt_poly_rec(encryption_scheme, t, u);

	if (chall != NULL) {
		fmpz_set_ui(q2, MODP / 2);
		for (int i = 0; i < DEGREE; i++) {
			fmpz_mod_poly_get_coeff_fmpz(coeff, chall, i, encryption_scheme->ctx_p);
			if (fmpz_cmp(coeff, q2) >= 0) {
				fmpz_sub_ui(coeff, coeff, MODP);
			}
			fmpz_mod_poly_set_coeff_fmpz(_t, i, coeff, encryption_scheme->ctx_q);
		}
		fmpz_mod_poly_mulmod(t, t, _t, encryption_scheme->large_poly, encryption_scheme->ctx_q);
	}

	fmpz_mod_poly_get_fmpz_poly(s, t, encryption_scheme->ctx_q);

	fmpz_set_str(q2, Q2, 10);
	for (int i = 0; i < DEGREE; i++) {
		fmpz_poly_get_coeff_fmpz(coeff, s, i);
		if (fmpz_cmp(coeff, q2) >= 0) {
			fmpz_sub(coeff, coeff, encryption_scheme->q);
		}
		fmpz_poly_set_coeff_fmpz(s, i, coeff);
	}

	fmpz_mod_poly_set_fmpz_poly(m, s, encryption_scheme->ctx_p);

	if (chall != NULL) {
		// Check linf-norm.
		fmpz_set_ui(q2, 12 * SIGMA_E);
		for (int i = 0; i < DEGREE; i++) {
			fmpz_mod_poly_get_coeff_fmpz(coeff, m, i, encryption_scheme->ctx_p);
			if (fmpz_cmp(coeff, q2) >= 0) {
				//TODO: fixme
				//result = 0;
			}
		}
	}

	fmpz_clear(coeff);
	fmpz_poly_clear(s);
	fmpz_mod_poly_clear(t, encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(_t, encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(u[0], encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(u[1], encryption_scheme->ctx_q);
	return result;
}

// Free ciphertext
void encrypt_free(encryption_scheme_t encryption_scheme,ciphertext_t *c) {
	for (int i = 0; i < DIM; i++) {
		fmpz_mod_poly_clear(c->w[i], encryption_scheme->ctx_q);
		for (int j = 0; j < DIM; j++) {
			fmpz_mod_poly_clear(c->v[i][j], encryption_scheme->ctx_q);
		}
	}
}

#ifdef MAIN
// Tests and benchmarks below.
static void test(encryption_scheme_t encryption_scheme, flint_rand_t rand) {
	publickey_t pk;
	privatekey_t sk;
	ciphertext_t c;
	fmpz_mod_poly_t m, _m, w[2];

	fmpz_mod_poly_init(m, encryption_scheme->ctx_q);
	fmpz_mod_poly_init(_m, encryption_scheme->ctx_q);
	fmpz_mod_poly_init(w[0], encryption_scheme->ctx_q);
	fmpz_mod_poly_init(w[1], encryption_scheme->ctx_q);

	TEST_BEGIN("CRT representation is correct") {
		fmpz_mod_poly_randtest( m, rand, DEGREE, encryption_scheme->ctx_q);
		for (int i = 0; i < 2; i++) {
			fmpz_mod_poly_rem(w[i], m, encryption_scheme->irred[i], encryption_scheme->ctx_q);
		}
		qcrt_poly_rec(encryption_scheme, _m, w);
		TEST_ASSERT(fmpz_mod_poly_equal(m, _m, encryption_scheme->ctx_q) == 1, end);
	} TEST_END;

	fmpz_mod_poly_clear(m, encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(_m, encryption_scheme->ctx_q);

	fmpz_mod_poly_init(m, encryption_scheme->ctx_p);
	fmpz_mod_poly_init(_m, encryption_scheme->ctx_p);

	TEST_BEGIN("encryption and decryption are consistent") {
		encrypt_sample_short(m, encryption_scheme->ctx_p);
		encrypt_keygen(encryption_scheme, &pk, &sk, rand);
		encrypt_doit(encryption_scheme, &c, m, &pk, rand);
		TEST_ASSERT(encrypt_undo(encryption_scheme, _m, NULL, &c, &sk) == 1, end);
		TEST_ASSERT(fmpz_mod_poly_equal(m, _m, encryption_scheme->ctx_p) == 1, end);
	} TEST_END;
  end:
	fmpz_mod_poly_clear(w[0], encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(w[1], encryption_scheme->ctx_q);
	fmpz_mod_poly_clear(m, encryption_scheme->ctx_p);
	fmpz_mod_poly_clear(_m, encryption_scheme->ctx_p);
	encrypt_keyfree(encryption_scheme, &pk, &sk);
}

static void bench(encryption_scheme_t encryption_scheme, flint_rand_t rand) {
	publickey_t pk;
	privatekey_t sk;
	ciphertext_t c;
	fmpz_mod_poly_t m, _m;

	fmpz_mod_poly_init(m, encryption_scheme->ctx_p);
	fmpz_mod_poly_init(_m, encryption_scheme->ctx_p);

	encrypt_sample_short(m, encryption_scheme->ctx_p);
	encrypt_keygen(encryption_scheme, &pk, &sk, rand);

	BENCH_BEGIN("encrypt_doit") {
		BENCH_ADD(encrypt_doit(encryption_scheme, &c, m, &pk, rand));
	} BENCH_END;

	BENCH_BEGIN("encrypt_undo") {
		BENCH_ADD(encrypt_undo(encryption_scheme, _m, NULL, &c, &sk));
	} BENCH_END;

	fmpz_mod_poly_clear(m, encryption_scheme->ctx_p);
	fmpz_mod_poly_clear(_m, encryption_scheme->ctx_p);
	encrypt_keyfree(encryption_scheme, &pk, &sk);
}

int main(int argc, char *argv[]) {
	flint_rand_t rand;

    encryption_scheme_t encryption_scheme;
	encrypt_setup(encryption_scheme);

	flint_randinit(rand);

	printf("\n** Tests for lattice-based encryption:\n\n");
	test(encryption_scheme, rand);

	printf("\n** Benchmarks for lattice-based encryption:\n\n");
	bench(encryption_scheme, rand);

	encrypt_finish(encryption_scheme);
}
#endif
