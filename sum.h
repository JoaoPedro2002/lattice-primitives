#include "commit.h"

# ifdef SHARED
extern "C" {
# endif

void sum_prover(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta, nmod_poly_t r1[WIDTH][2],
                nmod_poly_t r2[WIDTH][2], nmod_poly_t r3[WIDTH][2]);

int sum_verifier(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                 nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                 commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                 commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta);

# ifdef SHARED
} // extern "C"
# endif

