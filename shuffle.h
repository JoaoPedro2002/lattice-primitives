#include "commit.h"

#ifdef _WIN32
#   define API __declspec(dllexport)
#else
#   define API
#endif

# ifdef SHARED
extern "C" {
# endif
//    TODO msgs should be a variable
#define MSGS        25

int shuffle_run(commitment_scheme_t commitment_scheme, commit_t *com[MSGS], nmod_poly_t m[MSGS],
                nmod_poly_t _m[MSGS], nmod_poly_t r[MSGS][WIDTH][2], commitkey_t *key, flint_rand_t rng);

void sum_prover(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta, nmod_poly_t r1[WIDTH][2],
                nmod_poly_t r2[WIDTH][2], nmod_poly_t r3[WIDTH][2]);

int sum_verifier(nmod_poly_t y1[WIDTH][2], nmod_poly_t y2[WIDTH][2], nmod_poly_t y3[WIDTH][2],
                 nmod_poly_t t1[2], nmod_poly_t t2[2], nmod_poly_t t3[2], nmod_poly_t u[2],
                 commitment_scheme_t commitment_scheme, commit_t x1, commit_t x2, commit_t x3,
                 commitkey_t *key, nmod_poly_t alpha, nmod_poly_t beta);

void lin_prover(nmod_poly_t y[WIDTH][2], nmod_poly_t _y[WIDTH][2],
                nmod_poly_t t[2], nmod_poly_t _t[2], nmod_poly_t u[2], commitment_scheme_t commitment_scheme,
                commit_t x, commit_t _x, commitkey_t *key, nmod_poly_t alpha,
                nmod_poly_t beta, nmod_poly_t r[WIDTH][2], nmod_poly_t _r[WIDTH][2],
                int l);

int lin_verifier(nmod_poly_t y[WIDTH][2], nmod_poly_t _y[WIDTH][2],
                 nmod_poly_t t[2], nmod_poly_t _t[2], nmod_poly_t u[2], commitment_scheme_t commitment_scheme,
                 commit_t com, commit_t x, commitkey_t *key,
                 nmod_poly_t alpha, nmod_poly_t beta, int l);

void shuffle_prover(nmod_poly_t y[MSGS][WIDTH][2], nmod_poly_t _y[MSGS][WIDTH][2], nmod_poly_t t[MSGS][2],
                    nmod_poly_t _t[MSGS][2], nmod_poly_t u[MSGS][2], commitment_scheme_t commitment_scheme,
                    commit_t d[MSGS], nmod_poly_t s[MSGS], commit_t *com[MSGS], nmod_poly_t m[MSGS],
                    nmod_poly_t _m[MSGS], nmod_poly_t r[MSGS][WIDTH][2], nmod_poly_t rho,
                    commitkey_t *key, flint_rand_t rng);

int shuffle_verifier(nmod_poly_t y[MSGS][WIDTH][2],
                     nmod_poly_t _y[MSGS][WIDTH][2], nmod_poly_t t[MSGS][2],
                     nmod_poly_t _t[MSGS][2], nmod_poly_t u[MSGS][2], commitment_scheme_t commitment_scheme,
                     commit_t d[MSGS], nmod_poly_t s[MSGS], commit_t *com[MSGS], nmod_poly_t _m[MSGS],
                     nmod_poly_t rho, commitkey_t *key);

# ifdef SHARED
} // extern "C"
# endif
