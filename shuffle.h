#include "commit.h"

#ifdef _WIN32
#   define API __declspec(dllexport)
#else
#   define API
#endif

# ifdef SHARED
extern "C" {
# endif
#define MSGS        10000

typedef pcrt_poly_t opening_t[WIDTH];

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
                 nmod_poly_t alpha, nmod_poly_t beta, int l, int len);

int shuffle_run(commitment_scheme_t commitment_scheme, commit_t **com, nmod_poly_t *m,
                nmod_poly_t *_m, opening_t *r, commitkey_t *key, flint_rand_t rng, int len);

void shuffle_prover(opening_t *y, opening_t *_y, pcrt_poly_t *t,
                    pcrt_poly_t *_t, pcrt_poly_t *u, commitment_scheme_t commitment_scheme,
                    commit_t *d, nmod_poly_t *s, commit_t **com, nmod_poly_t *m,
                    nmod_poly_t *_m, opening_t *r, nmod_poly_t rho,
                    commitkey_t *key, flint_rand_t rng, int len);

int shuffle_verifier(opening_t *y, opening_t *_y, pcrt_poly_t *t,
                     pcrt_poly_t *_t, pcrt_poly_t *u, commitment_scheme_t commitment_scheme,
                     commit_t *d, nmod_poly_t *s, commit_t **com, nmod_poly_t *_m,
                     nmod_poly_t rho, commitkey_t *key, int len);

# ifdef SHARED
opening_t * malloc_opening(size_t len);

pcrt_poly_t * malloc_pcrt_poly(size_t len);

nmod_poly_t * malloc_poly(size_t len);

commit_t * malloc_commit(size_t len);

} // extern "C"
# endif
