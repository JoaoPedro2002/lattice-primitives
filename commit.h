/**
 * @defgroup commit Lattice-based commitment.
 */
/**
 * @file
 *
 * Interface of the lattice-based commitment scheme.
 *
 * @ingroup commit
 */

#include <flint/flint.h>
#include <flint/nmod_poly.h>

/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/* Parameter v in the commitment scheme (laximum l1-norm of challs). */
#define NONZERO 36
/* The \infty-norm bound of certain elements. */
#define BETA 	1
/* Width k of the comming matrix. */
#define WIDTH 	3
/* Height of the commitment matrix. */
#define HEIGHT 	1

#ifdef _WIN32
#   define API __declspec(dllexport)
#else
#   define API
#endif

# ifdef SHARED
extern "C" {
# endif

/*============================================================================*/
/* Type definitions                                                           */
/*============================================================================*/

/* Type that represents a polynomial in CRT representation. */
typedef nmod_poly_t pcrt_poly_t[2];

/* Type that represents a commitment key pair. */
typedef struct _key_t {
	pcrt_poly_t B1[HEIGHT][WIDTH];
	pcrt_poly_t b2[WIDTH];
} commitkey_t;

/* Type that represents a commitment in CRT representation. */
typedef struct _com_t {
	pcrt_poly_t c1, c2;
} commit_t;

typedef struct _commitment_scheme_s {
    /* Polynomial defining the cyclotomic ring. */
    nmod_poly_t cyclo_poly;
    /* Pair of irreducible polynomials for CRT representation. */
    pcrt_poly_t irred;
    /* Inverses of the irreducible polynomials for CRT reconstruction. */
    pcrt_poly_t inv;
} commitment_scheme_s;

typedef commitment_scheme_s commitment_scheme_t[1];



/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 * Initialize the commitment_scheme module.
 * @param[in] commitment_scheme - the commitment_scheme to initialize.
 */
void commit_scheme_init(commitment_scheme_t commitment_scheme);

/**
 * Finalize the commitment_scheme module.
 * @param[in] commitment_scheme - the commitment_scheme to finalize.
 */
void commit_scheme_finish(commitment_scheme_t commitment_scheme);

/**
 * Return the polynomial (x^N + 1) defining the cyclotomic ring Rp.
 *
 * @param[in] commitment_scheme - the commitment scheme.
 *
 * @return the polynomial defining the cyclotomic ring Rp.
 */
nmod_poly_t *commit_poly(commitment_scheme_t commitment_scheme);

/**
 * Return the i-th polynomial defining the CRT representation.
 * The returned polynomial is such that it factors the polynomial defining Rp.
 *
 * @param[in] commitment_scheme - the commitment scheme.
 * @param[in] i - the index of the polynomial to return.
 *
 * @return the i-th irreducible polynomial defining the CRT representation.
 */
nmod_poly_t *commit_irred(commitment_scheme_t commitment_scheme, int i);

/**
 * Recover polynomial from CRT representation.
 *
 * @param[in] commitment_scheme - the commitment scheme.
 * @param[out] c 		- the resulting polynomial.
 * @param[in] a 		- the polynomial in CRT representation.
 */
void pcrt_poly_rec(const commitment_scheme_t commitment_scheme, nmod_poly_t c, pcrt_poly_t a);

/**
 * Convert polynomial from CRT representation
 * @param[in] commitment_scheme - the commitment scheme.
 * @param[out] c 		- the resulting polynomial in CRT representation.
 * @param[in] a 		- the polynomial.
 */
void pcrt_poly_conv(const commitment_scheme_t commitment_scheme, pcrt_poly_t c, const nmod_poly_t a);

/**
 * Compute the squared l2-norm of a polynomial.
 *
 * @param[in] r			- the polynomial to compute the norm.
 * @return The squared l2-norm.
 */
uint64_t commit_norm2_sqr(nmod_poly_t r);

/**
 * Compute the l\infty-norm of a polynomial.
 *
 * @param[in] r			- the polynomial to compute the norm.
 * @return The l\infty-norm.
 */
uint64_t commit_norm_inf(nmod_poly_t r);

/**
 * Generate a key pair for the commitment scheme using a PRNG.
 *
 * @param[out] key 		- the generated key pair.
 * @param[in] rand		- the random number generator.
 */
void commit_keygen(commitkey_t *key, flint_rand_t rand);

/**
 * Free a key pair for the commitment scheme.
 *
 * @param[out] key 		- the generated key pair.
 * @param[in] rand		- the random number generator.
 */
void commit_keyfree(commitkey_t *key);

/**
 * Sample a short polynomial.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_short(nmod_poly_t r);

/**
 * Sample a short polynomial in CRT representation.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_short_crt(commitment_scheme_t commitment_scheme, pcrt_poly_t r);

/**
 * Sample a random polynomial.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_rand(nmod_poly_t r, flint_rand_t rand, int degree);

/**
 * Sample a random polynomial in CRT representation.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_rand_crt(commitment_scheme_t commitment_scheme, pcrt_poly_t r, flint_rand_t rand);

/**
 * Sample a random challenge.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_chall(nmod_poly_t f);

/**
 * Sample a random challenge in CRT representation.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_chall_crt(commitment_scheme_t commitment, pcrt_poly_t f);

/**
 * Sample a random polynomial following a Gaussian distribution.
 *
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_gauss(nmod_poly_t r);

/**
 * Sample a random polynomial following a Gaussian distribution in CRT
 * representation.
 *
 * @param[in] commitment	- the commitment scheme.
 * @param[out] r		- the polynomial to sample.
 */
void commit_sample_gauss_crt(commitment_scheme_t commitment, pcrt_poly_t r);

/**
 * Commit to a message and randomness using a key pair.
 *
 * @param[out] com 		- the resulting commitment.
 * @param[in] m 		- the message to commit.
 * @param[in] r 		- the commitment randomness.
 */
void commit_doit(commitment_scheme_t commitment, commit_t *com, nmod_poly_t m, commitkey_t *key,
                 pcrt_poly_t r[WIDTH]);

/**
 * Open a commitment on a certain message.
 *
 * @param[in] com 		- the commitment to open.
 * @param[in] m 		- the associated message.
 * @param[in] r			- the opening randomness.
 * @param[in] f			- the opening challenge.
 */
int commit_open(commitment_scheme_t commitment, commit_t *com, nmod_poly_t m, commitkey_t *key,
                pcrt_poly_t r[WIDTH], pcrt_poly_t f);

/**
 * Recover a message from a commitment and an opening.
 * @param[in] commitment_scheme - the commitment scheme.
 * @param[out] message - the recovered message.
 * @param[in] com - the commitment.
 * @param[in] key - the key used to commit the message.
 * @param[in] r - the commitment randomness.
 * @return 0 if the opening is valid, -1 otherwise.
 */
int commit_message_rec(commitment_scheme_t commitment_scheme, nmod_poly_t message, commit_t *com, commitkey_t *key,
                        pcrt_poly_t r[WIDTH]);

/**
 * Free a commitment.
 *
 * @param[out] com 		- the commitment to free.
 */
void commit_free(commit_t *com);


commit_t *commit_ptr_init();

void commit_ptr_free(commit_t *com);

# ifdef SHARED
} // extern "C"
# endif

