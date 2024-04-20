#include "encrypt.h"

// Dimension of the message space in verifiable encryption.
#define VECTOR	3

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

/* Type that represents a verifiable encryption ciphertext. */
typedef struct _veritext_t {
    ciphertext_t cipher[VECTOR];
    fmpz_mod_poly_t c;
    fmpz_mod_poly_t r[VECTOR][DIM][2];
    fmpz_mod_poly_t e[VECTOR][DIM][2];
    fmpz_mod_poly_t e_[VECTOR][2];
    fmpz_mod_poly_t u[VECTOR];
} veritext_t;

/*============================================================================*/
/* Function prototypes                                                        */
/*============================================================================*/

/**
 *
 * r, e, e′, μ are a preimage of v, w modulo q
 * @param out
 * @param t
 * @param u
 * @param m
 * @param encryption_scheme
 * @param pk
 * @param rand
 * @return
 */
int vericrypt_doit(veritext_t *out, fmpz_mod_poly_t t[VECTOR],
                   fmpz_mod_poly_t u, fmpz_mod_poly_t m[VECTOR], encryption_scheme_t encryption_scheme,
                   publickey_t *pk, flint_rand_t rand);

/**
 *
 * @param in
 * @param t
 * @param u
 * @param encryption_scheme
 * @param pk
 * @return
 */
int vericrypt_verify(veritext_t *in, fmpz_mod_poly_t t[VECTOR],
                     fmpz_mod_poly_t u, encryption_scheme_t  encryption_scheme, publickey_t *pk);

/**
 *
 * @param m
 * @param c
 * @param in
 * @param t
 * @param u
 * @param encryption_scheme
 * @param pk
 * @param sk
 * @return
 */
int vericrypt_undo(fmpz_mod_poly_t m[VECTOR], fmpz_mod_poly_t c,
                   veritext_t *in, fmpz_mod_poly_t t[VECTOR], fmpz_mod_poly_t u,
                   encryption_scheme_t encryption_scheme, publickey_t *pk, privatekey_t *sk);

void vericrypt_cipher_clear(veritext_t *in, encryption_scheme_t encryption_scheme);

#ifdef SHARED
} // extern "C"
#endif