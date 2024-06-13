/**
 * @file
 *
 * Helper interface for flint functions to export in the shared object
 *
 */
#include <flint/fmpz_mod_poly.h>
#include <flint/nmod_poly.h>


#ifdef _WIN32
#   define API __declspec(dllexport)
#else
#   define API
#endif

# ifdef SHARED
extern "C" {
# endif

    void utils_fmpz_to_nmod(nmod_poly_t f, const fmpz_mod_poly_t g);

    void utils_nmod_to_fmpz(fmpz_mod_poly_t f, const nmod_poly_t g);

    void utils_fmpz_mod_poly_one(fmpz_mod_poly_t poly, const fmpz_mod_ctx_t ctx);

    void utils_nmod_poly_one(nmod_poly_t f);

    void utils_nmod_poly_zero(nmod_poly_t f);

    void utils_print_nmod_poly(nmod_poly_t p);

    void utils_pretty_print_nmod_poly(nmod_poly_t p);

    void utils_print_fmpz_poly(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx);

    void utils_pretty_print_fmpz_poly(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx);

    char *utils_nmod_poly_to_string(nmod_poly_t p);

    char *utils_fmpz_mod_poly_to_string(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx);

    void utils_nmod_poly_from_string(nmod_poly_t p, char *str);

    void utils_fmpz_mod_poly_from_string(fmpz_mod_poly_t p, char *str);

    void utils_flint_free(void *ptr);

# ifdef SHARED
} // extern "C"
# endif