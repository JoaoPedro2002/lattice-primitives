#include "utils.h"
#include "param.h"

void utils_fmpz_to_nmod(nmod_poly_t f, const fmpz_mod_poly_t g) {
    fmpz_mod_poly_get_nmod_poly(f, g);
}

void utils_nmod_to_fmpz(fmpz_mod_poly_t f, const nmod_poly_t g) {
    fmpz_mod_poly_set_nmod_poly(f, g);
}

void utils_fmpz_mod_poly_one(fmpz_mod_poly_t poly, const fmpz_mod_ctx_t ctx) {
    fmpz_mod_poly_one(poly, ctx);
}

void utils_nmod_poly_one(nmod_poly_t f) {
    nmod_poly_zero(f);
    nmod_poly_set_coeff_ui(f, 0, 1);
}

void utils_nmod_poly_zero(nmod_poly_t f) {
    nmod_poly_zero(f);
}

void utils_print_nmod_poly(nmod_poly_t p) {
    nmod_poly_print(p);
}

void utils_pretty_print_nmod_poly(nmod_poly_t p) {
    nmod_poly_print_pretty(p, "x");
}

void utils_print_fmpz_poly(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx) {
    fmpz_mod_poly_print(p, ctx);
}

void utils_pretty_print_fmpz_poly(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx) {
    fmpz_mod_poly_print_pretty(p, "x", ctx);
}

char *utils_nmod_poly_to_string(nmod_poly_t p) {
    return nmod_poly_get_str(p);
}

char *utils_fmpz_mod_poly_to_string(fmpz_mod_poly_t p, fmpz_mod_ctx_t ctx) {
    nmod_poly_t tmp;
    nmod_poly_init(tmp, MODP);
    fmpz_mod_poly_get_nmod_poly(tmp, p);
    char* str = nmod_poly_get_str(tmp);
    nmod_poly_clear(tmp);
    return str;
}

void utils_nmod_poly_from_string(nmod_poly_t p, char *str) {
    nmod_poly_set_str(p, str);
}

void utils_fmpz_mod_poly_from_string(fmpz_mod_poly_t p, char *str) {
    nmod_poly_t tmp;
    nmod_poly_init(tmp, MODP);
    nmod_poly_set_str(tmp, str);
    fmpz_mod_poly_set_nmod_poly(p, tmp);
    nmod_poly_clear(tmp);
}

void utils_flint_free(void *ptr) {
    flint_free(ptr);
}

