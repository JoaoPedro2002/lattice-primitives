#include "gaussian.h"
#include "param.h"
#include "dgs/dgs_gauss.h"

int64_t discrete_gaussian(const double center) {
    mpz_t r;
    mpz_init(r);

    mpfr_set_default_prec(80);
    mpfr_t sigma;
    mpfr_init_set_d(sigma, SIGMA_C, MPFR_RNDN);
    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpfr_t c;
    mpfr_init_set_d(c, center, MPFR_RNDN);
    dgs_disc_gauss_mp_t *gen = dgs_disc_gauss_mp_init(sigma, c, 10, DGS_DISC_GAUSS_DEFAULT);

    gen->call(r, gen, state);
    int64_t result = mpz_get_si(r);

    dgs_disc_gauss_mp_clear(gen);
    mpfr_clear(sigma);
    mpz_clear(r);
    mpfr_clear(c);

    return result;
}

void discrete_gaussian_vec(int64_t* samples, const double center, const size_t size) {
    mpz_t r;
    mpz_init(r);

    mpfr_set_default_prec(80);
    mpfr_t sigma;
    mpfr_init_set_d(sigma, SIGMA_C, MPFR_RNDN);
    gmp_randstate_t state;
    gmp_randinit_default(state);

    mpfr_t c;
    mpfr_init_set_d(c, center, MPFR_RNDN);
    dgs_disc_gauss_mp_t *gen = dgs_disc_gauss_mp_init(sigma, c, 10, DGS_DISC_GAUSS_DEFAULT);

    for (size_t i = 0; i < size; i++) {
        gen->call(r, gen, state);
        samples[i] = mpz_get_si(r);
    }

    dgs_disc_gauss_mp_clear(gen);
    mpfr_clear(sigma);
    mpz_clear(r);
    mpfr_clear(c);
}