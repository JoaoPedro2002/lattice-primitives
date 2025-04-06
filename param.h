/**
 * @defgroup evoting Lattice-based electronic voting.
 */
/**
 * @file
 *
 * Common parameters to all lattice-based schemes.
 *
 * @ingroup evoting
 */

#include "stddef.h"
#include <sys/random.h>
#include <stdint.h>
#include <flint/flint.h>
#include <flint/fmpz_mod_poly.h>
#include <string.h>
#include "gmp.h"

#ifdef _WIN32
#   define API __declspec(dllexport)
#else
#   define API
#endif

# ifdef SHARED
extern "C" {
# endif
/*============================================================================*/
/* Constant definitions                                                       */
/*============================================================================*/

/* Modulus p defining the cyclotomic ring for the commitment scheme. */
#define MODP 	3906450253
/* Degree of the polynomial defining the cyclotomic ring for the commitment scheme. */
#define DEGREE 	1024
/* Degree of each polynomial used to define the CRT representation. */
#define DEGCRT 	(DEGREE >> 1)
/* Standard deviation for discrete Gaussians. */
#define SIGMA_C 54000
// Standard deviation of discrete Gaussian
#define SIGMA_E	54000

# ifdef SHARED
} // extern "C"
# endif