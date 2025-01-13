#include "stdint.h"
#include "stddef.h"

#ifdef __cplusplus
extern "C" {
#endif

int64_t discrete_gaussian(const double center);

void discrete_gaussian_vec(int64_t *samples, const double center, const size_t size);

#ifdef __cplusplus
}
#endif

