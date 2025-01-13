#include "param.h"
#include "shuffle.h"
#include "vericrypt.h"
#include "utils.h"


typedef char *poly_rep;

typedef struct {
    poly_rep B1[HEIGHT][WIDTH][2];
    poly_rep b2[WIDTH][2];
} PK_C;

typedef struct {
    poly_rep A[DIM][DIM][2];
    poly_rep t[DIM][2];
} PK_VE;

typedef struct {
    PK_C pk_c;
    PK_VE pk_v;
    PK_VE pk_r;
} PK;

typedef struct {
    poly_rep c1[2];
    poly_rep c2[2];
} COM;

typedef poly_rep OPENING[WIDTH][2];

typedef struct {
    poly_rep a;
    COM c_a;
    OPENING d_a;
} VCK;

typedef struct {
    poly_rep v[DIM][2];
    poly_rep w[2];
} CIPHER;

typedef struct {
    CIPHER cipher[VECTOR];
    poly_rep c;
    poly_rep r[VECTOR][DIM][2];
    poly_rep e[VECTOR][DIM][2];
    poly_rep e_[VECTOR][2];
    poly_rep u[VECTOR];
} VERITEXT;

typedef struct {
    poly_rep r[VECTOR][DIM][2];
    poly_rep e[VECTOR][DIM][2];
    poly_rep e_[VECTOR][2];
    poly_rep u[VECTOR];
} Z;

typedef struct {
    poly_rep y1[WIDTH][2];
    poly_rep y2[WIDTH][2];
    poly_rep y3[WIDTH][2];
    poly_rep t1[2];
    poly_rep t2[2];
    poly_rep t3[2];
    poly_rep u[2];
} SUM_PROOF;

typedef struct {
    COM c;
    CIPHER cipher[VECTOR];
    poly_rep e_c;
} EV;

typedef struct {
    Z z;
    COM c_r;
    VERITEXT e_r;
    SUM_PROOF psum;
} PROOF;

void cast(const PK pk, const VCK vck, poly_rep v);