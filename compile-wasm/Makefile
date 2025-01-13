##################################################################
#    Makefile that compiles flint and its dependencies to wasm   #
##################################################################
# Dirs
CURR_DIR=$(shell pwd)
OUTPUT_DIR := ${CURR_DIR}/output
SO_OUTPUT_DIR := ${OUTPUT_DIR}/shared
WASM_OUTPUT_DIR := ${OUTPUT_DIR}/wasm
WASM_LIB_DIR := ${WASM_OUTPUT_DIR}/lib
WASM_INCLUDE_DIR := ${WASM_OUTPUT_DIR}/include
BUILD_DIR := ${CURR_DIR}/build
__dummy := $(shell mkdir -p ${BUILD_DIR} ${SO_OUTPUT_DIR} ${WASM_OUTPUT_DIR})

# Libraries
FLINT_VERSION=3.1.2
FLINT=flint-${FLINT_VERSION}
FLINT_SOURCE=https://flintlib.org/${FLINT}.tar.gz

GMP_VERSION=6.3.0
GMP=gmp-${GMP_VERSION}
GMP_SOURCE=https://gmplib.org/download/gmp/${GMP}.tar.gz

MPFR_VERSION=4.2.1
MPFR=mpfr-${MPFR_VERSION}
MPFR_SOURCE=https://www.mpfr.org/mpfr-current/${MPFR}.tar.gz

# DGS
DGS=dgs
DGS_SOURCE=https://github.com/malb/dgs/archive/refs/heads/master.tar.gz

# Map to link a library to its source
${MPFR} := MPFR
${FLINT} := FLINT
${GMP} := GMP
${DGS} := DGS

# Commands
EMCONFIGURE := emconfigure ./configure --build i686-pc-linux-gnu --disable-assembly --host=none --prefix=${WASM_OUTPUT_DIR} CFLAGS="-O3 -Wall"
EMMAKE := emmake make -j $(shell expr $(shell nproc) + 1) && emmake make install

.PHONY: wasm build-clean

all: wasm

wasm: build-clean ${WASM_LIB_DIR}/libflint.a ${WASM_LIB_DIR}/libdgs.a

${WASM_LIB_DIR}/libgmp.a: ${BUILD_DIR}/${GMP}/
	cd ${BUILD_DIR}/${GMP}/ && CC_FOR_BUILD=gcc ${EMCONFIGURE} && ${EMMAKE}

${WASM_LIB_DIR}/libmpfr.a: ${WASM_LIB_DIR}/libgmp.a ${BUILD_DIR}/${MPFR}/
	cd ${BUILD_DIR}/${MPFR}/ && CC_FOR_BUILD=gcc ABI=long ${EMCONFIGURE} --with-gmp=${WASM_OUTPUT_DIR} && ${EMMAKE}

${WASM_LIB_DIR}/libflint.a: ${WASM_LIB_DIR}/libmpfr.a ${BUILD_DIR}/${FLINT}/
	cd ${BUILD_DIR}/${FLINT}/ && ${EMCONFIGURE} --with-gmp=${WASM_OUTPUT_DIR} --with-mpfr=${WASM_OUTPUT_DIR} && ${EMMAKE}

${WASM_LIB_DIR}/libdgs.a: ${BUILD_DIR}/${DGS}/
	cd ${BUILD_DIR}/${DGS}/ && autoreconf -i && ${EMCONFIGURE}  && emmake make -j $(shell expr $(shell nproc) + 1) CFLAGS="-I${WASM_INCLUDE_DIR} -L${WASM_LIB_DIR}" && emmake make install

${BUILD_DIR}/%/: %.tar.gz
	mkdir -p $@ && tar -xzf $< -C $@ --strip-components=1

%.tar.gz:
	wget -q $($($*)_SOURCE) -O $@

build-clean:
	if [ -d ${BUILD_DIR}/${FLINT} ]; then cd ${BUILD_DIR}/${FLINT}/ && make clean; fi
	if [ -d ${BUILD_DIR}/${MPFR} ]; then cd ${BUILD_DIR}/${MPFR}/ && make clean; fi
	if [ -d ${BUILD_DIR}/${GMP} ]; then cd ${BUILD_DIR}/${GMP}/ && make clean; fi

clean:
	rm -rf ${BUILD_DIR} ${OUTPUT_DIR}
