# lattice-voting-ctrsa21

Code developed from the implementation from the paper "Lattice-Based Proof of Shuffle and Applications to Electronic Voting" by Diego F. Aranha, Carsten Baum, Kristian Gjøsteen,
Tjerand Silde, and Thor Tunge accepted at CT-RSA 2021.

Depedencies are the GMP and FLINT 3.1.2

# Installation

To install the shared library, run the following commands:

```bash
$ make shared-lib
```

# Usage

The shared library should be moved to the python library module `lbvs-lib`

```bash
mv shared_lib.so {PATH_TO_PYTHON_LIB}/lbvs-lib/src/lbvs_lib/
```

# Test Proof for Sum

To test the proof for the sum of the votes, run the following command:

```bash
make sum
./sum
```

# WASM

To compile the code to WebAssembly, first compile all dependencies to WASM:

```bash
cd compile-wasm
make all
cd ..
```

This should take some time. Then compile the code to WASM:

```bash
export WASM_PREFIX=${PWD}/compile-wasm/output/wasm
make wasm
```

WARNING: This is an academic proof of concept, and in particular has not received code review. This implementation is NOT ready for any type of production use.
