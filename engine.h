#ifndef ENGINE_H
#define ENGINE_H
#include "colossus.h"

// Cipher-agnostic search engine. run_solver() drives every CipherModel; per-type
// solvers assemble a SolverCtx via make_solver_ctx() and hand it over.
double run_solver(const CipherModel *model, SolverCtx *ctx);
SolverCtx make_solver_ctx(ColossusConfig *cfg, SharedData *shared, char *cribtext,
    int cipher[], int cipher_len, int crib_indices[], int crib_positions[], int n_cribs);

// Overlay the tuned per-cipher-type search schedule (see SearchDefaults). Returns
// true if a profile was applied; `announce` prints a one-line note when it does.
bool apply_cipher_defaults(ColossusConfig *cfg, bool announce);
#endif
