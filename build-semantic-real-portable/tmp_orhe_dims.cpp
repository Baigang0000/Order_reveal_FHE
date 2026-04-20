#include <cstdio>
#include "orhe.h"
int main(){ ORHEParams p{8,0,255}; ORHEKeySet* ks = orhe_new_keyset(110,&p); const auto* bkfft = ks->data_sk->cloud.bkFFT; std::printf("in_n=%d out_n=%d ks_n=%d ks_t=%d ks_basebit=%d accum_N=%d accum_k=%d\n", bkfft->in_out_params->n, ks->cmp_sk->params->n, bkfft->ks->n, bkfft->ks->t, bkfft->ks->basebit, bkfft->accum_params->N, bkfft->accum_params->k); orhe_delete_keyset(ks); }
