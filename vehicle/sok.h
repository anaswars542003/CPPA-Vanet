#include"miracl.h"
#ifndef SOK_H
#define SOK_H

struct Signature{
    unsigned char Rx[33];
    unsigned char Ry[33];
    unsigned char z[33];
};

typedef struct Signature sok_signature;

void cal_e_hash(miracl* mip ,char* c, char* msg, size_t msg_size, big e);
void genProof(miracl* mip, big q, epoint* p, big sk, char* c, char* msg,  size_t msg_size, int t, sok_signature* sig);
BOOL verifyProof(miracl* mip, big q, epoint* p, char* c, char* msg, size_t msg_size, int t, sok_signature* sig);

#endif
