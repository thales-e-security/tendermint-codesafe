// Copyright 2017 Thales e-Security
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#ifndef TENDERMINT_H_
#define TENDERMINT_H_

#include <nfkm.h>

extern int createCanonicalVote(char *chainId, M_ByteBlock blockIDHash,
    M_ByteBlock partsHash, M_Word partsTotal, long long height, M_Word round, char *timestamp,
    M_Word type, unsigned char **output, M_Word *outputLen);

extern int createCanonicalProposal(char *chainID, M_ByteBlock blockPartsHash,
    M_Word blockPartTotal, long long height, M_ByteBlock polBlockIDHash,
    M_ByteBlock partsHash, M_Word partsTotal, int polRound, M_Word round, char *timestamp,
    unsigned char **output, M_Word *outputLen);

extern int createCanonicalHeartbeat(char *chainId, long long height, M_Word round,
    M_Word sequence, M_ByteBlock validatorAddress, M_Word validatorIndex,
    unsigned char **output, M_Word *outputLen);

#endif /* TENDERMINT_H_ */
