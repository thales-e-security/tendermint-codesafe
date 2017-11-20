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


#include <stdlib.h>
#include <nfkm.h>

#include "tendermint.h"
#include "utils.h"

// Ugly macro definition, but easier than crafting a canonical JSON library
#define VOTE_FMT "{\"chain_id\":\"%s\",\"vote\":{\"block_id\":{\"hash\":\"%s\",\"parts\":{\"hash\":\"%s\",\"total\":%d}},\"height\":%d,\"round\":%d,\"type\":%d}}"
#define PROPOSAL_FMT "{\"chain_id\":\"%s\",\"proposal\":{\"block_parts_header\":{\"hash\":\"%s\",\"total\":%d},\"height\":%d,\"pol_block_id\":{%s},\"pol_round\":%d,\"round\":%d}}"
#define POL_BLOCK_ID_FMT "\"hash\":\"%s\",\"parts\":{\"hash\":\"%s\",\"total\":%d}"
#define HEARTBEAT_FMT "{\"chain_id\":\"%s\",\"heartbeat\":{\"height\":%d,\"round\":%d,\"sequence\":%d,\"validator_address\":\"%s\",\"validator_index\":%d}}"

extern int createCanonicalVote(char *chainId, M_ByteBlock blockIDHash,
    M_ByteBlock partsHash, M_Word partsTotal, M_Word height, M_Word round,
    M_Word type, unsigned char **output, M_Word *outputLen) {

  int res;
  char *blockIdHashStr = NULL;
  char *partsHashStr = NULL;
  *output = NULL;

  res = toHexString(blockIDHash.ptr, blockIDHash.len, &blockIdHashStr);
  if (res) {
    goto cleanup;
  }

  res = toHexString(partsHash.ptr, partsHash.len, &partsHashStr);
  if (res) {
    goto cleanup;
  }

  res = allocSprintF((char **) output, VOTE_FMT, chainId, blockIdHashStr,
      partsHashStr, partsTotal, height, round, type);

  if (res < 0) {
    goto cleanup;
  }

  *outputLen = res;
  res = 0;

  cleanup:

  free(blockIdHashStr);
  free(partsHashStr);
  return res;
}

extern int createCanonicalProposal(char *chainID, M_ByteBlock blockPartsHash,
    M_Word blockPartTotal, M_Word height, M_ByteBlock polBlockIDHash,
    M_ByteBlock partsHash, M_Word partsTotal, int polRound, M_Word round,
    unsigned char **output, M_Word *outputLen) {

  int res;
  char *blockPartsHashStr = NULL;
  char *polBlockIDHashStr = NULL;
  char *partsHashStr = NULL;
  char *polBlockIDStr = NULL;
  *output = NULL;

  res = toHexString(blockPartsHash.ptr, blockPartsHash.len, &blockPartsHashStr);
  if (res) {
    goto cleanup;
  }

  res = toHexString(polBlockIDHash.ptr, polBlockIDHash.len, &polBlockIDHashStr);
  if (res) {
    goto cleanup;
  }

  if (polRound == -1) {
    polBlockIDStr = calloc(1, 1);
  } else {

    res = toHexString(partsHash.ptr, partsHash.len, &partsHashStr);
    if (res) {
      goto cleanup;
    }

    res = allocSprintF(&polBlockIDStr, POL_BLOCK_ID_FMT, polBlockIDHashStr,
        partsHashStr, partsTotal);
    if (res < 0) {
      goto cleanup;
    }
  }

  res = allocSprintF((char**) output, PROPOSAL_FMT, chainID, blockPartsHashStr,
      blockPartTotal, height, polBlockIDStr, polRound, round);

  if (res < 0) {
    goto cleanup;
  }

  *outputLen = res;
  res = 0;

  cleanup:

  free(blockPartsHashStr);
  free(polBlockIDHashStr);
  if (polRound != -1) {
    free(polBlockIDStr);
    free(partsHashStr);
  }

  return res;
}

extern int createCanonicalHeartbeat(char *chainId, M_Word height, M_Word round,
    M_Word sequence, M_ByteBlock validatorAddress, M_Word validatorIndex,
    unsigned char **output, M_Word *outputLen) {

  char *validatorAddressStr = NULL;
  int res;

  res = toHexString(validatorAddress.ptr, validatorAddress.len,
      &validatorAddressStr);
  if (res) {
    goto cleanup;
  }

  res = allocSprintF((char**) output, HEARTBEAT_FMT, chainId, height, round,
      sequence, validatorAddressStr, validatorIndex);

  if (res < 0) {
    goto cleanup;
  }

  *outputLen = res;
  res = 0;

  cleanup:

  free(validatorAddressStr);

  return res;
}
