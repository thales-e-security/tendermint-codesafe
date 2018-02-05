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


#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#include <nfkm.h>
#include <limits.h>

#include "utils.h"
#include "tendermint.h"
#include "ed25519/ed25519.h"

// File containing the port number to listen on for jobs
#define PORTNUMBER_FILE "/opt/nfast/portnumber"

// Ident of an AES wrapping key, whose ACL is tied to this SEE machine
#define WRAPPING_KEY_IDENT "ed-wrapping-key"

#define PUBLIC_KEY_LENGTH 32
#define PRIVATE_KEY_LENGTH 64
#define SIGNATURE_SIZE 64

// These error values are defined in the Tendermint Go code
#define ERR_HEIGHT_REGRESSION -1
#define ERR_ROUND_REGRESSION -2
#define ERR_STEP_REGRESSION -3


static void processHostsideRequest(int fd);
static void handleProgramExit(int sig);
static void handleKeyLoadJob(int fd, const unsigned char *buffer, int bufferLen);
static void handleKeyGen(int fd, const unsigned char *buffer, int bufferLen);
static void handleSignVote(int fd, const unsigned char *buffer, int bufferLen);
static void handleProposalVote(int fd, const unsigned char *buffer, int bufferLen);
static void handleHeartbeat(int fd, const unsigned char *buffer, int bufferLen);
static int validateAndSignData(long long height, unsigned round, unsigned step,
    const unsigned char *data, unsigned dataLen, unsigned char *sigBuffer);


// Indicates if key has been loaded yet
static int keyLoaded = 0;

// Store keys on the stack
static unsigned char public_key[PUBLIC_KEY_LENGTH];
static unsigned char private_key[PRIVATE_KEY_LENGTH];

// Data for regression testing
// **NOTE: In this example code, this data is only stored in memory and will be reset if the SEE
// machine is reloaded. A more robust solution would be to use NVRAM to ensure increment-only
// access to the data.**
static long long lastHeight = 0;
static unsigned lastRound = 0;
static unsigned lastStep = 0;
static unsigned char *lastSignedBytes = NULL;
static unsigned lastSignedBytesLen = 0;
static unsigned char lastSignature[SIGNATURE_SIZE];

// List of job handlers. The index of the handler is the job code that the hostside
// should send across.
typedef void (*JobHandler)(int fd, const unsigned char *buffer, int bufferLen);
static JobHandler handlers[] = {handleKeyLoadJob, handleKeyGen, handleSignVote, handleProposalVote, handleHeartbeat};


int main(void) {
  struct sockaddr_in serveraddr;
  int fd, server, portNumber;
  FILE *f = NULL;
  char portFile[10], *ptr = NULL;

#ifdef RUNNING_ON_HOST
  int optval;
#endif

  setvbuf(stdout, 0, _IONBF, 0);

#ifdef RUNNING_ON_HOST
  printf("****************WARNING*******************\n");
  printf("\nRunning in HOST MODE.  NOT FOR PRODUCTION USE!!!!!\n");
  printf("****************WARNING*******************\n");

  printf("\nUsing module %i.\n\n", MODULE);
#endif

  printf("Starting main().\n");

  if (initConnection() != Status_OK) {
    fprintf(stderr, "Could not connect to hardserver.");
    exit(1);
  }

  (void) signal(SIGINT, handleProgramExit);

  f = fopen(PORTNUMBER_FILE, "r");
  if (f == NULL ) {
    fprintf(stderr, "Could not open portnumber file: %s\n",
	    PORTNUMBER_FILE);
    exit(1);
  }

  ZERO(portFile);
  if (!fgets(portFile, 10, f)) {
    fprintf(stderr, "Nothing written in portnumber file.\n");
    exit(1);
  }

  fclose(f);

  portNumber = strtol(portFile, &ptr, 10);
  if (strlen(ptr) != 0 && *ptr != '\n') {
    fprintf(stderr, "Port number file contained non-digits.\n");
    exit(1);
  }

  ZERO(serveraddr);
  serveraddr.sin_family = AF_INET;
  serveraddr.sin_port = htons(portNumber);
  serveraddr.sin_addr.s_addr = inet_addr("0.0.0.0");

  server = socket(AF_INET, SOCK_STREAM, 0);
  if (!server) {
    perror("socket");
    exit(1);
  }

#if RUNNING_ON_HOST
  // Support quick re-use of sockets, to allow for repeated debugging
  optval = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);
#endif

  if (bind(server, (struct sockaddr *) &serveraddr, sizeof(serveraddr))) {
    perror("bind");
    exit(1);
  }

  if (listen(server, SOMAXCONN)) {
    perror("listen");
    exit(1);
  }

  while (1) {
    printf("***********************\n");
    printf("Waiting new connection on port %i...\n", portNumber);
    fd = accept(server, 0, 0);
    if (fd > 0) {
      printf("Received request, processing...\n");
      processHostsideRequest(fd);
    } else {
      perror("accept");
      exit(1);
    }
  }

  return 0; // never reached
}


static void handleProgramExit(int sig) {
  printf("\n\nCaught Ctrl-C.  Closing down security world.\n");
  NFKM_freeinfo(appHandle, &worldInfo, NULL );
  NFastApp_Disconnect(conn, NULL );
  NFastApp_Finish(appHandle, NULL );
  exit(sig);
}

static void processHostsideRequest(int fd) {
  M_Status rc;
  NF_Unmarshal_Context ctx;
  M_Word jobCode;
  int res, bufferLen;
  char *buffer = NULL;

  res = readSocket(fd, &buffer, &bufferLen);
  if (res == -1) {
    sendErrorResponse(fd, "Could not read stream data.");
    goto cleanup;
  }

  ctx.ip = (unsigned char *) buffer;
  ctx.remain = bufferLen;

  rc = NF_Unmarshal_Word(&ctx, &jobCode);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Failed to unmarshal job number", rc);
    return;
  }

  if (jobCode >= sizeof(handlers)) {
	  sendErrorResponse(fd, "Unknown job number");
  } else {
	  handlers[jobCode](fd, ctx.ip, ctx.remain);
  }

  cleanup:

  free(buffer);
  close(fd);
}

static void handleKeyLoadJob(int fd, const unsigned char *buffer, int bufferLen) {
  M_Status rc;
  M_ByteBlock result, wrappedPrivKey, pubKey, privKey, tmp;
  NF_Unmarshal_Context utx;
  NF_Marshal_Context ctx;
  NF_Free_Context ftx;
  M_KeyID wrappingKey = 0;
  struct NF_UserData *userdata = NULL;
  int ctxLen;
  void *ctxPtr = NULL;

  printf("handleKeyLoadJob\n");

  userdata = NFastApp_AllocUD(appHandle, NULL, NULL, 0);

  utx.ip = buffer;
  utx.remain = bufferLen;
  utx.u = userdata;

  ZERO(ctx);
  ZERO(ftx);
  ZERO(result);
  ZERO(wrappedPrivKey);
  ZERO(pubKey);
  ZERO(privKey);

  rc = NF_Unmarshal_ByteBlock(&utx, &wrappedPrivKey);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal private key", rc);
    goto cleanup;
  }

  // Unwrap private key
  rc = loadKey("simple", WRAPPING_KEY_IDENT, 1, &wrappingKey);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Failed to load wrapping key", rc);
    goto cleanup;
  }

  rc = aesCBCDecrypt(wrappingKey, wrappedPrivKey.ptr, wrappedPrivKey.len, &privKey.ptr, &privKey.len);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Failed to unwrap private key", rc);
    goto cleanup;
  }

  if (privKey.len != PRIVATE_KEY_LENGTH) {
    sendErrorResponse(fd, "Private key wrong length");
    fprintf(stderr, "Expected %d found %d\n", PRIVATE_KEY_LENGTH, privKey.len);
    goto cleanup;
  }

  memcpy(private_key, privKey.ptr, sizeof(private_key));

  // Make public from private
  ed25519_get_pubkey(public_key, private_key);

  keyLoaded = 1;

  /*
   * Marshal data back to host.
   */
  ctx.remain = INT_MAX;
  ctx.u = userdata;

  tmp.ptr = public_key;
  tmp.len = sizeof(public_key);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal public key", rc);
    goto cleanup;
  }

  ctxLen = INT_MAX - ctx.remain;
  ctxPtr = malloc(ctxLen);
  ctx.remain = ctxLen;
  ctx.op = ctxPtr;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal public key", rc);
    goto cleanup;
  }

  // send result to hostside
  result.ptr = ctxPtr;
  result.len = ctxLen;
  sendResultToHostside(fd, result);

 cleanup:

  ftx.u = userdata;
  free(ctxPtr);

  destroyObject(&wrappingKey);

  NF_Free_ByteBlock(&ftx, &wrappedPrivKey);
  NF_Free_ByteBlock(&ftx, &pubKey);
  NF_Free_ByteBlock(&ftx, &privKey);

  if (userdata != NULL) {
    NFastApp_FreeUD(userdata);
  }
}

static void handleKeyGen(int fd, const unsigned char *buffer, int bufferLen) {
  M_Status rc;
  M_ByteBlock result, tmp;
  NF_Marshal_Context ctx;
  NF_Free_Context ftx;
  struct NF_UserData *userdata = NULL;
  unsigned char seed[32], public_key[32], private_key[64];
  M_KeyID wrappingKey = 0;
  unsigned char *wrappedKey = NULL;
  unsigned wrappedKeyLen;

  int ctxLen;
  void *ctxPtr = NULL;

  printf("handleKeyGen\n");

  userdata = NFastApp_AllocUD(appHandle, NULL, NULL, 0);

  ZERO(ctx);
  ZERO(ftx);

  ed25519_create_seed(seed);
  ed25519_create_keypair(public_key, private_key, seed);

  rc = loadKey("simple", WRAPPING_KEY_IDENT, 1, &wrappingKey);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Failed to load wrapping key", rc);
    goto cleanup;
  }

  rc = aesCBCEncrypt(wrappingKey, private_key, sizeof(private_key), &wrappedKey, &wrappedKeyLen);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Failed to wrap private key", rc);
    goto cleanup;
  }


  /*
   * Marshal data back to host.
   */
  ctx.remain = INT_MAX;
  ctx.u = userdata;

  // Send public key, iv, wrapped private key

  tmp.ptr = public_key;
  tmp.len = sizeof(public_key);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal public key", rc);
    goto cleanup;
  }

  tmp.ptr = wrappedKey;
  tmp.len = wrappedKeyLen;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal wrapped key", rc);
    goto cleanup;
  }

  ctxLen = INT_MAX - ctx.remain;
  ctxPtr = malloc(ctxLen);
  ctx.remain = ctxLen;
  ctx.op = ctxPtr;

  tmp.ptr = public_key;
  tmp.len = sizeof(public_key);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal public key", rc);
    goto cleanup;
  }

  tmp.ptr = wrappedKey;
  tmp.len = wrappedKeyLen;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal wrapped key", rc);
    goto cleanup;
  }

  // send result to hostside
  result.ptr = ctxPtr;
  result.len = ctxLen;
  sendResultToHostside(fd, result);

 cleanup:

  ftx.u = userdata;
  free(ctxPtr);
  free(wrappedKey);
  destroyObject(&wrappingKey);

  if (userdata != NULL) {
    NFastApp_FreeUD(userdata);
  }
}

static void handleSignVote(int fd, const unsigned char *buffer, int bufferLen) {
  M_Status rc;
  M_ByteBlock result, blockIdHash, partsHash, canonicalVote, tmp;
  NF_Unmarshal_Context utx;
  NF_Marshal_Context ctx;
  NF_Free_Context ftx;
  struct NF_UserData *userdata = NULL;
  NFKM_String chainID = NULL, timestamp = NULL;
  unsigned char signature[SIGNATURE_SIZE];
  int ctxLen, res;
  M_Word partsTotal, round, type;
  long long height;
  void *ctxPtr = NULL;
  unsigned step;

  printf("handleSignVote\n");

  userdata = NFastApp_AllocUD(appHandle, NULL, NULL, 0);

  utx.ip = buffer;
  utx.remain = bufferLen;
  utx.u = userdata;


  ZERO(ctx);
  ZERO(ftx);
  ZERO(blockIdHash);
  ZERO(partsHash);
  ZERO(canonicalVote);

  if (!keyLoaded) {
    sendErrorResponse(fd, "Cannot sign data; no keys loaded");
    goto cleanup;
  }


  rc = NF_Unmarshal_String(&utx, &chainID);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal chainID", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_ByteBlock(&utx, &blockIdHash);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal block ID hash", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_ByteBlock(&utx, &partsHash);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal part hash", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &partsTotal);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal partsTotal", rc);
    goto cleanup;
  }

  rc = Unmarshal64BitInt(&utx, &height);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal height", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &round);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal round", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_String(&utx, &timestamp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal timestamp", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &type);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal type", rc);
    goto cleanup;
  }


  res = createCanonicalVote(chainID, blockIdHash, partsHash, partsTotal, height, round, timestamp, type,
      &canonicalVote.ptr, &canonicalVote.len);
  if (res != 0) {
    sendErrorResponse(fd, "Failed to create canonical vote");
    goto cleanup;
  }

  // magic numbers here are from Tendermint Go code (priv_validator.go)
  switch (type) {
  case 1:
    // prevote
    step = 2;
    break;
  case 2:
    // precommit
    step = 3;
    break;
  default:
    sendErrorResponse(fd, "unknown vote type");
    goto cleanup;
  }


  res = validateAndSignData(height, round, step, canonicalVote.ptr, canonicalVote.len, signature);
  if (res != 0) {
    switch (res) {
    case ERR_HEIGHT_REGRESSION:
      sendErrorResponse(fd, "Height regression");
      goto cleanup;
    case ERR_ROUND_REGRESSION:
      sendErrorResponse(fd, "Round regression");
      goto cleanup;
    case ERR_STEP_REGRESSION:
      sendErrorResponse(fd, "Step regression");
      goto cleanup;
    default:
      sendErrorResponse(fd, "Unknown error during signing");
      goto cleanup;
    }
  }

  /*
   * Marshal data back to host.
   */
  ctx.remain = INT_MAX;
  ctx.u = userdata;

  // Send signed vote

  tmp.ptr = signature;
  tmp.len = sizeof(signature);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal vote", rc);
    goto cleanup;
  }

  ctxLen = INT_MAX - ctx.remain;
  ctxPtr = malloc(ctxLen);
  ctx.remain = ctxLen;
  ctx.op = ctxPtr;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal vote", rc);
    goto cleanup;
  }


  // send result to hostside
  result.ptr = ctxPtr;
  result.len = ctxLen;
  sendResultToHostside(fd, result);

 cleanup:

  ftx.u = userdata;
  free(ctxPtr);

  NF_Free_String(&ftx, &chainID);
  NF_Free_String(&ftx, &timestamp);
  NF_Free_ByteBlock(&ftx, &blockIdHash);
  NF_Free_ByteBlock(&ftx, &partsHash);
  NF_Free_ByteBlock(&ftx, &canonicalVote);

  if (userdata != NULL) {
    NFastApp_FreeUD(userdata);
  }
}


static void handleProposalVote(int fd, const unsigned char *buffer, int bufferLen) {
  M_Status rc;
  M_ByteBlock result, canonicalProposal, blockPartsHash, polBlockIDHash, partsHash, tmp;
  NF_Unmarshal_Context utx;
  NF_Marshal_Context ctx;
  NF_Free_Context ftx;
  struct NF_UserData *userdata = NULL;
  NFKM_String chainID = NULL, timestamp = NULL;
  unsigned char signature[SIGNATURE_SIZE];
  int ctxLen, res;
  M_Word blockPartTotal, partsTotal, polRound, round;
  long long height;
  void *ctxPtr = NULL;

  printf("handleProposalVote\n");

  userdata = NFastApp_AllocUD(appHandle, NULL, NULL, 0);

  utx.ip = buffer;
  utx.remain = bufferLen;
  utx.u = userdata;


  ZERO(ctx);
  ZERO(ftx);
  ZERO(blockPartsHash);
  ZERO(polBlockIDHash);
  ZERO(partsHash);
  ZERO(canonicalProposal);


  if (!keyLoaded) {
    sendErrorResponse(fd, "Cannot sign data; no keys loaded");
    goto cleanup;
  }

  rc = NF_Unmarshal_String(&utx, &chainID);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal chainID", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_ByteBlock(&utx, &blockPartsHash);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal block parts hash", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &blockPartTotal);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal blockPartTotal", rc);
    goto cleanup;
  }

  rc = Unmarshal64BitInt(&utx, &height);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal height", rc);
    goto cleanup;
  }


  rc = NF_Unmarshal_ByteBlock(&utx, &polBlockIDHash);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal polBlockIDHash", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_ByteBlock(&utx, &partsHash);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal part hash", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &partsTotal);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal partsTotal", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &polRound);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal polRound", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &round);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal round", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_String(&utx, &timestamp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal timestamp", rc);
    goto cleanup;
  }

  res = createCanonicalProposal(chainID, blockPartsHash, blockPartTotal, height,
      polBlockIDHash, partsHash, partsTotal, (int) polRound, round, timestamp,
      &canonicalProposal.ptr, &canonicalProposal.len);
  if (res != 0) {
    sendErrorResponse(fd, "Could not create canonical proposal");
    goto cleanup;
  }

  // magic number from priv_validator.go
  res = validateAndSignData(height, round, 1, canonicalProposal.ptr, canonicalProposal.len, signature);
  if (res != 0) {
    switch (res) {
    case ERR_HEIGHT_REGRESSION:
      sendErrorResponse(fd, "Height regression");
      goto cleanup;
    case ERR_ROUND_REGRESSION:
      sendErrorResponse(fd, "Round regression");
      goto cleanup;
    case ERR_STEP_REGRESSION:
      sendErrorResponse(fd, "Step regression");
      goto cleanup;
    default:
      sendErrorResponse(fd, "Unknown error during signing");
      goto cleanup;
    }
  }

  /*
   * Marshal data back to host.
   */
  ctx.remain = INT_MAX;
  ctx.u = userdata;

  // Send canonical vote

  tmp.ptr = signature;
  tmp.len = sizeof(signature);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal proposal", rc);
    goto cleanup;
  }

  ctxLen = INT_MAX - ctx.remain;
  ctxPtr = malloc(ctxLen);
  ctx.remain = ctxLen;
  ctx.op = ctxPtr;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal proposal", rc);
    goto cleanup;
  }


  // send result to hostside
  result.ptr = ctxPtr;
  result.len = ctxLen;
  sendResultToHostside(fd, result);

 cleanup:

  ftx.u = userdata;
  free(ctxPtr);

  NF_Free_String(&ftx, &chainID);
  NF_Free_String(&ftx, &timestamp);
  NF_Free_ByteBlock(&ftx, &blockPartsHash);
  NF_Free_ByteBlock(&ftx, &polBlockIDHash);
  NF_Free_ByteBlock(&ftx, &partsHash);
  NF_Free_ByteBlock(&ftx, &canonicalProposal);

  if (userdata != NULL) {
    NFastApp_FreeUD(userdata);
  }
}


static void handleHeartbeat(int fd, const unsigned char *buffer, int bufferLen) {
  M_Status rc;
  M_ByteBlock result, canonicalHeartbeat, validatorAddress, tmp;
  NF_Unmarshal_Context utx;
  NF_Marshal_Context ctx;
  NF_Free_Context ftx;
  struct NF_UserData *userdata = NULL;
  NFKM_String chainID = NULL;
  unsigned char signature[SIGNATURE_SIZE];
  int ctxLen;
  M_Word round, sequence, validatorIndex;
  long long height;
  void *ctxPtr = NULL;

  printf("handleProposalVote\n");

  userdata = NFastApp_AllocUD(appHandle, NULL, NULL, 0);

  utx.ip = buffer;
  utx.remain = bufferLen;
  utx.u = userdata;

  /*
   * char *chainId, M_Word height, M_Word round,
    M_Word sequence, M_ByteBlock validatorAddress, M_Word validatorIndex,
   */

  ZERO(ctx);
  ZERO(ftx);
  ZERO(validatorAddress);
  ZERO(canonicalHeartbeat);

  if (!keyLoaded) {
    sendErrorResponse(fd, "Cannot sign data; no keys loaded");
    goto cleanup;
  }

  rc = NF_Unmarshal_String(&utx, &chainID);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal chainID", rc);
    goto cleanup;
  }

  rc = Unmarshal64BitInt(&utx, &height);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal height", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &round);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal round", rc);
    goto cleanup;
  }

  rc = NF_Unmarshal_Word(&utx, &sequence);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal sequence", rc);
    goto cleanup;
  }


  rc = NF_Unmarshal_ByteBlock(&utx, &validatorAddress);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal validator address", rc);
    goto cleanup;
  }


  rc = NF_Unmarshal_Word(&utx, &validatorIndex);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not unmarshal validatorIndex", rc);
    goto cleanup;
  }


  rc = createCanonicalHeartbeat(chainID, height, round, sequence, validatorAddress, validatorIndex,
      &canonicalHeartbeat.ptr, &canonicalHeartbeat.len);
  if (rc != 0) {
    sendErrorResponse(fd, "Could not create canonical heartbeat");
    goto cleanup;
  }

  ed25519_sign(signature, canonicalHeartbeat.ptr, canonicalHeartbeat.len, public_key, private_key);



  /*
   * Marshal data back to host.
   */
  ctx.remain = INT_MAX;
  ctx.u = userdata;

  // Send canonical vote

  tmp.ptr = signature;
  tmp.len = sizeof(signature);

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal heartbeat", rc);
    goto cleanup;
  }

  ctxLen = INT_MAX - ctx.remain;
  ctxPtr = malloc(ctxLen);
  ctx.remain = ctxLen;
  ctx.op = ctxPtr;

  rc = NF_Marshal_ByteBlock(&ctx, &tmp);
  if (rc != Status_OK) {
    sendNfastErrorResponse(fd, "Could not marshal heartbeat", rc);
    goto cleanup;
  }


  // send result to hostside
  result.ptr = ctxPtr;
  result.len = ctxLen;
  sendResultToHostside(fd, result);

 cleanup:

  ftx.u = userdata;
  free(ctxPtr);

  NF_Free_String(&ftx, &chainID);
  NF_Free_ByteBlock(&ftx, &validatorAddress);
  NF_Free_ByteBlock(&ftx, &canonicalHeartbeat);

  if (userdata != NULL) {
    NFastApp_FreeUD(userdata);
  }
}

// Sig buffer should be 64 bytes, allocated by caller
static int validateAndSignData(long long height, unsigned round, unsigned step,
    const unsigned char *data, unsigned dataLen, unsigned char *sigBuffer) {

  // Logic here is taken from Tendermint's PrivValidatorFS.signBytesHRS()

  if (lastHeight > height) {
    return ERR_HEIGHT_REGRESSION;
  }

  if (lastHeight == height) {
    if (lastRound > round) {
      return ERR_ROUND_REGRESSION;
    }

    if (lastRound == round) {
      if (lastStep > step) {
        return ERR_STEP_REGRESSION;
      }

      if (lastStep == step) {
        if (lastSignedBytes != NULL && dataLen == lastSignedBytesLen
            && memcmp(data, lastSignedBytes, dataLen)) {
          // We are being asked to sign the same thing again
          memcpy(sigBuffer, lastSignature, SIGNATURE_SIZE);
          return 0;
        }

        // Different data at the same step = regression
        return ERR_STEP_REGRESSION;
      }
    }
  }


  ed25519_sign(sigBuffer, data, dataLen, public_key, private_key);
  if (lastSignedBytes != NULL) {
    free(lastSignedBytes);
  }

  lastSignedBytesLen = dataLen;
  lastSignedBytes = malloc(lastSignedBytesLen);
  if (lastSignedBytes == NULL) {
    return -1; // out of memory
  }

  memcpy(lastSignedBytes, data, dataLen);
  memcpy(lastSignature, sigBuffer, SIGNATURE_SIZE);
  lastHeight = height;
  lastRound = round;
  lastStep = step;
  return 0;
}
