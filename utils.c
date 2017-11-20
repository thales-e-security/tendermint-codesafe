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


#include <sys/types.h>
#include <sys/socket.h>

#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <nfkm.h>
#include <simplebignum.h>

#include "utils.h"

NFastApp_Connection conn = NULL;
NFast_AppHandle appHandle = NULL;
NFKM_WorldInfo *worldInfo = NULL;

#define LENGTH_BYTES 4
#define BLOCKSIZE 8192        // Size of data block for each socket read/write

#ifndef RUNNING_ON_HOST
static M_Status getSEESigningHash(M_KeyHashAndMech *hashAndMech);
static M_Status populateSEECertificate(M_Certificate *cert);
#endif

// Note: returned string must be freed by caller. -1 return is error, 0 is ok.
extern int toHexString(const unsigned char *data, int len, char **output) {
  char *ptr;
  int i;

  *output = calloc(2 * len + 1, 1);
  if (*output == NULL) {
    return -1;
  }

  ptr = *output;

  for (i = 0; i < len; i++) {
    ptr += sprintf(ptr, "%02X", data[i]);
  }

  return 0;
}

extern int writeSocket(int fd, const unsigned char *data, int dataLen) {
  int numWritten = 0, res, totalLength;
  char *totalData = NULL;
  unsigned i;

  printf("About to send %i bytes.\n", dataLen);
  totalLength = dataLen + LENGTH_BYTES;
  totalData = malloc(totalLength);
  memcpy(totalData + LENGTH_BYTES, data, dataLen);

  for (i = 0; i < LENGTH_BYTES; i++) {
    totalData[i] = (totalLength >> (i * 8)) & 0xFF;
  }

  while (1) {
    res = send(fd, totalData + numWritten, totalLength - numWritten, 0);

    if (res == -1) {
      perror("send");
      free(totalData);
      return res;
    } else {
      // we've written something
      numWritten += res;

      if (numWritten == totalLength) {
        //done!
        break;
      }
    }
  }

  printf("Write complete.\n");

  free(totalData);
  return 0;
}

extern int readSocket(int fd, char **output, int *outputLen) {

  char buffer[BLOCKSIZE], lengthData[LENGTH_BYTES];
  int newBytesRead, dataLen = -1, currentTotal = 0, outputIndex = 0,
      additionalLengthData;
  unsigned i;

  ZERO(lengthData);

  while (1) {
    newBytesRead = recv(fd, buffer, sizeof(buffer), 0);
    if (newBytesRead == -1) {
      return newBytesRead;
    }
    if (dataLen == -1) {
      // We haven't yet read the data length

      if (currentTotal + newBytesRead > LENGTH_BYTES) {
        // We have enough bytes to read the length
        additionalLengthData = LENGTH_BYTES - currentTotal;
      } else {
        additionalLengthData = newBytesRead;
      }

      for (i = 0; i < additionalLengthData; i++) {
        //To deal with the unlikely case that the first read is insufficiently long to
        //read the total data length from. Keep interim results in lengthData.
        lengthData[i + currentTotal] = buffer[i];
      }

      currentTotal += newBytesRead;
      if (currentTotal < LENGTH_BYTES) {
        continue; //Still not enough data to find the total length, so read more
      }

      // If we are here, we have enough bytes to read the length. We will only
      // pass through this code once
      dataLen = 0;
      for (i = 0; i < LENGTH_BYTES; i++) {
        dataLen |= (lengthData[i] & 0xFF) << (i * 8);
      }

      *outputLen = dataLen;
      printf("Target length is %i bytes.\n", dataLen);

      *output = malloc(*outputLen);
      if (*output == NULL) {
        *outputLen = 0;
        fprintf(stderr, "FAILED TO MALLOC FOR SOCKET READ\n");
        return -1;
      }

      // Copy the parts of the input which are not length characters
      // into the output buffer
      memcpy(*output, buffer + additionalLengthData,
          currentTotal - LENGTH_BYTES);
      outputIndex = currentTotal - LENGTH_BYTES;

      // Check if we are finished with one read
      if (outputIndex == dataLen) {
        break;
      }

      continue;
    }

    /* Only get here if we have already read the total data length */
    if (newBytesRead == 0) {
      // socket closed gracefully
      break;
    } else {
      // We read some data.
      memcpy(*output + outputIndex, buffer, newBytesRead);
      outputIndex += newBytesRead;

      if ((outputIndex + LENGTH_BYTES) == dataLen) {
        break;
      }
    }
  }

  printf("Read %i bytes from stream.\n", outputIndex + LENGTH_BYTES);
  return 0;
}

extern M_Status findKey(const char *appname, const char *ident, NFKM_Key **key) {
  M_Status rc;
  NFKM_KeyIdent keyIdent;

  ZERO(keyIdent);
  keyIdent.appname = malloc(strlen(appname) + 1);
  strcpy(keyIdent.appname, appname);

  keyIdent.ident = malloc(strlen(ident) + 1);
  strcpy(keyIdent.ident, ident);

  rc = NFKM_findkey(appHandle, keyIdent, key, NULL);

  if (rc == Status_OK) {
    if (*key == NULL) {
      rc = Status_UnknownKey;
    }
  }

  free(keyIdent.appname);
  free(keyIdent.ident);

  return rc;
}

#ifndef RUNNING_ON_HOST
static M_Status getSEESigningHash(M_KeyHashAndMech *hashAndMech) {
  M_Command cmd;
  M_Reply rep;
  M_Status rc;

  ZERO(cmd);
  ZERO(rep);
  ZERO(*hashAndMech);

  cmd.cmd = Cmd_GetWorldSigners;
  rc = transact(&cmd, &rep);
  if (rc != Status_OK) {
    return rc;
  }

  if (rep.reply.getworldsigners.n_sigs != 1) {
    freeReply(&rep);
    return Status_InvalidCertificate;
  }

  hashAndMech->mech = rep.reply.getworldsigners.sigs[0].mech;
  memcpy(&hashAndMech->hash, &rep.reply.getworldsigners.sigs[0].hash,
      sizeof hashAndMech->hash);
  freeReply(&rep);
  return rc;
}

static M_Status populateSEECertificate(M_Certificate *cert) {
  M_Status rc;
  M_KeyHashAndMech seeSig;

  ZERO(*cert);

  rc = getSEESigningHash(&seeSig);
  if (rc != Status_OK) {
    return rc;
  }

  cert->type = CertType_SEECert;
  memcpy(cert->keyhash.bytes, seeSig.hash.bytes, sizeof(cert->keyhash.bytes));
  return Status_OK;
}
#endif

extern M_Status initAppHandle(void) {
  NFastAppInitArgs initArgs;
  M_Status rc;

  if (appHandle == NULL) {
    ZERO(initArgs);
    initArgs.bignumupcalls = &sbn_upcalls;
    initArgs.flags = NFAPP_IF_BIGNUM;

    rc = NFastApp_InitEx(&appHandle, &initArgs, NULL);
    if (rc != Status_OK) {
      return rc;
    }

    return NFKM_getinfo(appHandle, &worldInfo, NULL);
  } else {
    return Status_OK;
  }
}

extern M_Status initConnection(void) {
  M_Status rc;

  rc = initAppHandle();
  if (rc != Status_OK) {
    return rc;
  }

  return NFastApp_Connect(appHandle, &conn, 0, NULL);
}

extern void sendErrorResponse(int fd, const char *msg) {
  NF_Marshal_Context ctx;
  M_ByteBlock errorMsg;
  SEEJobResponse responseValue = SEEJobResponse_Error;
  int size;
  unsigned char *ptr;

  printf("Sending error response: \"%s\"\n", msg);

  errorMsg.len = strlen(msg) + 1;
  errorMsg.ptr = malloc(errorMsg.len);
  // essentially a strcpy, but without complaints about signedness
  memcpy(errorMsg.ptr, (unsigned char *) msg, strlen(msg) + 1);

  ctx.op = NULL;
  ctx.remain = INT_MAX;

  NF_Marshal_Word(&ctx, &responseValue);
  NF_Marshal_ByteBlock(&ctx, &errorMsg);

  size = INT_MAX - ctx.remain;
  ctx.op = malloc(size);
  ctx.remain = size;
  ptr = ctx.op;

  NF_Marshal_Word(&ctx, &responseValue);
  NF_Marshal_ByteBlock(&ctx, &errorMsg);

  // don't bother to check return value, not
  // much point reporting an error about error reporting
  writeSocket(fd, ptr, size);
  free(ptr);
  free(errorMsg.ptr);
}

extern void sendNfastErrorResponse(int fd, const char *comment,
    M_Status errorStatus) {
  char localBuffer[256], *totalMsg;
  const char *suffix = ": ";
  ZERO(localBuffer);

  NFast_StrError(localBuffer, 256, errorStatus, 0);

  totalMsg = calloc(strlen(comment) + strlen(suffix) + strlen(localBuffer) + 1,
      sizeof(char));
  strcat(totalMsg, comment);
  strcat(totalMsg, suffix);
  strcat(totalMsg, localBuffer);

  sendErrorResponse(fd, totalMsg);
  free(totalMsg);
}

extern void sendResultToHostside(int fd, M_ByteBlock result) {
  NF_Marshal_Context ctx;
  M_Word resultCode = SEEJobResponse_OK;
  int bufferSize, res;
  void *ptr;

  ctx.op = NULL;
  ctx.remain = INT_MAX;

  NF_Marshal_Word(&ctx, &resultCode);
  NF_Marshal_ByteBlock(&ctx, &result);

  bufferSize = INT_MAX - ctx.remain;
  ctx.remain = bufferSize;
  ctx.op = malloc(bufferSize);
  ptr = ctx.op;

  NF_Marshal_Word(&ctx, &resultCode);
  NF_Marshal_ByteBlock(&ctx, &result);

  res = writeSocket(fd, ptr, bufferSize);

  if (res == -1) {
    fprintf(stderr, "Socket write failed.\n");
  }

  free(ptr);
}

extern M_Status destroyObject(M_KeyID *object) {
  M_Command cmd;
  M_Reply rep;
  M_Status rc;

  if (!object || *object == 0) {
    return Status_OK;
  }

  ZERO(cmd);
  ZERO(rep);

  cmd.cmd = Cmd_Destroy;
  cmd.args.destroy.key = *object;

  if ((rc = transact(&cmd, &rep)) == Status_OK) {
    *object = 0;
  } else {
    fprintf(stderr, "WARNING: Key destruction failed.\n");
  }
  return rc;
}

extern M_Status safeMalloc(unsigned char **ptr, size_t len) {
  *ptr = malloc(len);
  if (*ptr == NULL) {
    return Status_NoModuleMemory;
  } else {
    return Status_OK;
  }
}

/*
 * Sends error code and message host.
 */
extern void sendErrorCodeAndResponse(int fd, const char *msg, M_Status rc) {
  NF_Marshal_Context ctx;
  M_ByteBlock errorMsg;
  SEEJobResponse responseValue = SEEJobResponse_ProcessingError;
  int size;
  unsigned char *ptr;

  printf("Sending error response: \"%s\" rc = %x\n", msg, rc);

  errorMsg.len = strlen(msg) + 1;
  errorMsg.ptr = malloc(errorMsg.len);
  memcpy(errorMsg.ptr, (unsigned char *) msg, strlen(msg) + 1);

  ctx.op = NULL;
  ctx.remain = INT_MAX;

  NF_Marshal_Word(&ctx, &responseValue);
  NF_Marshal_ByteBlock(&ctx, &errorMsg);
  NF_Marshal_Word(&ctx, &rc);

  size = INT_MAX - ctx.remain;
  ctx.op = malloc(size);
  ctx.remain = size;
  ptr = ctx.op;

  NF_Marshal_Word(&ctx, &responseValue);
  NF_Marshal_ByteBlock(&ctx, &errorMsg);
  NF_Marshal_Word(&ctx, &rc);

  // don't bother to check return value, not
  // much point reporting an error about error reporting
  writeSocket(fd, ptr, size);
  free(ptr);
  free(errorMsg.ptr);
}

/*
 * Sends an error code and nFast error message to the host
 */
extern void sendErrorCodeAndNfastErrorResponse(int fd, const char *comment,
    M_Status nFastErrorStatus, M_Status rc) {
  char localBuffer[256], *totalMsg;
  const char *suffix = ": ";
  ZERO(localBuffer);

  NFast_StrError(localBuffer, 256, nFastErrorStatus, 0);

  totalMsg = calloc(strlen(comment) + strlen(suffix) + strlen(localBuffer) + 1,
      sizeof(char));
  strcat(totalMsg, comment);
  strcat(totalMsg, suffix);
  strcat(totalMsg, localBuffer);

  sendErrorCodeAndResponse(fd, totalMsg, rc);
  free(totalMsg);
}

extern void freeReply(M_Reply *reply) {
  NFastApp_Free_Reply(appHandle, NULL, NULL, reply);
  ZERO(*reply);
}

// note: frees reply on error
extern M_Status transact(M_Command *cmd, M_Reply *reply) {
  return transactx(cmd, reply, 0, 0);
}

extern M_Status transactx(M_Command *cmd, M_Reply *reply, int needsSEECert,
    int freeCommand) {
  M_Status rc;
  M_CertificateList *certList = NULL;
  NF_Free_Context ftx;

#ifndef RUNNING_ON_HOST
  if (needsSEECert) {
    certList = calloc(1, sizeof(M_CertificateList));
    if (certList == NULL) {
      rc = Status_NoModuleMemory;
      goto cleanup;
    }

    certList->certs = malloc(sizeof(M_Certificate));
    if (certList->certs == NULL) {
      rc = Status_NoModuleMemory;
      goto cleanup;
    }
    certList->n_certs = 1;

    rc = populateSEECertificate(certList->certs);
    if (rc != Status_OK) {
      goto cleanup;
    }

    cmd->certs = certList;
    cmd->flags |= Command_flags_certs_present;
  }
#endif

  rc = NFastApp_Transact(conn, NULL, cmd, reply, NULL);

  if (freeCommand) {
    NFastApp_Free_Command(appHandle, NULL, NULL, cmd);
    certList = NULL; // ensure this isn't freed twice
  }

  if (rc != Status_OK) {
    fprintf(stderr, "Transact failed: %s\n",
        NF_Lookup(rc, NF_Status_enumtable));
    freeReply(reply);
    goto cleanup;
  }

  rc = reply->status;
  if (rc != Status_OK) {
    fprintf(stderr, "Command failed: %s\n", NF_Lookup(rc, NF_Status_enumtable));
    freeReply(reply);
    goto cleanup;
  }

  cleanup:

  if (certList) {
    ftx.u = NFastApp_AllocUD(appHandle, NULL, NULL, 0);
    NF_Free_CertificateList(&ftx, certList);
    NFastApp_FreeUD(ftx.u);
    free(certList);
  }

  return rc;
}

extern M_Status loadKey(const char *appname, const char *ident,
    int needsSEECert, M_KeyID *keyID) {
  NFKM_Key *key = NULL;
  M_Status rc;
  M_Command cmd;
  M_Reply rep;

  rc = findKey(appname, ident, &key);
  if (rc != Status_OK) {
    goto cleanup;
  }

  ZERO(cmd);
  ZERO(rep);

  cmd.cmd = Cmd_LoadBlob;
  cmd.args.loadblob.blob = key->privblob;

  rc = transactx(&cmd, &rep, needsSEECert, 0);
  if (rc != Status_OK) {
    goto cleanup;
  }

  *keyID = rep.reply.loadblob.idka;

  cleanup:

  NFKM_freekey(appHandle, key, NULL);
  return rc;
}

extern M_Status aesCBCEncrypt(M_KeyID aesKey, unsigned char *data, unsigned len,
    unsigned char **output, unsigned *outputLen) {

  M_Status rc;
  M_Command cmd;
  M_Reply rep;
  M_IV zeroIV;

  ZERO(cmd);
  ZERO(rep);
  ZERO(zeroIV);

  cmd.cmd = Cmd_Encrypt;
  cmd.args.encrypt.flags = Cmd_Encrypt_Args_flags_given_iv_present;
  cmd.args.encrypt.key = aesKey;
  cmd.args.encrypt.mech = Mech_RijndaelmCBCpNONE;
  cmd.args.encrypt.given_iv = &zeroIV;
  cmd.args.encrypt.given_iv->mech = Mech_RijndaelmCBCpNONE;
  cmd.args.encrypt.plain.type = PlainTextType_Bytes;
  cmd.args.encrypt.plain.data.bytes.data.len = len;
  cmd.args.encrypt.plain.data.bytes.data.ptr = data;

  rc = transactx(&cmd, &rep, 1, 0);
  if (rc != Status_OK) {
    goto cleanup;
  }

  *outputLen = rep.reply.encrypt.cipher.data.generic128.cipher.len;
  rc = safeMalloc(output, *outputLen);
  if (rc != Status_OK) {
    goto cleanup;
  }

  memcpy(*output, rep.reply.encrypt.cipher.data.generic128.cipher.ptr,
      *outputLen);

  cleanup:

  freeReply(&rep);
  return rc;
}

extern M_Status aesCBCDecrypt(M_KeyID aesKey, unsigned char *ciphertext,
    unsigned len, unsigned char **output, unsigned *outputLen) {

  M_Status rc;
  M_Command cmd;
  M_Reply rep;

  ZERO(cmd);
  ZERO(rep);

  cmd.cmd = Cmd_Decrypt;
  cmd.args.decrypt.key = aesKey;
  cmd.args.decrypt.mech = Mech_RijndaelmCBCpNONE;
  cmd.args.decrypt.reply_type = PlainTextType_Bytes;
  cmd.args.decrypt.cipher.data.generic128.cipher.len = len;
  cmd.args.decrypt.cipher.data.generic128.cipher.ptr = ciphertext;
  cmd.args.decrypt.cipher.mech = Mech_RijndaelmCBCpNONE;

  rc = transactx(&cmd, &rep, 1, 0);
  if (rc != Status_OK) {
    goto cleanup;
  }

  // This should be ok, leave the caller to free the only allocated memory
  *output = rep.reply.decrypt.plain.data.bytes.data.ptr;
  *outputLen = rep.reply.decrypt.plain.data.bytes.data.len;

  cleanup: return rc;
}

// Essentially an implementation of asprintf. Returns negative on
// error, otherwise returns no. characters written. Caller must free
// *output. *output is NULL on failure.
extern int allocSprintF(char **output, const char *fmt, ...) {
  va_list ap;
  int required;

  *output = NULL;

  va_start(ap, fmt);
  required = vsnprintf(NULL, 0, fmt, ap);
  va_end(ap);

  *output = malloc(required + 1);
  if (*output == NULL) {
    return -1;
  }

  va_start(ap, fmt);
  required = vsnprintf(*output, required + 1, fmt, ap);
  va_end(ap);

  return required;
}
