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


#ifndef UTILS_H_
#define UTILS_H_

#include <string.h>
#include <nfkm.h>

#define ZERO(thing) memset(&thing, 0, sizeof(thing))

typedef enum SEEJobResponse {
  SEEJobResponse_OK = 0, SEEJobResponse_Error = 1, SEEJobResponse_ProcessingError = 2
} SEEJobResponse;

extern NFastApp_Connection conn;
extern NFast_AppHandle appHandle;
extern NFKM_WorldInfo *worldInfo;

/* Convenience macro.  Assumes a single label `cleanup' for handling errors,
   an M_Status rc local variable and file description `fd' */
#define CLEAN_ON_FAIL(CMD, COMMENT) {\
    rc = CMD;\
    if (rc != Status_OK) {\
      sendNfastErrorResponse(fd, COMMENT, rc);\
      goto cleanup;\
    }\
  }

extern M_Status transactx(M_Command *cmd, M_Reply *reply, int needsSEECert,
			  int freeCommand);

extern int writeSocket(int fd, const unsigned char *data, int dataLen);
extern int readSocket(int fd, char **output, int *outputLen);

extern M_Status findKey(const char *appname, const char *ident, NFKM_Key **key);

extern M_Status loadKey(const char *appname, const char *ident, int needsSEECert, M_KeyID *keyID);

extern M_Status aesCBCEncrypt(M_KeyID aesKey, unsigned char *data, unsigned len,
    unsigned char **output, unsigned *outputLen);

extern M_Status aesCBCDecrypt(M_KeyID aesKey, unsigned char *ciphertext, unsigned len,
    unsigned char **output, unsigned *outputLen);

extern M_Status initAppHandle(void);

extern M_Status initConnection(void);

extern void sendErrorResponse(int fd, const char *msg);

extern void sendNfastErrorResponse(int fd, const char *comment,
				   M_Status errorStatus);

extern void sendResultToHostside(int fd, M_ByteBlock result);

extern void sendErrorCodeAndResponse(int fd, const char *msg, M_Status rc);

extern void sendErrorCodeAndNfastErrorResponse(int fd, const char *comment,
					       M_Status nFastErrorStatus, M_Status rc);

// note: frees reply on error
extern M_Status transact(M_Command *cmd, M_Reply *reply);

extern void freeReply(M_Reply *reply);

extern M_Status destroyObject(M_KeyID *object);


extern M_Status safeMalloc(unsigned char **ptr, size_t len);

extern int toHexString(const unsigned char *data, int len, char **output);

extern int allocSprintF(char **output, const char *fmt, ...);

#endif /* UTILS_H_ */
