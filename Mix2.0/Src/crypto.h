/* $Id: crypto.h,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 *
 * crypto.h            1996-10-25 um
 *
 *      (c) Copyright 1996 by Ulf Moeller. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 *
 */

#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef USE_RSAREF
/* definitions for RSAREF */

typedef unsigned char *POINTER;
typedef unsigned short int UINT2;
typedef unsigned long int UINT4;

#ifndef PROTO_LIST
#define PROTO_LIST(args) args
#endif

#include "rsaref.h"
#include "r_random.h"

#define DH_PARAMS R_DH_PARAMS
#define PUBLIC_KEY R_RSA_PUBLIC_KEY
#define PRIVATE_KEY R_RSA_PRIVATE_KEY
#define RANDOM R_RANDOM_STRUCT

#else
/* definitions for BSAFE / BSAFEeay */

#include "aglobal.h"
#include "bsafe.h"

extern B_ALGORITHM_METHOD *CHOOSER[];

#define DH_PARAMS void /* not implemented */
#define PUBLIC_KEY B_KEY_OBJ
#define PRIVATE_KEY B_KEY_OBJ
#define RANDOM B_ALGORITHM_OBJ

#define MAX_ENCRYPTED_KEY_LEN 128 /* 1024 bit keys */
#define MAX_RSA_MODULUS_LEN 128
#define MAX_RSA_PRIME_LEN 64

#endif
#endif /* CRYPTO_H */
