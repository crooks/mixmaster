/* Modified for Mixmaster.
 * $Id: bsafeeay.h,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 */

/* Copyright (c) 1997
 *  BSAFE International
 *  All Rights Reserved.
 *  Read the accompanying COPYRIGHT file for the full copyright and license.
 *
 * bsafeeay.h
 *
 * BSAFEeay is a free, public domain implementation of RSA Data
 * Security's BSAFE API, using the SSLeay crypto library.
 * BSAFEeay was developed based on the BSAFE API spec as found
 * in public domain code such as SETREF.
 * 
 * NOTE: If you want to legally use BSAFEeay in the US, you must
 * license RSA from RSA Data Security, Inc. BSAFEeay is NOT a
 * product of RSA Data Security and conveys no license for the
 * algorithms within.
 * 
 * BSAFEeay requires the SSLeay crypto library, visit
 *         http://www.psy.uq.oz.au/~ftp/Crypto/
 * for details on SSLeay, where to get it, etc.
 * 
 * BSAFEeay is meant for developers and people who like to get
 * their hands dirty in code. It is NOT an end-user product and
 * the authors will ignore any questions not directly related
 * to BSAFEeay.
 * 
 * The authors can be reached at bsafeeay@cypherpunks.to
 * Visit the https://www.cypherpunks.to/ web site for updates
 * and other information.
 * 
 * The authors' public key is:
 *
 * -----BEGIN PGP PUBLIC KEY BLOCK-----
 * Version: PGP 5.0i
 * 
 * mQCNAzRmehMAAAEEAKgPlIibft+x0Vm7uF0IJ3YPl2XZLOHJJ3nN+XivjCV7rvCX
 * 8mZcOEznBSYj7LCr3kTZ645ZSjCyc8k8DFMYScClQKqeA3aRuXJBeFW7JTJ+rQpj
 * CsxREXWnl41Pkd9uNiVHw/qBm6c0+werrnMf3c4R+PVRMpY7V5M0Bmsl+tm9AAUR
 * tC1CU0FGRSBJbnRlcm5hdGlvbmFsIDxic2FmZWVheUBjeXBoZXJwdW5rcy50bz6J
 * AJUDBRA0a0b0kzQGayX62b0BAYBEA/0XNI7jbNTgU4TV1xYPnkB/6xUC+mgV2eAk
 * 9JOkVOoOobwqoypPR+k5AOkmPKj/GLpv/30YD34pYgXgzGa3p3wLfdMrj0itoEjQ
 * IwV71+bxErcr8zv4wKem2tSltSfVPgnaqXIfKk+cI3gnfu88R50wrQmegLNYjvho
 * VinPqkxTIA==
 * =su8Q
 * -----END PGP PUBLIC KEY BLOCK-----
 * 
 * (this is a 2.6.x compatible key)
 */

#ifndef _BSAFEEAY_H_
#define _BSAFEEAY_H_
#define _AGLOBAL_H_

#ifndef CALL_CONV
#define CALL_CONV
#endif
#ifndef PROTOTYPES
#define PROTOTYPES
#endif
#ifndef GLOBAL_FUNCTION_POINTERS
#define GLOBAL_FUNCTION_POINTERS
#endif

typedef unsigned char *POINTER;
typedef unsigned short UINT2;
typedef unsigned int UINT4;

#ifndef NULL_PTR
#define NULL_PTR ((POINTER) 0)
#endif
#ifndef PROTO_LIST
#define PROTO_LIST(args) args
#endif


/* ALGORITHM INFO TYPES
 *
 * (these are _not_ the same physical numbers as the ones in BSAFE,
 *  in fact BSAFE may not use numbers at all but rather some sort of
 *  function pointer scheme)
 */
#define AI_BSSecretSharing             1
#define AI_CBC_IV8                     2
#define AI_DES_CBC_IV8                 3
#define AI_DES_CBCPadBER               4
#define AI_DES_CBCPadPEM               5
#define AI_DES_EDE3_CBC_IV8            6
#define AI_DES_EDE3_CBCPadIV8          7
#define AI_DES_EDE3_CBCPadBER          8
#define AI_DES_CBCPadIV8               9
#define AI_DESX_CBC_IV8               10
#define AI_DESX_CBCPadIV8             11
#define AI_DESX_CBCPadBER             12
#define AI_DHKeyAgree                 13
#define AI_DHKeyAgreeBER              14
#define AI_DHParamGen                 15
#define AI_DSA                        16
#define AI_DSAKeyGen                  17
#define AI_DSAParamGen                18
#define AI_DSAWithSHA1                19
#define AI_DSAWithSHA1_BER            20
#define AI_MD2                        21
#define AI_MD2Random                  22
#define AI_MD2WithDES_CBCPad          23
#define AI_MD2WithDES_CBCPadBER       24
#define AI_MD2WithRC2_CBCPad          25
#define AI_MD2WithRC2_CBCPadBER       26
#define AI_MD2WithRSAEncryption       27
#define AI_MD2WithRSAEncryptionBER    28
#define AI_MD2_BER                    29
#define AI_MD2_PEM                    30
#define AI_MD5                        31
#define AI_MD5Random                  32
#define AI_MD5WithDES_CBCPad          33
#define AI_MD5WithDES_CBCPadBER       34
#define AI_MD5WithRC2_CBCPad          35
#define AI_MD5WithRC2_CBCPadBER       36
#define AI_MD5WithRSAEncryption       37
#define AI_MD5WithRSAEncryptionBER    38
#define AI_MD5WithXOR                 39
#define AI_MD5WithXOR_BER             40
#define AI_MD5_BER                    41
#define AI_MD5_PEM                    42
#define AI_PKCS_RSAPrivate            43
#define AI_PKCS_RSAPrivateBER         44
#define AI_PKCS_RSAPrivatePEM         45
#define AI_PKCS_RSAPublic             46
#define AI_PKCS_RSAPublicBER          47
#define AI_PKCS_RSAPublicPEM          48
#define AI_RC2_CBC                    49
#define AI_RC2_CBCPad                 50
#define AI_RC2_CBCPadBER              51
#define AI_RC2_CBCPadPEM              52
#define AI_RC4                        53
#define AI_RC4WithMAC                 54
#define AI_RC4WithMAC_BER             55
#define AI_RC4_BER                    56
#define AI_RC5_CBC                    57
#define AI_RC5_CBCPad                 58
#define AI_RFC1113Recode              59
#define AI_RSAKeyGen                  60
#define AI_RSAPrivate                 61
#define AI_RSAPublic                  62
#define AI_SHA1                       63
#define AI_SHA1_BER                   64
#define AI_SHA1WithDES_CBCPad         65
#define AI_SHA1WithDES_CBCPadBER      66
#define AI_SHA1WithRSAEncryption      67
#define AI_SHA1WithRSAEncryptionBER   68 


/* KEY TYPES 
 *
 * (these are _not_ the same physical numbers as the ones in BSAFE,
 *  in fact BSAFE may not use numbers at all but rather some sort of
 *  function pointer scheme)
 */
#define KI_8Byte                 1
#define KI_24Byte                2
#define KI_DES8                  3
#define KI_DES8Strong            4
#define KI_DES24Strong           5
#define KI_DESX                  6
#define KI_DSAPrivate            7
#define KI_DSAPrivateBER         8
#define KI_DSAPublic             9
#define KI_DSAPublicBER         10
#define KI_Item                 11
#define KI_PKCS_RSAPrivate      12
#define KI_PKCS_RSAPrivateBER   13
#define KI_RSAPrivate           14
#define KI_RSAPublic            15
#define KI_RSAPublicBER         16
#define KI_RSA_CRT              17


/* ERROR CODES (these _are_ BSAFE error codes)
 */
#define BE_ALGORITHM_ALREADY_SET 0x0200
#define BE_ALGORITHM_INFO 0x0201
#define BE_ALGORITHM_NOT_INITIALIZED 0x0202
#define BE_ALGORITHM_NOT_SET 0x0203
#define BE_ALGORITHM_OBJ 0x0204
#define BE_ALG_OPERATION_UNKNOWN 0x0205
#define BE_ALLOC 0x0206
#define BE_CANCEL 0x0207
#define BE_DATA 0x0208
#define BE_EXPONENT_EVEN 0x0209
#define BE_EXPONENT_LEN 0x020a
#define BE_HARDWARE 0x020b
#define BE_INPUT_DATA 0x020c
#define BE_INPUT_LEN 0x020d
#define BE_KEY_ALREADY_SET 0x020e
#define BE_KEY_INFO 0x020f
#define BE_KEY_LEN 0x0210
#define BE_KEY_NOT_SET 0x0211
#define BE_KEY_OBJ 0x0212
#define BE_KEY_OPERATION_UNKNOWN 0x0213
#define BE_MEMORY_OBJ 0x0214
#define BE_MODULUS_LEN 0x0215
#define BE_NOT_INITIALIZED 0x0216
#define BE_NOT_SUPPORTED 0x0217
#define BE_OUTPUT_LEN 0x0218
#define BE_OVER_32K 0x0219
#define BE_RANDOM_NOT_INITIALIZED 0x021a
#define BE_RANDOM_OBJ 0x021b
#define BE_SIGNATURE 0x021c
#define BE_WRONG_ALGORITHM_INFO 0x021d
#define BE_WRONG_KEY_INFO 0x021e
#define BE_INPUT_COUNT 0x021f
#define BE_OUTPUT_COUNT 0x0220
#define BE_METHOD_NOT_IN_CHOOSER 0x221
#define BE_KEY_WEAK 0x222



typedef struct {
  unsigned char *data;
  unsigned int len;
} ITEM;

typedef struct {
  ITEM modulus;
  ITEM exponent;
} A_RSA_KEY;

typedef struct {
  ITEM modulus;
  ITEM publicExponent;
  ITEM privateExponent;
  ITEM prime[2];
  ITEM primeExponent[2];
  ITEM coefficient;
} A_PKCS_RSA_PRIVATE_KEY;

typedef struct {
  ITEM prime;
  ITEM base;
  unsigned int exponentBits;
} A_DH_KEY_AGREE_PARAMS;

typedef struct {
    ITEM publicExponent;
    unsigned int modulusBits;
} A_RSA_KEY_GEN_PARAMS;

typedef struct _BS_KEY BS_KEY;
typedef struct _BS_ALG BS_ALG;
typedef BS_ALG *B_ALGORITHM_OBJ;
typedef BS_KEY *B_KEY_OBJ;
typedef void A_SURRENDER_CTX;
typedef int B_INFO_TYPE;

struct _BS_KEY {
  int type;
  unsigned char *data;
};

struct _BS_ALG {
  int type;
  unsigned char *alg;
  unsigned char *key;
  unsigned char *state;
  unsigned char *info;
  int key_size;
  int state_size;
  int info_size;
};


typedef struct {
  unsigned char *salt;
  unsigned int iterationCount;
} B_PBE_PARAMS;

typedef int B_ALGORITHM_METHOD;

extern B_ALGORITHM_METHOD AM_DESX_CBC_DECRYPT;
extern B_ALGORITHM_METHOD AM_DESX_CBC_ENCRYPT;
extern B_ALGORITHM_METHOD AM_DES_CBC_DECRYPT;
extern B_ALGORITHM_METHOD AM_DES_CBC_ENCRYPT;
extern B_ALGORITHM_METHOD AM_DES_EDE3_CBC_DECRYPT;
extern B_ALGORITHM_METHOD AM_DES_EDE3_CBC_ENCRYPT;
extern B_ALGORITHM_METHOD AM_DH_KEY_AGREE;
extern B_ALGORITHM_METHOD AM_DH_PARAM_GEN;
extern B_ALGORITHM_METHOD AM_DSA_KEY_GEN;
extern B_ALGORITHM_METHOD AM_DSA_PARAM_GEN;
extern B_ALGORITHM_METHOD AM_DSA_SIGN;
extern B_ALGORITHM_METHOD AM_DSA_VERIFY;
extern B_ALGORITHM_METHOD AM_MAC;
extern B_ALGORITHM_METHOD AM_MD;
extern B_ALGORITHM_METHOD AM_MD2;
extern B_ALGORITHM_METHOD AM_MD2_RANDOM;
extern B_ALGORITHM_METHOD AM_MD5;
extern B_ALGORITHM_METHOD AM_MD5_RANDOM;
extern B_ALGORITHM_METHOD AM_RC2_CBC_DECRYPT;
extern B_ALGORITHM_METHOD AM_RC2_CBC_ENCRYPT;
extern B_ALGORITHM_METHOD AM_RC4_DECRYPT;
extern B_ALGORITHM_METHOD AM_RC4_ENCRYPT;
extern B_ALGORITHM_METHOD AM_RC4_WITH_MAC_DECRYPT;
extern B_ALGORITHM_METHOD AM_RC4_WITH_MAC_ENCRYPT ;
extern B_ALGORITHM_METHOD AM_RC5_CBC_DECRYPT;
extern B_ALGORITHM_METHOD AM_RC5_CBC_ENCRYPT;
extern B_ALGORITHM_METHOD AM_RSA_CRT_DECRYPT;
extern B_ALGORITHM_METHOD AM_RSA_CRT_ENCRYPT;
extern B_ALGORITHM_METHOD AM_RSA_DECRYPT;
extern B_ALGORITHM_METHOD AM_RSA_ENCRYPT;
extern B_ALGORITHM_METHOD AM_RSA_KEY_GEN;
extern B_ALGORITHM_METHOD AM_SHA;


/* FUNCTIONS */

/*   B_CreateAlgorithmObject   */

int
B_CreateAlgorithmObject (
  B_ALGORITHM_OBJ *alg
);


/*   B_CreateKeyObject   */

int
B_CreateKeyObject (
  B_KEY_OBJ *key
);


/*   B_DecodeDigestInfo   */

int
B_DecodeDigestInfo (
  ITEM *id,
  ITEM *dig,
  char *bug,
  unsigned int len
);


/*   B_DecryptFinal   */

int
B_DecryptFinal (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int rest,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_DecryptInit   */

int
B_DecryptInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_DecryptUpdate   */

int
B_DecryptUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int outsize,
  POINTER in,
  unsigned int inlen,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_DestroyAlgorithmObject   */

int
B_DestroyAlgorithmObject (
  B_ALGORITHM_OBJ *alg
);


/*   B_DestroyKeyObject   */

int
B_DestroyKeyObject (
  B_KEY_OBJ *key
);


/*   B_DigestFinal   */

int
B_DigestFinal (
  B_ALGORITHM_OBJ alg,
  POINTER digest,
  unsigned int *digestlen,
  unsigned int digestsize,
  A_SURRENDER_CTX *ctx
);


/*   B_DigestInit   */

int
B_DigestInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_DigestUpdate   */

int
B_DigestUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER in,
  unsigned int inlen,
  A_SURRENDER_CTX *ctx
);


/*   B_EncryptFinal   */

int
B_EncryptFinal (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int rest,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_EncryptInit   */

int
B_EncryptInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_EncryptUpdate   */

int
B_EncryptUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int outsize,
  POINTER in,
  unsigned int inlen,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_GenerateInit   */

int
B_GenerateInit (
  B_ALGORITHM_OBJ alg,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_GenerateKeypair   */

int
B_GenerateKeypair (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ publickey,
  B_KEY_OBJ privatekey,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);

/*   B_GenerateRandomBytes   */

int
B_GenerateRandomBytes (
  B_ALGORITHM_OBJ alg,
  POINTER data,
  unsigned int datalen,
  A_SURRENDER_CTX *ctx
);


/*   B_GetAlgorithmInfo   */

int
B_GetAlgorithmInfo (
  POINTER *to,
  B_ALGORITHM_OBJ alg,
  B_INFO_TYPE alginfo
);


/*    B_GetKeyInfo   */

int
B_GetKeyInfo (
  POINTER *to,
  B_KEY_OBJ key,
  B_INFO_TYPE keyinfo
);


/*   B_IntegerBits   */

int
B_IntegerBits (
  unsigned char *data,
  int len
);


/*   B_KeyAgreeInit   */

int
B_KeyAgreeInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);

/*   B_KeyAgreePhase1   */

int
B_KeyAgreePhase1 (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int outzize,
  B_ALGORITHM_OBJ rand,
  A_SURRENDER_CTX *ctx
);


/*   B_KeyAgreePhase2   */

int
B_KeyAgreePhase2 (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int outzize,
  POINTER in,
  unsigned int inlen,
  A_SURRENDER_CTX *ctx
);


/*   B_RandomInit   */

int
B_RandomInit (
  B_ALGORITHM_OBJ alg,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_RandomUpdate   */

int
B_RandomUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER seed,
  unsigned int seedlen,
  A_SURRENDER_CTX *ctx
);


/*   B_SetAlgorithmInfo   */

int
B_SetAlgorithmInfo (
  B_ALGORITHM_OBJ alg,
  B_INFO_TYPE alginfo,
  POINTER params
);


/*   B_SetKeyInfo   */

int
B_SetKeyInfo (
  B_KEY_OBJ key,
  B_INFO_TYPE keyinfo,
  POINTER from
);


/*   B_SignFinal   */

int
B_SignFinal (
  B_ALGORITHM_OBJ alg,
  POINTER out,
  unsigned int *outlen,
  unsigned int outsize,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_SignInit   */

int
B_SignInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_SignUpdate   */

int
B_SignUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER in,
  unsigned int inlen,
  A_SURRENDER_CTX *ctx
);


/*   B_VerifyFinal   */

int
B_VerifyFinal (
  B_ALGORITHM_OBJ alg,
  POINTER sig,
  unsigned int siglen,
  B_ALGORITHM_OBJ randomalg,
  A_SURRENDER_CTX *ctx
);


/*   B_VerifyInit   */

int
B_VerifyInit (
  B_ALGORITHM_OBJ alg,
  B_KEY_OBJ key,
  B_ALGORITHM_METHOD *chooser[],
  A_SURRENDER_CTX *ctx
);


/*   B_VerifyUpdate   */

int
B_VerifyUpdate (
  B_ALGORITHM_OBJ alg,
  POINTER in,
  unsigned int inlen,
  A_SURRENDER_CTX *ctx
);


#endif /* _BSAFEEAY_H_*/
