/* Modified for Mixmaster.
 * $Id: bsafeeay.c,v 1.3 2002/09/10 18:29:40 rabbi Exp $
 */

/* Copyright (c) 1997
 *  BSAFE International
 *  All Rights Reserved.
 *  Read the accompanying COPYRIGHT file for the full copyright and license.
 *
 * bsafeeay.c
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

#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <rsa.h>
#include <des.h>
#include <md5.h>
#include <sha.h>
#include <rand.h>
#include <dh.h>
#include <bsafeeay.h>
#include <assert.h>

#if (SSLEAY_VERSION_NUMBER >= 0x900)
#define NOPADDING
#endif

B_ALGORITHM_METHOD AM_DESX_CBC_DECRYPT;
B_ALGORITHM_METHOD AM_DESX_CBC_ENCRYPT;
B_ALGORITHM_METHOD AM_DES_CBC_DECRYPT;
B_ALGORITHM_METHOD AM_DES_CBC_ENCRYPT;
B_ALGORITHM_METHOD AM_DES_EDE3_CBC_DECRYPT;
B_ALGORITHM_METHOD AM_DES_EDE3_CBC_ENCRYPT;
B_ALGORITHM_METHOD AM_DH_KEY_AGREE;
B_ALGORITHM_METHOD AM_DH_PARAM_GEN;
B_ALGORITHM_METHOD AM_DSA_KEY_GEN;
B_ALGORITHM_METHOD AM_DSA_PARAM_GEN;
B_ALGORITHM_METHOD AM_DSA_SIGN;
B_ALGORITHM_METHOD AM_DSA_VERIFY;
B_ALGORITHM_METHOD AM_MAC;
B_ALGORITHM_METHOD AM_MD;
B_ALGORITHM_METHOD AM_MD2;
B_ALGORITHM_METHOD AM_MD2_RANDOM;
B_ALGORITHM_METHOD AM_MD5;
B_ALGORITHM_METHOD AM_MD5_RANDOM;
B_ALGORITHM_METHOD AM_RC2_CBC_DECRYPT;
B_ALGORITHM_METHOD AM_RC2_CBC_ENCRYPT;
B_ALGORITHM_METHOD AM_RC4_DECRYPT;
B_ALGORITHM_METHOD AM_RC4_ENCRYPT;
B_ALGORITHM_METHOD AM_RC4_WITH_MAC_DECRYPT;
B_ALGORITHM_METHOD AM_RC4_WITH_MAC_ENCRYPT;
B_ALGORITHM_METHOD AM_RC5_CBC_DECRYPT;
B_ALGORITHM_METHOD AM_RC5_CBC_ENCRYPT;
B_ALGORITHM_METHOD AM_RSA_CRT_DECRYPT;
B_ALGORITHM_METHOD AM_RSA_CRT_ENCRYPT;
B_ALGORITHM_METHOD AM_RSA_DECRYPT;
B_ALGORITHM_METHOD AM_RSA_ENCRYPT;
B_ALGORITHM_METHOD AM_RSA_KEY_GEN;
B_ALGORITHM_METHOD AM_SHA;

static FILE *fp = NULL;

#ifdef _BDebug
#define return(x) _BDebug ("  Returning %d\n", (x)); return(x);
#endif

static void
_Init_Debug( void )
{
  char fname[256];

  sprintf( fname, "/tmp/BSAFEeay-%d.log", getpid() );

  fp = fopen( fname, "w" );
}


static void
_BDebug( char *fmt, ... )
{
#ifdef _BDEBUG 
  va_list ap;

  va_start( ap, fmt );

  if( !fp ) _Init_Debug();

  if( fp ) vfprintf( fp, fmt, ap );
  fflush(fp);
#endif
}


int
B_CreateAlgorithmObject( B_ALGORITHM_OBJ *obj )
{
  _BDebug( "In B_CreateAlgorithmObject\n" );

  *obj = (B_ALGORITHM_OBJ)malloc(sizeof(BS_ALG));
  if( *obj == NULL ) {
    return (-1);
  }
  
  memset( (*obj), 0, sizeof(BS_ALG) );
  
  return (0);
}

int
B_DestroyAlgorithmObject( B_ALGORITHM_OBJ *obj )
{
  _BDebug( "In B_DestroyAlgorithmObject\n" );

#if 0
  /* Mmm... leakum
   */
  if( (*obj)->alg ) {
    free( (*obj)->alg );
  }
  if( (*obj)->key ) {
    free( (*obj)->key );
  }
  if( (*obj)->state ) {
    free( (*obj)->state );
  }
#endif

  memset( (*obj), 0, sizeof(BS_ALG) );
  free(*obj);
  *obj = NULL;
  
  return (0);
}

int
B_SetAlgorithmInfo( B_ALGORITHM_OBJ obj, int type, POINTER info )
{
  _BDebug( "In B_SetAlgorithmInfo\n" );

  if( obj == NULL ) {
    return (-1);
  }
  
  obj->type = type;

  switch( type ) {
    
  case AI_DES_CBC_IV8:
  case AI_DES_EDE3_CBC_IV8:
    {
      obj->info = (unsigned char *)malloc(8);
      if( !obj->info ) {
	return (-1);
      }
      
      memcpy( obj->info, (unsigned char *)info, 8 );
      break;
  }

  case AI_DES_CBCPadIV8:
    {
      obj->info = (unsigned char *)malloc(8);
      if( !obj->info ) {
	return (-1);
      }
      
      memcpy( obj->info, (unsigned char *)info, 8 );
      break;
    }

  case AI_DES_CBCPadBER:
    {
      static unsigned char des_cbc_der[] = { 0x30, 0x11, 0x06, 0x05, 0x2b,
					     0x0e, 0x03, 0x02, 0x07, 0x04,
					     0x08 };
      ITEM *item;
      
      item = (ITEM *)info;
      
      if( memcmp( item->data, des_cbc_der, sizeof(des_cbc_der) ) != 0 ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }
      
      obj->info = (unsigned char *)malloc(8);
      if( !obj->info ) {
	return (-1);
      }

      memcpy( obj->info, (unsigned char *)(item->data)+sizeof(des_cbc_der), 8 );
      
      break;
    }

  case AI_MD5WithDES_CBCPad:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;

      params = (B_PBE_PARAMS *)info;
      if( !params || !params->salt ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      o_params = (B_PBE_PARAMS *)malloc(sizeof(B_PBE_PARAMS));
      if( !o_params ) {
	return (-1);
      }

      o_params->salt = (unsigned char *)malloc(8);
      if( !o_params->salt ) {
	return (-1);
      }

      memcpy( o_params->salt, params->salt, 8 );
      o_params->iterationCount = params->iterationCount;

      obj->info = (unsigned char *)o_params;

      break;
    }

  case AI_MD5WithDES_CBCPadBER:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;
      static unsigned char md5des_pbe_der[] = { 0x30, 0x1a, 0x06, 0x09, 0x2a,
						0x86, 0x48, 0x86, 0xf7, 0x0d,
						0x01, 0x05, 0x03, 0x30, 0x0d,
						0x04, 0x08 };
      ITEM *item;
      unsigned char *p;
      int t;
      int i;

      item = (ITEM *)info;
      if( item->len < sizeof(md5des_pbe_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, md5des_pbe_der, sizeof(md5des_pbe_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      p = (item->data)+sizeof(md5des_pbe_der);

      params = (B_PBE_PARAMS *)malloc(sizeof(B_PBE_PARAMS));
      if( !params ) {
	return (-1);
      }

      params->salt = (unsigned char *)malloc(8);
      if( !params->salt ) {
	return (-1);
      }

      memcpy( params->salt, p, 8 );
      p += 8;
      
      if( p[0] != 0x02 ) {   /* hope this is always the case, should be IMO */
	return (-1);
      }

      t = (int)p[1];
      if( t > 4 ) {
	return (-1);
      }

      p++; /* only increment ONCE, so we don't have to subtract in the loop */
      params->iterationCount = 0;

      for( i=1; i <= t; i++ ) {
	params->iterationCount |= (p[i] << (t-i)*8);
      }

      obj->info = (unsigned char *)params;

      break;
    }

  case AI_SHA1WithDES_CBCPad:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;

      params = (B_PBE_PARAMS *)info;
      if( !params || !params->salt ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      o_params = (B_PBE_PARAMS *)malloc(sizeof(B_PBE_PARAMS));
      if( !o_params ) {
	return (-1);
      }

      o_params->salt = (unsigned char *)malloc(8);
      if( !o_params->salt ) {
	return (-1);
      }

      memcpy( o_params->salt, params->salt, 8 );
      o_params->iterationCount = params->iterationCount;

      obj->info = (unsigned char *)o_params;

      break;
    }

  case AI_SHA1WithDES_CBCPadBER:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;
      static unsigned char sha1des_pbe_der[] = { 0x30, 0x1b, 0x06, 0x09, 0x2a,
						 0x86, 0x48, 0x86, 0xf7, 0x0d,
						 0x01, 0x05, 0x0a, 0x30, 0x0e,
						 0x04, 0x08 };
      ITEM *item;
      unsigned char *p;
      int t;
      int i;

      item = (ITEM *)info;
      if( item->len < sizeof(sha1des_pbe_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, sha1des_pbe_der, sizeof(sha1des_pbe_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      p = (item->data)+sizeof(sha1des_pbe_der);

      params = (B_PBE_PARAMS *)malloc(sizeof(B_PBE_PARAMS));
      if( !params ) {
	return (-1);
      }

      params->salt = (unsigned char *)malloc(8);
      if( !params->salt ) {
	return (-1);
      }

      memcpy( params->salt, p, 8 );
      p += 8;
      
      if( p[0] != 0x02 ) {   /* hope this is always the case, should be IMO */
	return (-1);
      }

      t = (int)p[1];
      if( t > 4 ) {
	return (-1);
      }

      p++; /* only increment ONCE, so we don't have to subtract in the loop */
      params->iterationCount = 0;

      for( i=1; i <= t; i++ ) {
	params->iterationCount |= (p[i] << (t-i)*8);
      }

      obj->info = (unsigned char *)params;

      break;
    }

  case AI_SHA1:
    {
      break;
    }

  case AI_SHA1_BER:
    {
      static unsigned char sha1_der[] = { 0x30, 0x09, 0x06, 0x05, 0x2b,
					  0x0e, 0x03, 0x02, 0x1a, 0x05,
					  0x00 };
      ITEM *item;
      
      item = (ITEM *)info;
      if( item->len != sizeof(sha1_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }
      
      if( memcmp( item->data, sha1_der, sizeof(sha1_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }
      
      break;
    }

  case AI_MD5:
    {
      break;
    }
    
  case AI_MD5_BER:
    {
      static unsigned char md5_der[] = { 0x30, 0x0c, 0x06, 0x08, 0x2a,
					 0x86, 0x48, 0x86, 0xf7, 0x0d,
					 0x02, 0x05, 0x05, 0x00 };
      ITEM *item;

      item = (ITEM *)info;
      if( item->len != sizeof(md5_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, md5_der, sizeof(md5_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      break;
    }

  case AI_PKCS_RSAPublic:
    {
      break;
    }

  case AI_PKCS_RSAPublicBER:
    {
      static unsigned char rsa_pub_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					     0x86, 0x48, 0x86, 0xf7, 0x0d,
					     0x01, 0x01, 0x01, 0x05, 0x00 };
      ITEM *item;

      item = (ITEM *)info;
      if( item->len != sizeof(rsa_pub_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, rsa_pub_der, sizeof(rsa_pub_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      break;
    }

  case AI_PKCS_RSAPrivate:
    {
      break;
    }

  case AI_PKCS_RSAPrivateBER:
    {
      static unsigned char rsa_priv_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					      0x86, 0x48, 0x86, 0xf7, 0x0d,
					      0x01, 0x01, 0x01, 0x05, 0x00 };
      ITEM *item;

      item = (ITEM *)info;
      if( item->len != sizeof(rsa_priv_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, rsa_priv_der, sizeof(rsa_priv_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      break;
    }

  case AI_SHA1WithRSAEncryption:
    {
      break;
    }

  case AI_SHA1WithRSAEncryptionBER:
    {
      static unsigned char sha1_rsa_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					      0x86, 0x48, 0x86, 0xf7, 0x0d,
					      0x01, 0x01, 0x05, 0x05, 0x00 };

      ITEM *item;

      item = (ITEM *)info;
      if( item->len != sizeof(sha1_rsa_der) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      if( memcmp( item->data, sha1_rsa_der, sizeof(sha1_rsa_der) ) ) {
	return (BE_WRONG_ALGORITHM_INFO);
      }

      break;
    }

      
  default:
    {
      obj->info = info;
      break;
    }
  }
  
  return (0);
}

int
B_GetAlgorithmInfo( POINTER *info, B_ALGORITHM_OBJ obj, int type )
{
  _BDebug( "In B_GetAlgorithmInfo\n" );

  if( obj == NULL ) {
    return (-1);
  }
  
  switch( obj->type ) {
    
  case AI_DES_CBC_IV8:
  case AI_DES_EDE3_CBC_IV8:
  case AI_DES_CBCPadIV8:
  case AI_DES_CBCPadBER:
    {
      /* Boy is this stupid. */
      static unsigned char des_cbc_der[] = { 0x30, 0x11, 0x06, 0x05, 0x2b,
					     0x0e, 0x03, 0x02, 0x07, 0x04,
					     0x08 };
      ITEM *item;
      
      if( type != AI_DES_CBCPadBER ) {
	*info = (unsigned char *)malloc(8);
	if( !*info ) {
	  return (-1);
	}
	
	memcpy( *info, obj->info, 8 );
      } 
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}
	
	item->len = sizeof(des_cbc_der)+8;

	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}
      
	memcpy( item->data, des_cbc_der, sizeof(des_cbc_der) );
	memcpy( (item->data)+sizeof(des_cbc_der), obj->info, 8 );

	*info = (POINTER)item;
      }

      break;
    }

  case AI_MD5WithDES_CBCPad:
  case AI_MD5WithDES_CBCPadBER:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;
      static unsigned char md5des_pbe_der[] = { 0x30, 0x1a, 0x06, 0x09, 0x2a,
						0x86, 0x48, 0x86, 0xf7, 0x0d,
						0x01, 0x05, 0x03, 0x30, 0x0d,
						0x04, 0x08 };
      ITEM *item;

      o_params = (B_PBE_PARAMS *)obj->info;
      
      if( type != AI_MD5WithDES_CBCPadBER ) {
	*info = (unsigned char *)malloc(sizeof(B_PBE_PARAMS));
	if( !*info ) {
	  return (-1);
	}

	params = (B_PBE_PARAMS *)*info;

	params->iterationCount = o_params->iterationCount;
	params->salt = (unsigned char *)malloc(8);
	if( !params->salt ) {
	  return (-1);
	}

	memcpy( params->salt, o_params->salt, 8 );
      } 
      else {
	int t;
	int i;
	int j;
	unsigned char buf[4];
	unsigned char *p;

	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	t = o_params->iterationCount;
	
	for( i=0, j=0; i < 4; i++ ) {
	  if( (t >> (3-i)*8) & 0xff ) {
	    buf[j++] = (unsigned char)(t >> (3-i)*8) & 0xff;
	  }
	}

	item->len = sizeof(md5des_pbe_der)+10+j;
      
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	p = item->data;
	memcpy( p, md5des_pbe_der, sizeof(md5des_pbe_der) );
	p += sizeof(md5des_pbe_der);
	memcpy( p, o_params->salt, 8 );
	p += 8;
	p[0] = 0x02;
	p[1] = j;
	p += 2;
	memcpy( p, buf, j );
	
	*info = (POINTER)item;
      }

      break;
    }

  case AI_SHA1WithDES_CBCPad:
  case AI_SHA1WithDES_CBCPadBER:
    {
      B_PBE_PARAMS *params;
      B_PBE_PARAMS *o_params;
      static unsigned char sha1des_pbe_der[] = { 0x30, 0x1b, 0x06, 0x09, 0x2a,
						 0x86, 0x48, 0x86, 0xf7, 0x0d,
						 0x01, 0x05, 0x0a, 0x30, 0x0e,
						 0x04, 0x08 };
      ITEM *item;

      o_params = (B_PBE_PARAMS *)obj->info;
      
      if( type != AI_SHA1WithDES_CBCPadBER ) {
	*info = (unsigned char *)malloc(sizeof(B_PBE_PARAMS));
	if( !*info ) {
	  return (-1);
	}

	params = (B_PBE_PARAMS *)*info;

	params->iterationCount = o_params->iterationCount;
	params->salt = (unsigned char *)malloc(8);
	if( !params->salt ) {
	  return (-1);
	}

	memcpy( params->salt, o_params->salt, 8 );
      } 
      else {
	int t;
	int i;
	int j;
	unsigned char buf[4];
	unsigned char *p;

	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	t = o_params->iterationCount;
	
	for( i=0, j=0; i < 4; i++ ) {
	  if( (t >> (3-i)*8) & 0xff ) {
	    buf[j++] = (unsigned char)(t >> (3-i)*8) & 0xff;
	  }
	}

	item->len = sizeof(sha1des_pbe_der)+10+j;
      
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	p = item->data;
	memcpy( p, sha1des_pbe_der, sizeof(sha1des_pbe_der) );
	p += sizeof(sha1des_pbe_der);
	memcpy( p, o_params->salt, 8 );
	p += 8;
	p[0] = 0x02;
	p[1] = j;
	p += 2;
	memcpy( p, buf, j );
	
	*info = (POINTER)item;
      }

      break;
    }

  case AI_SHA1:
  case AI_SHA1_BER:
    {
      static unsigned char sha1_der[] = { 0x30, 0x09, 0x06, 0x05, 0x2b,
					  0x0e, 0x03, 0x02, 0x1a, 0x05,
					  0x00 };
      ITEM *item;

      if( type != AI_SHA1_BER ) {
	*info = NULL_PTR;
      }
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	item->len = sizeof(sha1_der);
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	memcpy( item->data, sha1_der, sizeof(sha1_der) );
	
	*info = (POINTER) item;
      }

      break;
    }

  case AI_MD5:
  case AI_MD5_BER:
    {
      static unsigned char md5_der[] = { 0x30, 0x0c, 0x06, 0x08, 0x2a,
					 0x86, 0x48, 0x86, 0xf7, 0x0d,
					 0x02, 0x05, 0x05, 0x00 };
      ITEM *item;

      if( type != AI_MD5_BER ) {
	*info = NULL_PTR;
      }
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	item->len = sizeof(md5_der);
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	memcpy( item->data, md5_der, sizeof(md5_der) );
	
	*info = (POINTER) item;
      }

      break;
    }

  case AI_PKCS_RSAPublic:
  case AI_PKCS_RSAPublicBER:
    {
      static unsigned char rsa_pub_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					     0x86, 0x48, 0x86, 0xf7, 0x0d,
					     0x01, 0x01, 0x01, 0x05, 0x00 };
      ITEM *item;

      if( type != AI_PKCS_RSAPublicBER ) {
	*info = NULL_PTR;
      }
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	item->len = sizeof(rsa_pub_der);
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	memcpy( item->data, rsa_pub_der, sizeof(rsa_pub_der) );
	
	*info = (POINTER) item;
      }
      
      break;
    }

  case AI_PKCS_RSAPrivate:
  case AI_PKCS_RSAPrivateBER:
    {
      static unsigned char rsa_priv_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					      0x86, 0x48, 0x86, 0xf7, 0x0d,
					      0x01, 0x01, 0x01, 0x05, 0x00 };
      ITEM *item;

      if( type != AI_PKCS_RSAPrivateBER ) {
	*info = NULL_PTR;
      }
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	item->len = sizeof(rsa_priv_der);
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	memcpy( item->data, rsa_priv_der, sizeof(rsa_priv_der) );
	
	*info = (POINTER) item;
      }
      
      break;
    }

  case AI_SHA1WithRSAEncryption:
  case AI_SHA1WithRSAEncryptionBER:
    {
      static unsigned char sha1_rsa_der[] = { 0x30, 0x0d, 0x06, 0x09, 0x2a,
					      0x86, 0x48, 0x86, 0xf7, 0x0d,
					      0x01, 0x01, 0x05, 0x05, 0x00 };
      ITEM *item;

      if( type != AI_SHA1WithRSAEncryptionBER ) {
	*info = NULL_PTR;
      }
      else {
	item = (ITEM *)malloc(sizeof(ITEM));
	if( !item ) {
	  return (-1);
	}

	item->len = sizeof(sha1_rsa_der);
	item->data = (unsigned char *)malloc(item->len);
	if( !item->data ) {
	  return (-1);
	}

	memcpy( item->data, sha1_rsa_der, sizeof(sha1_rsa_der) );
	
	*info = (POINTER) item;
      }
      
      break;
    }

  default:
    {
      return (-1);
      break;
    }
  }
  
  return (0);
}
    
int
B_CreateKeyObject( B_KEY_OBJ *obj )
{
  _BDebug( "In B_CreateKeyObject\n" );

  if( obj == NULL ) {
    return (-1);
  }
  
  *obj = (B_KEY_OBJ)malloc(sizeof(BS_KEY));
  if( *obj == NULL ) {
    return (-1);
  }
  
  memset( (*obj), 0, sizeof(BS_KEY) );
  
  return (0);
}

int
B_DestroyKeyObject( B_KEY_OBJ *obj )
{
  _BDebug( "In B_DestroyKeyObject\n" );

#if 0
  if( (*obj)->data ) {
    free( (*obj)->data );
  }
#endif

  memset( (*obj), 0, sizeof(BS_KEY) );
  free(*obj);
  *obj = NULL;
  
  return (0);
}

int
B_SetKeyInfo( B_KEY_OBJ obj, int type, POINTER info )
{
  _BDebug( "In B_SetKeyInfo\n" );

  obj->type = type;

  if( info == NULL ) {
    return (-1);
  }
  
  switch( type ) {
    
  case KI_RSAPublic:
    {
      A_RSA_KEY *pub;
      RSA *rsa;
      
      obj->data = (unsigned char *)RSA_new();
      if( obj->data == NULL ) {
	return (-1);
      }
      
      pub = (A_RSA_KEY *)info;
      rsa = (RSA *)obj->data;
      
      rsa->n = BN_bin2bn(pub->modulus.data, pub->modulus.len, NULL);
      rsa->e = BN_bin2bn(pub->exponent.data, pub->exponent.len, NULL);
      
      break;
    }

  case KI_RSAPublicBER:
    {
      ITEM *item = (ITEM *)info;
      int i;
      RSA *rsa;
      unsigned char *p = item->data;

      /* HACK ALERT HACK ALERT
       * This will work for 1024 bit keys ONLY
       */
      p += 22;

      rsa = d2i_RSAPublicKey( NULL, (const unsigned char * *)&p, item->len-22 );
      if( !rsa ) {
	return (-1);
      }
      obj->data = (unsigned char *)rsa;

      break;
    }

  case KI_PKCS_RSAPrivate:
    {
      A_PKCS_RSA_PRIVATE_KEY *priv;
      RSA *rsa;
      
      obj->data = (unsigned char *)RSA_new();
      if( obj->data == NULL ) {
	return (-1);
      }
      
      priv = (A_PKCS_RSA_PRIVATE_KEY *)info;
      rsa = (RSA *)obj->data;

      rsa->n = BN_bin2bn(priv->modulus.data, priv->modulus.len, NULL);
      rsa->e = BN_bin2bn(priv->publicExponent.data, priv->publicExponent.len, 
			 NULL);
      rsa->d = BN_bin2bn(priv->privateExponent.data, priv->privateExponent.len, 
			 NULL);
      rsa->p = BN_bin2bn(priv->prime[0].data, priv->prime[0].len, NULL);
      rsa->q = BN_bin2bn(priv->prime[1].data, priv->prime[1].len, NULL);
      rsa->dmp1 = BN_bin2bn(priv->primeExponent[0].data, 
			    priv->primeExponent[0].len, 
			    NULL);
      rsa->dmq1 = BN_bin2bn(priv->primeExponent[1].data, 
			    priv->primeExponent[1].len, 
			    NULL);
      rsa->iqmp = BN_bin2bn(priv->coefficient.data, priv->coefficient.len, NULL);
      
      break;
    }

  case KI_PKCS_RSAPrivateBER:
    {
      RSA *rsa;
      ITEM *item = (ITEM *)info;
      int i;
      unsigned char *p = item->data;

      /* HACK ALERT HACK ALERT
       * This will work for 1024 bit keys only
       */
      p += 26;
      
      rsa = d2i_RSAPrivateKey( NULL, (const unsigned char * *)&p, item->len-26 );
      if( !rsa ) {
	return (-1);
      }

      obj->data = (unsigned char *)rsa;

      break;
    }
    
  case KI_DES8:
    {
      obj->data = (unsigned char *)malloc(sizeof(des_cblock));
      memcpy( obj->data, (unsigned char *)info, sizeof(des_cblock) );
      des_set_odd_parity( (des_cblock *)obj->data );
      break;
    }

  case KI_DES24Strong:
    {
      obj->data = (unsigned char *)malloc(3 * sizeof(des_cblock) );
      memcpy( obj->data, (unsigned char *)info, 3 * sizeof(des_cblock) );
      des_set_odd_parity( (des_cblock *)obj->data );
      des_set_odd_parity( (des_cblock *)(obj->data+sizeof(des_cblock)));
      des_set_odd_parity( (des_cblock *)(obj->data+2 * sizeof(des_cblock)));
      break;
    }
    
  case KI_8Byte:
    {
      obj->data = (unsigned char *)malloc(sizeof(des_cblock));
      memcpy( obj->data, (unsigned char *)info, sizeof(des_cblock) );
      des_set_odd_parity( (des_cblock *)obj->data );
      break;
    }
    
  case KI_Item:
    {
      ITEM *item = (ITEM *)info;
      ITEM *t;
      
      obj->data = (unsigned char *)malloc(sizeof(ITEM));
      if( !obj->data) {
	return (-1);
      }

      t = (ITEM *)obj->data;

      t->len = item->len;
      t->data = (unsigned char *)malloc(t->len);
      if( !t->data ) {
	return (BE_ALLOC);
      }

      memcpy( t->data, item->data, t->len );

      break;
    }
    
  default:
    return (-1);
  }
  
  return (0);
}

int
B_GetKeyInfo( POINTER *info, B_KEY_OBJ obj, int type )
{
  _BDebug( "In B_GetKeyInfo\n" );

  if( !obj || !info  ) {
    return (-1);
  }

  switch( type ) {
    
  case KI_RSAPublic:
    {
      A_RSA_KEY *pub;
      RSA *rsa;

      pub = (A_RSA_KEY *)malloc(sizeof(A_RSA_KEY));
      if( !pub ) {
	return (-1);
      }
      
      rsa = (RSA *)obj->data;
      if( !rsa ) {
	return (-1);
      }

      pub->modulus.len = BN_num_bytes(rsa->n);
      pub->exponent.len = BN_num_bytes(rsa->e);

      pub->modulus.data = (unsigned char *)malloc(pub->modulus.len);
      pub->exponent.data = (unsigned char *)malloc(pub->exponent.len);

      if( !pub->modulus.data || !pub->exponent.data ) {
	return (-1);
      }
      
      if( BN_bn2bin(rsa->n, pub->modulus.data) != pub->modulus.len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->e, pub->exponent.data) != pub->exponent.len ) {
	return (-1);
      }
      
      *info = (POINTER) pub;

      break;
    }
    
  case KI_PKCS_RSAPrivate:
    {
      A_PKCS_RSA_PRIVATE_KEY *priv;
      RSA *rsa;

      priv = (A_PKCS_RSA_PRIVATE_KEY *)malloc(sizeof(A_PKCS_RSA_PRIVATE_KEY));
      if( !priv ) {
	return (-1);
      }
      
      rsa = (RSA *)obj->data;
      if( !rsa ) {
	return (-1);
      }

      priv->modulus.len = BN_num_bytes(rsa->n);
      priv->publicExponent.len = BN_num_bytes(rsa->e);
      priv->privateExponent.len = BN_num_bytes(rsa->d);
      priv->prime[0].len = BN_num_bytes(rsa->p);
      priv->prime[1].len = BN_num_bytes(rsa->q);
      priv->primeExponent[0].len = BN_num_bytes(rsa->dmp1);
      priv->primeExponent[1].len = BN_num_bytes(rsa->dmq1);
      priv->coefficient.len = BN_num_bytes(rsa->iqmp);

      priv->modulus.data = (unsigned char *)malloc(priv->modulus.len);
      priv->publicExponent.data = (unsigned char *)
	  malloc(priv->publicExponent.len);
      priv->privateExponent.data = (unsigned char *)
	  malloc(priv->privateExponent.len);
      priv->prime[0].data = (unsigned char *)
	  malloc(priv->prime[0].len);
      priv->prime[1].data = (unsigned char *)
	  malloc(priv->prime[1].len);
      priv->primeExponent[0].data = (unsigned char *)
	  malloc(priv->primeExponent[0].len);
      priv->primeExponent[1].data = (unsigned char *)
	  malloc(priv->primeExponent[1].len);
      priv->coefficient.data = (unsigned char *)malloc(priv->coefficient.len);

      if( !priv->modulus.data || !priv->publicExponent.data ||
	 !priv->privateExponent.data || !priv->prime[0].data ||
	 !priv->prime[1].data || !priv->primeExponent[0].data ||
	 !priv->primeExponent[1].data) {
	return (-1);
      }
      
      if( BN_bn2bin(rsa->n, priv->modulus.data) != priv->modulus.len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->e, priv->publicExponent.data) !=
	 priv->publicExponent.len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->d, priv->privateExponent.data) !=
	 priv->privateExponent.len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->p, priv->prime[0].data) !=
	 priv->prime[0].len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->q, priv->prime[1].data) !=
	 priv->prime[1].len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->dmp1, priv->primeExponent[0].data) !=
	 priv->primeExponent[0].len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->dmq1, priv->primeExponent[1].data) !=
	 priv->primeExponent[1].len ) {
	return (-1);
      }
      if( BN_bn2bin(rsa->iqmp, priv->coefficient.data)
	 != priv->coefficient.len ) {
	return (-1);
      }
      
      *info = (POINTER) priv;

      break;
    }
    
  default:
    return (-1);
  }

  return (0);
}

int
B_DigestInit(B_ALGORITHM_OBJ obj, B_KEY_OBJ key, 
	     B_ALGORITHM_METHOD *chooser[], A_SURRENDER_CTX *ctx)
{
  _BDebug( "In B_DigestInit\n" );

  switch( obj->type ) {
    
  case AI_MD5:
  case AI_MD5_BER:
    {
      obj->state = (unsigned char *)malloc(sizeof(MD5_CTX));
      if( !obj->state ) {
	return (-1);
      }

      MD5_Init( (MD5_CTX *)obj->state );

      break;
    }

  case AI_SHA1:
  case AI_SHA1_BER:
    {
      obj->state = (unsigned char *)malloc(sizeof(SHA_CTX));
      if( !obj->state ) {
	return (-1);
      }

      SHA1_Init( (SHA_CTX *)obj->state );

      break;
    }

  default:
    {
      return (-1);
      break;
    }
  }

  return (0);
}

int
B_DigestUpdate(B_ALGORITHM_OBJ obj, POINTER in, unsigned inlen,
	       A_SURRENDER_CTX *ctx)
{
  _BDebug( "In B_DigestUpdate\n" );

  switch( obj->type ) {
    
  case AI_MD5:
  case AI_MD5_BER:
    {
      if( !obj->state ) {
	B_DigestInit( obj, NULL, NULL, NULL );
      }
      
      MD5_Update( (MD5_CTX *)obj->state, in, inlen );

      break;
    }

  case AI_SHA1:
  case AI_SHA1_BER:
    {
      if( !obj->state ) {
	_BDebug( "Update calling Init..." );
	B_DigestInit( obj, NULL, NULL, NULL );
      }
      
      SHA1_Update( (SHA_CTX *)obj->state, in, inlen );

      break;
    }

  default:
    {
      return (-1);
      break;
    }
  }

  return (0);
}

int
B_DigestFinal(B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
	      unsigned int max_out, A_SURRENDER_CTX *ctx)
{
  _BDebug( "In B_DigestFinal\n" );

  switch( obj->type ) {
    
  case AI_SHA1:
  case AI_SHA1_BER:
    {
      SHA1_Final( out, (SHA_CTX *)obj->state );
      free( obj->state );
      obj->state = NULL;
      *outlen = 20;

      break;
    }

  case AI_MD5:
  case AI_MD5_BER:
    {
      MD5_Final( out, (MD5_CTX *)obj->state );
      free( obj->state );
      obj->state = NULL;
      *outlen = 16;

      break;
    }

  default:
    return (-1);
  }

  return (0);
}

int
B_RandomInit( B_ALGORITHM_OBJ obj, B_ALGORITHM_METHOD *chooser[],
	      A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_RandomInit\n" );

  return (0);
}

int
B_RandomUpdate( B_ALGORITHM_OBJ obj, POINTER blah, unsigned int len, 
	       A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_RandomUpdate\n" );

  RAND_seed( blah, len );
  return (0);
}

int
B_GenerateRandomBytes( B_ALGORITHM_OBJ obj, POINTER data, unsigned int len,
		      A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_GenerateRandomBytes\n" );

  RAND_bytes( data, len );
  return (0);
}

int
B_KeyAgreeInit(B_ALGORITHM_OBJ obj, B_KEY_OBJ key, 
	       B_ALGORITHM_METHOD *chooser[],
	       A_SURRENDER_CTX *ctx )
{
  B_KEY_OBJ kobj;
  DH *gen;
  A_DH_KEY_AGREE_PARAMS *dhparams;

  _BDebug( "In B_KeyAgreeInit\n" );
  
  dhparams = (A_DH_KEY_AGREE_PARAMS *)obj->info;
  
  gen = DH_new();

  gen->p = BN_bin2bn( dhparams->prime.data, dhparams->prime.len, NULL );
  gen->g = BN_bin2bn( dhparams->base.data, dhparams->base.len, NULL );

  kobj = (B_KEY_OBJ)malloc(sizeof(BS_KEY));
  if( !kobj ) {
    return (-1);
  }

  kobj->data = (unsigned char *)gen;
  obj->key = (unsigned char *)kobj;

  return (0);
}

int
B_KeyAgreePhase1(B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
		 unsigned int max_out, B_ALGORITHM_OBJ rng,
		 A_SURRENDER_CTX *ctx)
{
  B_KEY_OBJ kobj;
  DH *gen, *a;

  _BDebug( "In B_KeyAgreePhase1\n" );

  kobj = (B_KEY_OBJ)obj->key;
  gen = (DH *)kobj->data;

  a = DH_new();
  a->p=BN_dup(gen->p);
  a->g=BN_dup(gen->g);

  if( !DH_generate_key(a) ) return (-1);
  BN_bn2bin( a->pub_key, out );
  *outlen = DH_size(a);

  kobj->data = (unsigned char *)a;
  DH_free(gen);
  
  return (0);
}

int
B_KeyAgreePhase2(B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
		 unsigned int max_out, POINTER in, unsigned int inlen,
		 A_SURRENDER_CTX *ctx)
{
  B_KEY_OBJ kobj;
  DH *a;
  BIGNUM *bn;
  int l;
  
  _BDebug( "In B_KeyAgreePhase2\n" );

  kobj = (B_KEY_OBJ)obj->key;
  a = (DH *)kobj->data;

  BN_bin2bn(in, inlen, NULL);

  l = DH_compute_key( out, bn, a );
  if( l < 0 ) {
    return (-1);
  }

  *outlen = l;
  
  return (0);
}

int
B_EncryptInit( B_ALGORITHM_OBJ obj, B_KEY_OBJ key, 
	      B_ALGORITHM_METHOD *chooser[], A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_EncryptInit\n" );

  obj->key = (void *)key;

  switch( obj->type ) {

  case AI_MD5WithDES_CBCPad:
  case AI_MD5WithDES_CBCPadBER:
    {
      MD5_CTX *ctx;
      unsigned char tmp[16];
      B_PBE_PARAMS *pbe = (B_PBE_PARAMS *)obj->info;
      ITEM *item = (ITEM *)key->data;
      int i;
      
      obj->state = (unsigned char *)malloc(16);
      if( !obj->state ) {
	return (-1);
      }

      ctx = (MD5_CTX *)malloc(sizeof(MD5_CTX));
      if( !ctx ) {
	return (-1);
      }
	
      MD5_Init( ctx );

      memcpy( tmp, item->data, item->len );
      memcpy( tmp+item->len, pbe->salt, 8 );

      MD5_Update( ctx, tmp, item->len + 8 );
      MD5_Final( tmp, ctx );

      pbe->iterationCount--;  /* this will save us time in the loop */

      for( i=0; i < pbe->iterationCount; i++ ) {
	MD5_Init( ctx );
	MD5_Update( ctx, tmp, 16 );
	MD5_Final( tmp, ctx );
      }

      pbe->iterationCount++;  /* undo */

      memcpy( obj->state, tmp, 16 );
      free(ctx);
      
      break;
    }

  case AI_SHA1WithDES_CBCPad:
  case AI_SHA1WithDES_CBCPadBER:
    {
      SHA_CTX *ctx;
      unsigned char tmp[20];
      B_PBE_PARAMS *pbe = (B_PBE_PARAMS *)obj->info;
      ITEM *item = (ITEM *)key->data;
      int i;
      
      obj->state = (unsigned char *)malloc(16);
      if( !obj->state ) {
	return (-1);
      }

      ctx = (SHA_CTX *)malloc(sizeof(SHA_CTX));
      if( !ctx ) {
	return (-1);
      }
	
      SHA1_Init( ctx );

      memcpy( tmp, item->data, item->len );
      memcpy( tmp+item->len, pbe->salt, 8 );

      SHA1_Update( ctx, tmp, item->len + 8 );
      SHA1_Final( tmp, ctx );

      pbe->iterationCount--;  /* this will save us time in the loop */

      for( i=0; i < pbe->iterationCount; i++ ) {
	SHA1_Init( ctx );
	SHA1_Update( ctx, tmp, 20 ); /* IS THIS RIGHT? There's no bloody PKCS
					draft that I can find for this alg */
	SHA1_Final( tmp, ctx );
      }

      pbe->iterationCount++;  /* undo */

      memcpy( obj->state, tmp, 16 ); /* IS THIS RIGHT? There's no bloody PKCS
					draft that I can find for this alg */

      free(ctx);
      
      break;
    }
  }
  
  return (0);
}

int 
B_EncryptUpdate( B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
		 unsigned int maxoutlen, POINTER in, unsigned int inlen,
		 B_ALGORITHM_OBJ rand, A_SURRENDER_CTX *ctx )
{
  B_KEY_OBJ kobj;
  int l;

  _BDebug( "In B_EncryptUpdate\n" );

  switch( obj->type ) {
    
  case AI_PKCS_RSAPublic:
  case AI_PKCS_RSAPublicBER:
    {
      RSA* rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_public_encrypt( inlen, (unsigned char *)in,
				    (unsigned char *)out, 
				    rsa,
				    RSA_PKCS1_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;

      break;
    }
    
  case AI_PKCS_RSAPrivate:
  case AI_PKCS_RSAPrivateBER:
    {
      RSA* rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_private_encrypt( inlen, (unsigned char *)in,
				     (unsigned char *)out, 
				     rsa,
				     RSA_PKCS1_PADDING );
      if( l <= 0 ) {
	return (-1);
      }

      *outlen = l;
      break;
    }

#ifdef NOPADDING
  case AI_RSAPublic:
    {
      RSA* rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_public_encrypt( inlen, (unsigned char *)in,
				    (unsigned char *)out, 
				    rsa,
				    RSA_NO_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;

      break;
    }
    
  case AI_RSAPrivate:
    {
      RSA* rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_private_encrypt( inlen, (unsigned char *)in,
				     (unsigned char *)out, 
				     rsa,
				     RSA_NO_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;

      break;
    }
#endif

  case AI_DES_CBC_IV8:
    {
      des_key_schedule sched;

      kobj = (B_KEY_OBJ)obj->key;

      des_set_key( (des_cblock *)kobj->data, sched );

      des_ncbc_encrypt( in, 
			out, 
			inlen, 
			sched, 
			(des_cblock *)obj->info, 
			DES_ENCRYPT );
      *outlen = inlen;

      break;
    }

  case AI_DES_EDE3_CBC_IV8:
    {
      des_key_schedule sched1;
      des_key_schedule sched2;
      des_key_schedule sched3;

      kobj = (B_KEY_OBJ)obj->key;

      des_set_key( (des_cblock *)kobj->data, sched1 );
      des_set_key( (des_cblock *)(kobj->data + sizeof(des_cblock)), sched2 );
      des_set_key( (des_cblock *)(kobj->data + 2 * sizeof(des_cblock)),
		  sched3 );

      des_ede3_cbc_encrypt( in, 
			   out, 
			   inlen, 
			   sched1, sched2, sched3,
			   (des_cblock *)obj->info, 
			   DES_ENCRYPT );
      *outlen = inlen;

      break;
    }
    
  case AI_DES_CBCPadIV8:
  case AI_DES_CBCPadBER:
    {
      des_key_schedule sched;
      unsigned char *in_pad;
      int newlen;
      int i;
      
      newlen = (inlen % 8) ? inlen + (8-(inlen%8)) : inlen + 8;
      
      in_pad = (unsigned char *)malloc(newlen);
      if( !in_pad ) {
	return (-1);
      }

      memcpy( in_pad, in, inlen );
      
      /* PKCS #5 padding
       */
      for( i=inlen; i < newlen; i++ ) {
	in_pad[i] = (unsigned char)(newlen-inlen);
      }

      kobj = (B_KEY_OBJ)obj->key;
      des_set_key( (des_cblock *)kobj->data, sched );

      des_ncbc_encrypt( in_pad, 
			out, 
			newlen, 
			sched, 
			(des_cblock *)obj->info, 
			DES_ENCRYPT );
      *outlen = newlen;
      free(in_pad);

      break;
    }
    
  case AI_MD5WithDES_CBCPad:
  case AI_MD5WithDES_CBCPadBER:
    {
      des_key_schedule sched;
      unsigned char *in_pad;
      int newlen;
      int i;
      
      newlen = (inlen % 8) ? inlen + (8-(inlen%8)) : inlen + 8;
      
      in_pad = (unsigned char *)malloc(newlen);
      if( !in_pad ) {
	return (-1);
      }

      memcpy( in_pad, in, inlen );
      
      /* PKCS #5 padding
       */
      for( i=inlen; i < newlen; i++ ) {
	in_pad[i] = (unsigned char)(newlen-inlen);
      }

      des_set_key( (des_cblock *)obj->state, sched );

      des_ncbc_encrypt( in_pad, 
			out, 
			newlen, 
			sched, 
			(des_cblock *)&(obj->state[8]), 
			DES_ENCRYPT );
      *outlen = newlen;
      free(in_pad);

      break;
    }
    
  case AI_SHA1WithDES_CBCPad:
  case AI_SHA1WithDES_CBCPadBER:
    {
      des_key_schedule sched;
      unsigned char *in_pad;
      int newlen;
      int i;
      
      newlen = (inlen % 8) ? inlen + (8-(inlen%8)) : inlen + 8;
      
      in_pad = (unsigned char *)malloc(newlen);
      if( !in_pad ) {
	return (-1);
      }

      memcpy( in_pad, in, inlen );
      
      /* PKCS #5 padding
       */
      for( i=inlen; i < newlen; i++ ) {
	in_pad[i] = (unsigned char)(newlen-inlen);
      }

      des_set_key( (des_cblock *)obj->state, sched );

      des_ncbc_encrypt( in_pad, 
			out, 
			newlen, 
			sched, 
			(des_cblock *)&(obj->state[8]), 
			DES_ENCRYPT );
      *outlen = newlen;
      free(in_pad);

      break;
    }
    
  default:
    return (-1);
  }

  assert (*outlen <= maxoutlen);
  return (0);
}

int
B_EncryptFinal( B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
		unsigned int maxoutlen, B_ALGORITHM_OBJ rand,
		A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_EncryptFinal\n" );

  *outlen = 0;
  return (0);
}

int
B_DecryptInit( B_ALGORITHM_OBJ obj, B_KEY_OBJ key, 
	       B_ALGORITHM_METHOD *chooser[], A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_DecryptInit\n" );

  obj->key = (void *)key;
  
  switch( obj->type ) {

  case AI_MD5WithDES_CBCPad:
  case AI_MD5WithDES_CBCPadBER:
    {
      MD5_CTX *ctx;
      unsigned char tmp[16];
      B_PBE_PARAMS *pbe = (B_PBE_PARAMS *)obj->info;
      ITEM *item = (ITEM *)key->data;
      int i;
      
      obj->state = (unsigned char *)malloc(16);
      if( !obj->state ) {
	return (-1);
      }

      ctx = (MD5_CTX *)malloc(sizeof(MD5_CTX));
      if( !ctx ) {
	return (-1);
      }
	
      MD5_Init( ctx );

      memcpy( tmp, item->data, item->len );
      memcpy( tmp+item->len, pbe->salt, 8 );

      MD5_Update( ctx, tmp, item->len + 8 );
      MD5_Final( tmp, ctx );

      pbe->iterationCount--;  /* this will save us time in the loop */

      for( i=0; i < pbe->iterationCount; i++ ) {
	MD5_Init( ctx );
	MD5_Update( ctx, tmp, 16 );
	MD5_Final( tmp, ctx );
      }

      pbe->iterationCount++;  /* undo */

      memcpy( obj->state, tmp, 16 );
      free(ctx);
      
      break;
    }

  case AI_SHA1WithDES_CBCPad:
  case AI_SHA1WithDES_CBCPadBER:
    {
      SHA_CTX *ctx;
      unsigned char tmp[20];
      B_PBE_PARAMS *pbe = (B_PBE_PARAMS *)obj->info;
      ITEM *item = (ITEM *)key->data;
      int i;
      
      obj->state = (unsigned char *)malloc(16);
      if( !obj->state ) {
	return (-1);
      }

      ctx = (SHA_CTX *)malloc(sizeof(SHA_CTX));
      if( !ctx ) {
	return (-1);
      }
	
      SHA1_Init( ctx );

      memcpy( tmp, item->data, item->len );
      memcpy( tmp+item->len, pbe->salt, 8 );

      SHA1_Update( ctx, tmp, item->len + 8 );
      SHA1_Final( tmp, ctx );

      pbe->iterationCount--;  /* this will save us time in the loop */

      for( i=0; i < pbe->iterationCount; i++ ) {
	SHA1_Init( ctx );
	SHA1_Update( ctx, tmp, 20 ); /* IS THIS RIGHT? There's no bloody PKCS
					draft that I can find for this alg */
	SHA1_Final( tmp, ctx );
      }

      pbe->iterationCount++;  /* undo */

      memcpy( obj->state, tmp, 16 ); /* IS THIS RIGHT? There's no bloody PKCS
					draft that I can find for this alg */

      free(ctx);
      
      break;
    }
  }
  
  return (0);
}

int 
B_DecryptUpdate( B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
		unsigned int maxoutlen, POINTER in, unsigned int inlen,
		B_ALGORITHM_OBJ rand, A_SURRENDER_CTX *ctx )
{
  B_KEY_OBJ kobj;
  int l;

  _BDebug( "In B_DecryptUpdate\n" );

  switch( obj->type ) {
    
  case AI_PKCS_RSAPublic:
  case AI_PKCS_RSAPublicBER:
    {
      RSA *rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_public_decrypt( inlen, (unsigned char *)in,
				    (unsigned char *)out, 
				    rsa,
				    RSA_PKCS1_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;
      break;
    }

  case AI_PKCS_RSAPrivate:
  case AI_PKCS_RSAPrivateBER:
    {
      RSA *rsa;

      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_private_decrypt( inlen, (unsigned char *)in,
				     (unsigned char *)out, 
				     rsa,
				     RSA_PKCS1_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;
      break;
    }

#ifdef NOPADDING
  case AI_RSAPublic:
    {
      RSA *rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_public_decrypt( inlen, (unsigned char *)in,
				    (unsigned char *)out, 
				    rsa,
				    RSA_NO_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;
      break;
    }

  case AI_RSAPrivate:
    {
      RSA *rsa;
      
      kobj = (B_KEY_OBJ)obj->key;
      rsa = (RSA *)kobj->data;
      
      l = RSA_private_decrypt( inlen, (unsigned char *)in,
				     (unsigned char *)out, 
				     rsa,
				     RSA_NO_PADDING );
      if( l <= 0 ) {
	return (-1);
      }
      *outlen = l;
      break;
    }
#endif

  case AI_DES_CBC_IV8:
    {
      des_key_schedule sched;

      kobj = (B_KEY_OBJ)obj->key;

      des_set_key( (des_cblock *)kobj->data, sched );
      
      des_ncbc_encrypt( in, 
			out, 
			inlen, 
			sched, 
			(des_cblock *)obj->info, 
			DES_DECRYPT );
      *outlen = inlen;

      break;
    }

  case AI_DES_EDE3_CBC_IV8:
    {
      des_key_schedule sched1;
      des_key_schedule sched2;
      des_key_schedule sched3;

      kobj = (B_KEY_OBJ)obj->key;

      des_set_key( (des_cblock *)kobj->data, sched1 );
      des_set_key( (des_cblock *)(kobj->data + sizeof(des_cblock)), sched2 );
      des_set_key( (des_cblock *)(kobj->data + 2 * sizeof(des_cblock)),
		  sched3 );
      
      des_ede3_cbc_encrypt( in, 
			   out, 
			   inlen, 
			   sched1, sched2, sched3,
			   (des_cblock *)obj->info, 
			   DES_DECRYPT );
      *outlen = inlen;

      break;
    }
    
  case AI_DES_CBCPadIV8:
  case AI_DES_CBCPadBER:
    {
      des_key_schedule sched;

      kobj = (B_KEY_OBJ)obj->key;
      des_set_key( (des_cblock *)kobj->data, sched );

      des_ncbc_encrypt( in, 
			out, 
			inlen, 
			sched, 
			(des_cblock *)obj->info, 
			DES_DECRYPT );

      /* Determine length of PKCS #5 padding
       */
      *outlen = inlen - (int)(out[inlen-1]);

      break;
    }
    
  case AI_MD5WithDES_CBCPad:
  case AI_MD5WithDES_CBCPadBER:
    {
      des_key_schedule sched;

      kobj = (B_KEY_OBJ)obj->key;
      des_set_key( (des_cblock *)obj->state, sched );

      des_ncbc_encrypt( in, 
			out, 
			inlen, 
			sched, 
			(des_cblock *)&(obj->state[8]), 
			DES_DECRYPT );

      /* Determine length of PKCS #5 padding
       */
      *outlen = inlen - (int)(out[inlen-1]);

      break;
    }
    
  case AI_SHA1WithDES_CBCPad:
  case AI_SHA1WithDES_CBCPadBER:
    {
      des_key_schedule sched;

      kobj = (B_KEY_OBJ)obj->key;
      des_set_key( (des_cblock *)obj->state, sched );

      des_ncbc_encrypt( in, 
			out, 
			inlen, 
			sched, 
			(des_cblock *)&(obj->state[8]), 
			DES_DECRYPT );

      /* Determine length of PKCS #5 padding
       */
      *outlen = inlen - (int)(out[inlen-1]);

      break;
    }
    
  default:
    return (-1);
  }
  
  return (0);
}

int
B_DecryptFinal( B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
	       unsigned int maxoutlen, B_ALGORITHM_OBJ rand,
	       A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_DecryptFinal\n" );

  *outlen = 0;
  return (0);
}

int
B_SignInit( B_ALGORITHM_OBJ obj, B_KEY_OBJ key,
	   B_ALGORITHM_METHOD *chooser[], A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_SignInit\n" );

  obj->key = (void *)key;
  obj->state = NULL;
  return (0);
}

int 
B_SignUpdate( B_ALGORITHM_OBJ obj, POINTER in, unsigned int inlen,
	     A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_SignUpdate\n" );

  switch( obj->type ) {
    
  case AI_MD5WithRSAEncryption:
  case AI_MD5WithRSAEncryptionBER:
    {
      MD5_CTX *ctx;

      if( !obj->state ) {
	ctx = (MD5_CTX *)malloc(sizeof(MD5_CTX));
	if( !ctx ) {
	  return (-1);
	}
	
	obj->state = (unsigned char *)ctx;
	MD5_Init( ctx );
      }
      else {
	ctx = (MD5_CTX *)obj->state;
      }

      MD5_Update( ctx, in, inlen );
      
      break;
    }

  case AI_SHA1WithRSAEncryption:
  case AI_SHA1WithRSAEncryptionBER:
    {
      SHA_CTX *ctx;

      if( !obj->state ) {
	ctx = (SHA_CTX *)malloc(sizeof(SHA_CTX));
	if( !ctx ) {
	  return (-1);
	}
	
	obj->state = (unsigned char *)ctx;
	SHA1_Init( ctx );
      }
      else {
	ctx = (SHA_CTX *)obj->state;
      }

      SHA1_Update( ctx, in, inlen );
      
      break;
    }

  default:
    return (-1);
  }
      
  return (0);
}

int
B_SignFinal( B_ALGORITHM_OBJ obj, POINTER out, unsigned int *outlen,
	     unsigned int maxoutlen, B_ALGORITHM_OBJ rand,
	     A_SURRENDER_CTX *ctx )
{
  B_KEY_OBJ kobj;
  unsigned char buf[64];

  /* why do we need 18 bytes to tell us about the following 16?
   */
  unsigned char md5_ber[] = {
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 
    0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 
    0x04, 0x10
  };

  /* why do we need 15 bytes to tell us about the following 20?
   */
  unsigned char sha1_ber[] = {      
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
  };
  unsigned char hash[20];
  int l;

  _BDebug( "In B_SignFinal\n" );

  switch( obj->type ) {
    
  case AI_MD5WithRSAEncryption:
  case AI_MD5WithRSAEncryptionBER:
    {
      MD5_CTX *ctx = (MD5_CTX *)obj->state;

      MD5_Final( hash, ctx );

      memcpy( buf, md5_ber, 18 );
      memcpy( buf+18, hash, 16 );
      
      kobj = (B_KEY_OBJ)obj->key;
      
      l = RSA_private_encrypt( 34, buf, out, (RSA *)kobj->data, 
				     RSA_PKCS1_PADDING );
      if( l < 0 ) {
	return (-1);
      }
      *outlen = l;
      
      break;
    }
    
  case AI_SHA1WithRSAEncryption:
  case AI_SHA1WithRSAEncryptionBER:
    {
      SHA_CTX *ctx = (SHA_CTX *)obj->state;

      SHA1_Final( hash, ctx );

      memcpy( buf, sha1_ber, 15 );
      memcpy( buf+15, hash, 20 );
      
      kobj = (B_KEY_OBJ)obj->key;
      
      l = RSA_private_encrypt( 35, buf, out, (RSA *)kobj->data, 
				     RSA_PKCS1_PADDING );
      if( l < 0 ) {
	return (-1);
      }
      *outlen = l;
      
      break;
    }
    
  default:
    return (-1);
  }

  return (0);
}

int
B_VerifyInit( B_ALGORITHM_OBJ obj, B_KEY_OBJ key,
	     B_ALGORITHM_METHOD *chooser[], A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_VerifyInit\n" );

  obj->key = (void *)key;
  obj->state = NULL;
  return (0);
}

int 
B_VerifyUpdate( B_ALGORITHM_OBJ obj, POINTER in, unsigned int inlen,
	       A_SURRENDER_CTX *ctx )
{
  _BDebug( "In B_VerifyUpdate\n" );

  switch( obj->type ) {
    
  case AI_MD5WithRSAEncryption:
  case AI_MD5WithRSAEncryptionBER:
    {
      MD5_CTX *ctx;

      if( !obj->state ) {
	ctx = (MD5_CTX *)malloc(sizeof(MD5_CTX));
	if( !ctx ) {
	  return (-1);
	}
	
	obj->state = (unsigned char *)ctx;
	MD5_Init( ctx );
      }
      else {
	ctx = (MD5_CTX *)obj->state;
      }

      MD5_Update( ctx, in, inlen );
      
      break;
    }

  case AI_SHA1WithRSAEncryption:
  case AI_SHA1WithRSAEncryptionBER:
    {
      SHA_CTX *ctx;

      if( !obj->state ) {
	ctx = (SHA_CTX *)malloc(sizeof(SHA_CTX));
	if( !ctx ) {
	  return (-1);
	}
	
	obj->state = (unsigned char *)ctx;
	SHA1_Init( ctx );
      }
      else {
	ctx = (SHA_CTX *)obj->state;
      }

      SHA1_Update( ctx, in, inlen );
      
      break;
    }

  default:
    return (-1);
  }
      
  return (0);
}

int
B_VerifyFinal( B_ALGORITHM_OBJ obj, POINTER inhash, unsigned int hashlen,
	      B_ALGORITHM_OBJ rand, A_SURRENDER_CTX *ctx )
{
  B_KEY_OBJ kobj;
  unsigned char out[64];
  unsigned char md5_ber[] = { 
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 
    0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 
    0x04, 0x10
  };
  unsigned char sha1_ber[] = {      
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
  };
  int outlen;
  unsigned char hash[20];

  _BDebug( "In B_VerifyFinal\n" );

  switch( obj->type ) {
    
  case AI_MD5WithRSAEncryption:
  case AI_MD5WithRSAEncryptionBER:
    {
      MD5_CTX *ctx = (MD5_CTX *)obj->state;
      
      kobj = (B_KEY_OBJ)obj->key;
      
      outlen = RSA_public_decrypt( hashlen, inhash, out, 
				   (RSA *)kobj->data, RSA_PKCS1_PADDING );
      if( outlen != 34 ) {
	return (-1);
      }
      
      if( memcmp( out, md5_ber, 18 ) != 0 ) {
	return (-1);
      }
      
      MD5_Final( hash, ctx );
      
      if( memcmp( out+18, hash, 16 ) != 0 ) {
	return (-1);
      }
    
      break;
    }
    
  case AI_SHA1WithRSAEncryption:
  case AI_SHA1WithRSAEncryptionBER:
    {
      SHA_CTX *ctx = (SHA_CTX *)obj->state;
      
      kobj = (B_KEY_OBJ)obj->key;
      
      outlen = RSA_public_decrypt( hashlen, inhash, out, 
				   (RSA *)kobj->data, RSA_PKCS1_PADDING );
      if( outlen != 35 ) {
	return (-1);
      }
      
      if( memcmp( out, sha1_ber, 15 ) != 0 ) {
	return (-1);
      }
      
      SHA1_Final( hash, ctx );
      
      if( memcmp( out+15, hash, 20 ) != 0 ) {
	return (-1);
      }
      
      break;
    }
    
  default:
    return (-1);
  }

  return (0);
}

int
B_IntegerBits( unsigned char *num, int bytes )
{
  register int i;
  register int j;
  int bits;

  _BDebug( "In B_IntegerBits\n" );

  if( bytes < 0 ) {
    return (-1);
  }
  if( bytes == 0 ) {
    return (0);
  }
  
  for( i=0; i < bytes && num[i] == (unsigned char) 0; i++ );
  if( i == bytes ) {
    return (0);
  }
  
  for( j=7; j >= 0; j-- ) {
    if( num[i] >> j ) {
      bits = j+1;
      break;
    }
  }
    
  bytes -= i;
  bytes--;
  bits += (bytes*8);
    
  return (bits);
}


int
B_GenerateInit (B_ALGORITHM_OBJ alg, B_ALGORITHM_METHOD *chooser[],
		A_SURRENDER_CTX *ctx)
{
    return (0);
};

int
B_GenerateKeypair (B_ALGORITHM_OBJ obj, B_KEY_OBJ pub,
		   B_KEY_OBJ priv, B_ALGORITHM_OBJ randomalg,
		   A_SURRENDER_CTX *ctx)
{
    A_RSA_KEY_GEN_PARAMS *params;
    RSA *rsa;
    BIGNUM *e;

    _BDebug ( "In B_GenerateKeypair\n" );

    params = (A_RSA_KEY_GEN_PARAMS *)obj->info;

    e = BN_bin2bn (params->publicExponent.data,
		   params->publicExponent.len,
		   NULL);

    rsa = RSA_generate_key (params->modulusBits, BN_get_word (e), NULL
#if (SSLEAY_VERSION_NUMBER >= 0x900)
			    ,NULL
#endif
);

      if( !rsa ) {
	return (-1);
      }

    priv->type = KI_PKCS_RSAPrivate;
    priv->data = (unsigned char *) rsa;
    
    pub->type = KI_RSAPublic;
    pub->data = (unsigned char *)rsa; /* probably should not point to the same object... */

    return (0);
}
