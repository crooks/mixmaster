/* $Id: keymgt.c,v 1.2 2002/10/18 22:37:50 rabbi Exp $
 * $Log: keymgt.c,v $
 * Revision 1.2  2002/10/18 22:37:50  rabbi
 * We prepend the protocol version string to the software version number in
 * the type 2 capstring. This is necessary to allow existing Mixmaster
 * versions to interoperate with future versions of Mixmaster.
 *
 * This isn't strictly necessary with versions 2.x, but I'm making this
 * change for consistency.
 *
 * Revision 1.1.1.1  2002/08/28 20:06:50  rabbi
 * Mixmaster 2.0.5 source.
 *
 * Revision 2.7  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.6  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.5  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 * Revision 2.4  1998/02/26  03:34:40  um
 * Bug fix.
 *
 * Revision 2.3  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 * Revision 2.2  1998/02/17  23:25:41  um
 * Check R_DecodePEMBlock return values.
 *
 * keymgt.c            1997-08-19 um
 *      gcc warnings eliminated.
 *
 * keymgt.c            1997-07-06 um
 *
 * keymgt.c            1997-06-12 um
 *      new file keyinfo.txt. minor modifications
 *
 * keymgt.c            1997-05-30 um
 *      create key certificate
 *
 * keymgt.c            1997-05-30 um
 *      new key management functions
 *
 * keymgt.c            1996-10-07 um
 *      randomness handling moved to random.c
 *
 * keymgt.c        1.5 11/5/95
 *      Key files created if they don't exist already.
 *
 * keymgt.c        1.4 9/10/95
 *      Minor bux fix to error messages
 *
 * keymgt.c        1.3 4/27/95
 *
 *      (c) Copyright 1995 by Lance Cottrell. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 *
 *                      - Lance Cottrell (loki@obscura.com) 4/23/95
 *
 */

#include "mix.h"
#include "crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MIX_RSA_MOD 1024
#define MIX_DH_PRIME 1024
#define MIX_DH_SUB 700


void
encode_ID (unsigned char *IDstr, const unsigned char *ID)
{
  sprintf (IDstr, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	   ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7], ID[8],
	   ID[9], ID[10], ID[11], ID[12], ID[13], ID[14], ID[15]);
}

void
print_ID (FILE * f, unsigned char *ID)
{
  fprintf (f, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	   ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7], ID[8],
	   ID[9], ID[10], ID[11], ID[12], ID[13], ID[14], ID[15]);
}

int
generate_DH (void)
{
#ifdef USE_RSAREF
  R_DH_PARAMS DH_parms;
  unsigned char tmp, ID[16];
  unsigned char prime[DH_PRIME_LEN (MIX_DH_PRIME)], generator[DH_PRIME_LEN (MIX_DH_PRIME)];
  int i, err;
  BUFFER *buff;
  R_DIGEST_CTX context;
  FILE *dhfile, *dhlock;

  fprintf (errlog, "Now making the DH parameters. This may take a while.\n");

  mix_lock ("DH", &dhlock);
  if ((dhfile = open_mix_file ("DH.mix", "w")) == NULL)
    {
      mix_unlock ("DH", dhlock);
      return (-1);
    }
  DH_parms.prime = prime;
  DH_parms.generator = generator;

  err = R_GenerateDHParams (&DH_parms, MIX_DH_PRIME, MIX_DH_SUB, &random_obj);
  if (err != 0)
    {
      fprintf (errlog, "Error: DH param generator error.\n");
      fprintf (errlog, "err = %d, modlen = %d, randerr = %d\n",
	       err, RE_MODULUS_LEN, RE_NEED_RANDOM);
      return (-1);
    }
  /* Make Key ID */
  R_DigestInit (&context, DA_MD5);
  R_DigestUpdate (&context, DH_parms.prime, sizeof (prime));
  R_DigestUpdate (&context, DH_parms.generator, sizeof (generator));
  R_DigestFinal (&context, ID, &i);

  buff = new_buffer ();
  tmp = DH_parms.primeLen;
  add_to_buffer (buff, &tmp, 1);
  add_to_buffer (buff, DH_parms.prime, DH_parms.primeLen);
  tmp = DH_parms.generatorLen;
  add_to_buffer (buff, &tmp, 1);
  add_to_buffer (buff, DH_parms.generator, DH_parms.generatorLen);
  fprintf (dhfile, "%s\n", begin_key);
  print_ID (dhfile, ID);
  fprintf (dhfile, "%d\n", (int) buff->length);

  /* Armor DH_parms */
  armor (buff);
  write_buffer (buff, dhfile);
  free_buffer (buff);
  fprintf (dhfile, "%s\n", end_key);
  fclose (dhfile);
  mix_unlock ("DH", dhlock);
  return (0);
#else
  /* not implemented */
  return (-1);
#endif
}

int
get_DH (DH_PARAMS * DH_parms)
{
#ifdef USE_RSAREF
  unsigned char line[1024], IDstr[80], line2[1024];
  unsigned char ID[16];
  unsigned int i, len, length, found = 0;
  unsigned char *temp;
  FILE *dhfile;
  FILE *dhlock;
  R_DIGEST_CTX digest_context;
  byte *byteptr;
  BUFFER *buff;

  mix_lock ("DH", &dhlock);
  if ((dhfile = open_mix_file ("DH.mix", "r")) == NULL)
    {
      mix_unlock ("DH", dhlock);
      return (-1);
    }
  while (!found)
    {
      getline (line, sizeof (line), dhfile);
      while (!streq (line, begin_key))
	{
	  if (getline (line, sizeof (line), dhfile) == NULL)
	    {
	      fprintf (errlog, "End of file DH.mix\n");
	      fclose (dhfile);
	      mix_unlock ("DH", dhlock);
	      return (-1);
	    }
	}
      getline (line2, sizeof (line2), dhfile);
      buff = new_buffer ();
      /* read in the length */
      if ((temp = getline (line, 1024, dhfile)) == NULL)
	break;
      sscanf (line, "%d", &length);

      if ((temp = getline (line, sizeof (line), dhfile)) == NULL)
	break;
      while (temp != NULL && !streq (line, end_key))
	{
	  add_to_buffer (buff, line, strlen (line));
	  temp = getline (line, sizeof (line), dhfile);
	}
      temp = malloc (buff->length);	/* Longer than we need */
      if (decode_block (temp, &len, buff->message, buff->length) != 0)
	{
	  fprintf (errlog, "Bad DH.mix format!\n");
	  return (-1);
	}
      free_buffer (buff);
      if (len < length)
	{
	  fprintf (errlog, "Error: recovered DH parameters file is too small!\n");
	  fclose (dhfile);
	  mix_unlock ("DH", dhlock);
	  return (-2);
	}
      /* Rebuild the DH_parms struct */
      byteptr = temp;
      (*DH_parms).primeLen = *byteptr++;
      if ((*DH_parms).primeLen > length)
	{
	  fprintf (errlog, "Error: DH.mix is inconsistent!\n");
	  fclose (dhfile);
	  mix_unlock ("DH", dhlock);
	  return (-2);
	}
      (*DH_parms).prime = malloc ((*DH_parms).primeLen);
      for (i = 0; i < (*DH_parms).primeLen; i++)
	(*DH_parms).prime[i] = *byteptr++;
      (*DH_parms).generatorLen = *byteptr++;
      if ((*DH_parms).primeLen + (*DH_parms).generatorLen > length)
	{
	  fprintf (errlog, "Error: DH.mix is inconsistent!\n");
	  fclose (dhfile);
	  mix_unlock ("DH", dhlock);
	  return (-2);
	}
      (*DH_parms).generator = malloc ((*DH_parms).generatorLen);
      for (i = 0; i < (*DH_parms).generatorLen; i++)
	(*DH_parms).generator[i] = *byteptr++;
      free (temp);

      /* Make Key ID */
      R_DigestInit (&digest_context, DA_MD5);
      R_DigestUpdate (&digest_context, (*DH_parms).prime,
		      (*DH_parms).primeLen);
      R_DigestUpdate (&digest_context, (*DH_parms).generator,
		      (*DH_parms).generatorLen);
      R_DigestFinal (&digest_context, ID, &i);

      encode_ID (IDstr, ID);

      /* compare new ID with saved ID */
      if (memcmp (IDstr, line2, 32) != 0)
	{
	  fprintf (errlog, "Error: DH Parameter IDs do not match!\n");
	  fclose (dhfile);
	  mix_unlock ("DH", dhlock);
	  return (-3);
	}
      found = 1;		/* this will end the loop */
    }
  fclose (dhfile);
  mix_unlock ("DH", dhlock);
  if (found)
    return (0);
  return (1);
#else
  /* not implemented */
  return (1);
#endif
}

long
next_key (FILE * key)
{
  char line[1024];

  do
    {
      if (getline (line, sizeof (line), key) == NULL)
	return -1;
    }
  while (!streq (line, begin_key));
  return ftell (key);
}

int
keyheader (FILE * key, long pos, const char *type, char *value)
{
  char line[1024];

  fseek (key, pos, SEEK_SET);
  do
    {
      if (getline (line, sizeof (line), key) == NULL)
	return -1;
      if (streq (line, end_key))
	return -1;
    }
  while (!strstr (line, type));
  strcpy (value, line + strlen (type));
  chop (value);
  return 0;
}

void
update_keys (FILE * keys)
{
  FILE *privring, *privlock;
  char line[1024];
  long pos;
  unsigned long exp, expmax;
  int sk = 0, pk = 0, tk = 0;

  mix_lock ("secring", &privlock);
  if ((privring = try_open_mix_file (SECRING, "r+")) == NULL)
    mix_unlock ("secring", privlock);
  else
    {
      /* We're a remailer */
      expmax = time (NULL) + KEYOVERLAP * SECONDSPERDAY;
      while ((pos = next_key (privring)) != -1)
	{
	  if (keyheader (privring, pos, KEY_VERSION, line) == -1)
	    pk++;		/* permanent key, old version */
	  if ((keyheader (privring, pos, KEY_TYPE, line) != -1) &&
	      (streq (line, "sig")))
	    sk++;		/* signature key */
	  else if (keyheader (privring, pos, KEY_EXPIRES, line) == -1)
	    pk++;		/* permanent key */
	  else
	    {
	      sscanf (line, "%lu", &exp);
	      if (exp <= (unsigned long) time (NULL))
		{
		  fseek (privring, pos, SEEK_SET);
		  /* OVERWRITE UNTIL END OF KEY */
		}
	      else
		{
		  expmax = exp;
		  tk++;		/* temporary key */
		}
	    }
	}
      fclose (privring);
      mix_unlock ("secring", privlock);

#ifdef NEW
      if (sk == 0)
	generate_key (KEY_TYPE "sig\n");
#endif
      if (pk == 0)
	generate_key ("");

      for (; tk < CREATEKEYS; tk++)
	{
	  sprintf (line, KEY_VALID "%lu\n" KEY_EXPIRES "%lu\n",
		   expmax - KEYOVERLAP * SECONDSPERDAY,
		   expmax + (KEYVALIDITY - KEYOVERLAP) * SECONDSPERDAY);
	  expmax += (KEYVALIDITY - KEYOVERLAP) * SECONDSPERDAY;
	  generate_key (line);
	}
      /* write our public keys to file */
      write_keyfile ();
    }

  if (keys != NULL)
    read_key_file (keys);

  expire_pub_keys ();
}

int
generate_permanent_key (void)
{
  drop_mix_uid ();		/* we don't let other users generate new keys.. */
  fprintf (errlog, "Now making the key. This may take a while.\n");
  return generate_key ("");
}

int
create_sig (BUFFER * data, BUFFER * signature)
{
#ifdef USE_RSAREF
  R_RSA_PRIVATE_KEY sigKey;
  R_SIGNATURE_CTX context;
  unsigned char sig[MAX_SIGNATURE_LEN];
  unsigned int sigLen;

  if (get_priv_key (NULL, &sigKey) != 0)
    return -1;
  R_SignInit (&context, DA_MD5);
  R_SignUpdate (&context, data->message, data->length);
  if (R_SignFinal (&context, sig, &sigLen, &sigKey) != 0)
    {
      fprintf (errlog, "Error: Cannot create signature.\n");
      return (-1);
    }
  add_to_buffer (signature, sig, sigLen);
  return 0;
#else
  /* not implemented */
  return (-1);
#endif
}

int
generate_key (const char *header)
{
  PUBLIC_KEY pubkey;
  PRIVATE_KEY privkey;
  unsigned char line[1024];
  int i, err, len;
  unsigned char iv[8];
  byte digest[16], ID[16], tmpbyte;
  byte des3key[24];
  BUFFER *b1, *encrypted_key;
  FILE *privring, *privlock;
#ifdef USE_RSAREF
  R_DIGEST_CTX digest_context;
  DES3_CBC_CTX context;
  R_RSA_PROTO_KEY protokey;
#else
  B_ALGORITHM_OBJ digest_obj;
  B_ALGORITHM_OBJ des_obj;
  B_ALGORITHM_OBJ gen_obj;
  B_KEY_OBJ key_obj;
  A_RSA_KEY_GEN_PARAMS keypar;
  A_PKCS_RSA_PRIVATE_KEY *keyinfo;
  unsigned char pubexpt[] =
  {1, 0, 1};
#endif

#ifdef DEBUG
  printf ("Generating key:\n%s", header);
#endif
  /* Generate a 1024 bit key with pub exponent = 65537 */
#ifdef USE_RSAREF
  protokey.bits = MIX_RSA_MOD;
  protokey.useFermat4 = 1;
  err = R_GeneratePEMKeys (&pubkey, &privkey, &protokey, &random_obj);
#else
  B_CreateAlgorithmObject (&gen_obj);
  /* Generate a 1024 bit key with pub exponent = 65537 */
  keypar.modulusBits = 1024;
  keypar.publicExponent.data = pubexpt;
  keypar.publicExponent.len = sizeof (pubexpt);
  B_SetAlgorithmInfo (gen_obj, AI_RSAKeyGen, (POINTER) & keypar);
  B_GenerateInit (gen_obj, CHOOSER, NULL);
  B_CreateKeyObject (&pubkey);
  B_CreateKeyObject (&privkey);
  err = (B_GenerateKeypair (gen_obj, pubkey, privkey, random_obj, NULL));
#endif
  if (err != 0)
    {
      fprintf (errlog, "Key generation error.\n");
      return (-1);
    }

#ifdef DEBUG
  printf ("Done.\n");
#endif
  /* put private key in a buffer */
  b1 = new_buffer ();
#ifdef USE_RSAREF
  /* Convert privkey.bits to two bytes */
  i = privkey.bits;
#else
  B_GetKeyInfo ((POINTER *) & keyinfo, privkey, KI_PKCS_RSAPrivate);
  i = keyinfo->modulus.len * 8;
#endif
  tmpbyte = i & 0xFF;
  add_to_buffer (b1, &tmpbyte, 1);	/* low byte of bits */
  tmpbyte = (i / 256) & 0xFF;
  add_to_buffer (b1, &tmpbyte, 1);	/* high byte of bits */

#ifdef USE_RSAREF
  add_to_buffer (b1, privkey.modulus, MAX_RSA_MODULUS_LEN);
  add_to_buffer (b1, privkey.publicExponent, MAX_RSA_MODULUS_LEN);

  /* Make Key ID */
  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, pubkey.modulus, MAX_RSA_MODULUS_LEN);
  R_DigestUpdate (&digest_context, pubkey.exponent, MAX_RSA_MODULUS_LEN);
  R_DigestFinal (&digest_context, ID, &i);

  add_to_buffer (b1, privkey.exponent, MAX_RSA_MODULUS_LEN);
  add_to_buffer (b1, privkey.prime[0], MAX_RSA_PRIME_LEN);
  add_to_buffer (b1, privkey.prime[1], MAX_RSA_PRIME_LEN);
  add_to_buffer (b1, privkey.primeExponent[0], MAX_RSA_PRIME_LEN);
  add_to_buffer (b1, privkey.primeExponent[1], MAX_RSA_PRIME_LEN);
  add_to_buffer (b1, privkey.coefficient, MAX_RSA_PRIME_LEN);
#else
  i = (i + 7) / 8;

  /* Make Key ID */
  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);
  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);

  add_to_buffer (b1, keyinfo->modulus.data, i);

  if (keyinfo->publicExponent.len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->publicExponent.len);
  add_to_buffer (b1, keyinfo->publicExponent.data,
		 keyinfo->publicExponent.len);

  B_DigestUpdate (digest_obj, b1->message + 2,
		  2 * i,
		  NULL);
  B_DigestFinal (digest_obj, ID, &i, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);

  if (keyinfo->privateExponent.len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->privateExponent.len);
  add_to_buffer (b1, keyinfo->privateExponent.data,
		 keyinfo->privateExponent.len);

  i = (i + 1) / 2;

  if (keyinfo->prime[0].len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->prime[0].len);
  add_to_buffer (b1, keyinfo->prime[0].data, keyinfo->prime[0].len);

  if (keyinfo->prime[1].len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->prime[1].len);
  add_to_buffer (b1, keyinfo->prime[1].data, keyinfo->prime[1].len);

  if (keyinfo->primeExponent[0].len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->primeExponent[0].len);
  add_to_buffer (b1, keyinfo->primeExponent[0].data,
		 keyinfo->primeExponent[0].len);

  if (keyinfo->primeExponent[1].len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->primeExponent[1].len);
  add_to_buffer (b1, keyinfo->primeExponent[1].data,
		 keyinfo->primeExponent[1].len);

  if (keyinfo->coefficient.len < i)
    add_to_buffer (b1, NULL,
		   i - keyinfo->coefficient.len);
  add_to_buffer (b1, keyinfo->coefficient.data, keyinfo->coefficient.len);
#endif

  /* Encrypt the secret key */
  encrypted_key = new_buffer ();
  len = b1->length;
  if (len % 8 != 0)		/* ensure length is mult of 8 */
    len += 8 - len % 8;
  add_to_buffer (encrypted_key, malloc (len), len);
  our_randombytes (iv, 8);
#ifdef USE_RSAREF
  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, PASSPHRASE, strlen (PASSPHRASE));
  R_DigestFinal (&digest_context, digest, &i);
  memcpy (des3key, digest, 16);	/* set first 2 keys */
  memcpy (des3key + 16, digest, 8);	/* third key = first key */
  DES3_CBCInit (&context, des3key, iv, 1);
  if (DES3_CBCUpdate (&context, encrypted_key->message, b1->message,
		      encrypted_key->length))
    {
      printf ("Error: Problem encrypting key\n");
      return (-1);
    }
#else
  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);

  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
  B_DigestUpdate (digest_obj, PASSPHRASE, strlen (PASSPHRASE), NULL);
  B_DigestFinal (digest_obj, digest, &i, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);

  memcpy (des3key, digest, 16);	/* set first 2 keys */
  memcpy (des3key + 16, digest, 8);	/* third key = first key */
  B_CreateAlgorithmObject (&des_obj);
  B_SetAlgorithmInfo (des_obj, AI_DES_EDE3_CBC_IV8, iv);
  B_CreateKeyObject (&key_obj);
  B_SetKeyInfo (key_obj, KI_DES24Strong, des3key);
  B_EncryptInit (des_obj, key_obj, CHOOSER, NULL);
  B_EncryptUpdate (des_obj, encrypted_key->message, &len,
		   encrypted_key->length,
		   b1->message, b1->length, random_obj, NULL);
  B_EncryptFinal (des_obj, encrypted_key->message + len,
		  &len, encrypted_key->length - len, random_obj, NULL);
  /* err? XXX */
#endif
  memset ((void *) digest, 0, 16);	/* zero password */

  mix_lock ("secring", &privlock);
  if ((privring = open_mix_file (SECRING, "a+")) == NULL)
    {
      mix_unlock ("secring", privlock);
      return (-1);
    }
  fprintf (privring, "%s\n", begin_key);
  if (strlen (header) > 0)
    {
      fprintf (privring, KEY_VERSION "%s\n", VERSION);
      fprintf (privring, "%s", header);
    }
  print_ID (privring, ID);
  fprintf (privring, "%d\n", len);
  encode_block (line, &i, iv, 8);
  fwrite (line, 1, i, privring);
  fprintf (privring, "\n");

  /* Armor privkey */
  armor (encrypted_key);
  write_buffer (encrypted_key, privring);
  free_buffer (encrypted_key);
  fprintf (privring, "%s\n", end_key);
  fclose (privring);
  mix_unlock ("secring", privlock);
  return 0;
}

int
read_priv_key (FILE * privring, PRIVATE_KEY * privkey,
	       unsigned char *newID)
{
  unsigned char line[1024];
  int i, err, len, length;
  unsigned char iv[20];
  unsigned char *temp, *temp2;
  byte digest[16], *byteptr;
  byte des3key[24];
  BUFFER *buff;
#ifdef USE_RSAREF
  R_DIGEST_CTX digest_context;
  DES3_CBC_CTX context;
#else
  B_ALGORITHM_OBJ digest_obj;
  B_ALGORITHM_OBJ des_obj;
  B_KEY_OBJ key_obj;
  A_PKCS_RSA_PRIVATE_KEY keyinfo;
#endif

  buff = new_buffer ();
  /* read in the length */
  if ((temp = getline (line, sizeof (line), privring)) == NULL)
    return -1;
  sscanf (line, "%d", &length);

  /* Read in iv */
  if (((temp = getline (line, sizeof (line), privring)) == NULL)
      || (decode_block (iv, &len, line, strlen (line))))
    return -1;

  if ((temp = getline (line, sizeof (line), privring)) == NULL)
    return -1;
  while (temp != NULL && !streq (line, end_key))
    {
      add_to_buffer (buff, line, strlen (line));
      temp = getline (line, sizeof (line), privring);
    }
  temp = malloc (buff->length);
  temp2 = malloc (buff->length);
  if (decode_block (temp, &len, buff->message, buff->length) != 0)
    return -1;

  if (len < length)
    {
      fprintf (errlog, "Error: recovered key is too small!\n");
      return (-2);
    }
  /* decrypt key */
#ifdef USE_RSAREF
  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, PASSPHRASE, strlen (PASSPHRASE));
  R_DigestFinal (&digest_context, digest, &i);
  memcpy (des3key, digest, 16);	/* set first 2 keys */
  memcpy (des3key + 16, digest, 8);	/* third key = first key */
  DES3_CBCInit (&context, des3key, iv, 0);
  while (len % 8 != 0)
    len++;			/* align on block boundry */
  err = DES3_CBCUpdate (&context, temp2, temp, len);
#else
  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);

  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
  B_DigestUpdate (digest_obj, PASSPHRASE, strlen (PASSPHRASE), NULL);
  B_DigestFinal (digest_obj, digest, &i, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);

  memcpy (des3key, digest, 16);	/* set first 2 keys */
  memcpy (des3key + 16, digest, 8);	/* third key = first key */
  B_CreateAlgorithmObject (&des_obj);
  B_SetAlgorithmInfo (des_obj, AI_DES_EDE3_CBC_IV8, iv);
  B_CreateKeyObject (&key_obj);
  err = B_SetKeyInfo (key_obj, KI_DES24Strong, des3key);
  B_DecryptInit (des_obj, key_obj, CHOOSER, NULL);
  err = B_DecryptUpdate (des_obj, temp2, &i, len, temp, len, random_obj,
			 NULL);
  B_DecryptFinal (des_obj, temp2 + i, &i, len - i, random_obj, NULL);
  B_DestroyKeyObject (&key_obj);
  B_DestroyAlgorithmObject (&des_obj);
#endif

  if (err)
    {
      printf ("Error: Problem decrypting key %x\n", err);
      return (-1);
    }
  memset ((void *) digest, 0, 16);	/* zero password */
  free (temp);

  /* Rebuild privkey */
  byteptr = temp2;
  i = *byteptr++;
  i += (*byteptr++ * 256);

#ifdef USE_RSAREF
  (*privkey).bits = i;

  for (i = 0; i < MAX_RSA_MODULUS_LEN; i++)
    (*privkey).modulus[i] = *byteptr++;
  for (i = 0; i < MAX_RSA_MODULUS_LEN; i++)
    (*privkey).publicExponent[i] = *byteptr++;
  for (i = 0; i < MAX_RSA_MODULUS_LEN; i++)
    (*privkey).exponent[i] = *byteptr++;
  for (i = 0; i < MAX_RSA_PRIME_LEN; i++)
    (*privkey).prime[0][i] = *byteptr++;
  for (i = 0; i < MAX_RSA_PRIME_LEN; i++)
    (*privkey).prime[1][i] = *byteptr++;
  for (i = 0; i < MAX_RSA_PRIME_LEN; i++)
    (*privkey).primeExponent[0][i] = *byteptr++;
  for (i = 0; i < MAX_RSA_PRIME_LEN; i++)
    (*privkey).primeExponent[1][i] = *byteptr++;
  for (i = 0; i < MAX_RSA_PRIME_LEN; i++)
    (*privkey).coefficient[i] = *byteptr++;
  free (temp2);

  /* Make Key ID */
  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, privkey->modulus, MAX_RSA_MODULUS_LEN);
  R_DigestUpdate (&digest_context, privkey->publicExponent, MAX_RSA_MODULUS_LEN);
  R_DigestFinal (&digest_context, newID, &i);
#else
  i = (i + 7) / 8;
  if (i < MAX_RSA_MODULUS_LEN)
    i = MAX_RSA_MODULUS_LEN;

  keyinfo.modulus.len = i;
  keyinfo.publicExponent.len = i;
  keyinfo.privateExponent.len = i;
  keyinfo.prime[0].len = (i + 1) / 2;
  keyinfo.prime[1].len = (i + 1) / 2;
  keyinfo.primeExponent[0].len = (i + 1) / 2;
  keyinfo.primeExponent[1].len = (i + 1) / 2;
  keyinfo.coefficient.len = (i + 1) / 2;

  keyinfo.modulus.data = malloc (keyinfo.modulus.len);
  memcpy (keyinfo.modulus.data, byteptr, keyinfo.modulus.len);
  byteptr += keyinfo.modulus.len;

  keyinfo.publicExponent.data = malloc (keyinfo.publicExponent.len);
  memcpy (keyinfo.publicExponent.data, byteptr, keyinfo.publicExponent.len);
  byteptr += keyinfo.publicExponent.len;

  keyinfo.privateExponent.data = malloc (keyinfo.privateExponent.len);
  memcpy (keyinfo.privateExponent.data, byteptr, keyinfo.privateExponent.len);
  byteptr += keyinfo.privateExponent.len;

  keyinfo.prime[0].data = malloc (keyinfo.prime[0].len);
  memcpy (keyinfo.prime[0].data, byteptr, keyinfo.prime[0].len);
  byteptr += keyinfo.prime[0].len;

  keyinfo.prime[1].data = malloc (keyinfo.prime[1].len);
  memcpy (keyinfo.prime[1].data, byteptr, keyinfo.prime[1].len);
  byteptr += keyinfo.prime[1].len;

  keyinfo.primeExponent[0].data = malloc (keyinfo.primeExponent[0].len);
  memcpy (keyinfo.primeExponent[0].data, byteptr,
	  keyinfo.primeExponent[0].len);
  byteptr += keyinfo.primeExponent[0].len;

  keyinfo.primeExponent[1].data = malloc (keyinfo.primeExponent[1].len);
  memcpy (keyinfo.primeExponent[1].data, byteptr,
	  keyinfo.primeExponent[1].len);
  byteptr += keyinfo.primeExponent[1].len;

  keyinfo.coefficient.data = malloc (keyinfo.coefficient.len);
  memcpy (keyinfo.coefficient.data, byteptr, keyinfo.coefficient.len);

  B_CreateKeyObject (privkey);
  B_SetKeyInfo (*privkey, KI_PKCS_RSAPrivate, (POINTER) & keyinfo);

  /* Make Key ID */
  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);

  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
  B_DigestUpdate (digest_obj, keyinfo.modulus.data, keyinfo.modulus.len, NULL);
  B_DigestUpdate (digest_obj, keyinfo.publicExponent.data,
		  keyinfo.publicExponent.len, NULL);
  B_DigestFinal (digest_obj, newID, &i, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);
  free (keyinfo.modulus.data);
  free (keyinfo.publicExponent.data);
  free (keyinfo.privateExponent.data);
  free (keyinfo.prime[0].data);
  free (keyinfo.prime[1].data);
  free (keyinfo.primeExponent[0].data);
  free (keyinfo.primeExponent[1].data);
  free (keyinfo.coefficient.data);
  free (temp2);
#endif
  return 0;
}

int
get_priv_key (unsigned char *ID, PRIVATE_KEY * privkey)
{
  /* return key ID, or signature key if ID == NULL */
  unsigned char line[1024], IDstr[80];
  unsigned char newID[16];
  int found = 0;
  FILE *privring;
  FILE *privlock;
  unsigned long t;

  if (ID != NULL)
    encode_ID (IDstr, ID);
  mix_lock ("secring", &privlock);
  if ((privring = open_mix_file (SECRING, "r")) == NULL)
    {
      mix_unlock ("secring", privlock);
      return (-1);
    }
  while (!found)
    {
      getline (line, sizeof (line), privring);
      while (!streq (line, begin_key))
	{
	  if (getline (line, sizeof (line), privring) == NULL)
	    {
	      fclose (privring);
	      mix_unlock ("secring", privlock);
	      goto notfound;
	    }
	}
      getline (line, sizeof (line), privring);
      /* THIS SHOULD NOT RELY ON THE ORDER OF THE LINES ** */
      if (strstr (line, KEY_VERSION))
	getline (line, sizeof (line), privring);
      if (strstr (line, KEY_VALID))
	{
	  sscanf (line, KEY_VALID "%lu", &t);
	  if ((unsigned long) time (NULL) < t)
	    continue;		/* don't use keys that aren't currently valid */
	}
      if (strstr (line, KEY_EXPIRES))
	{
	  sscanf (line, KEY_EXPIRES "%lu", &t);
	  if (t < (unsigned long) time (NULL))
	    continue;
	}
      if ((ID != NULL) && strstr (line, KEY_TYPE) && strstr (line, "sig"))
	continue;		/* use sig key only if asked */

      if ((ID != NULL && strstr (line, IDstr)) ||
	  ((ID == NULL) && strstr (line, KEY_TYPE) && strstr (line, "sig")))
	{
	  /* we use this key if the ID matches or it is the sig key we need */

	  if (strstr (line, "sig"))
	    getline (line, sizeof (line), privring);	/* read and drop ID */

	  if (read_priv_key (privring, privkey, newID) != 0)
	    break;
	  /* compare new ID with passed ID */
	  if ((ID != NULL) && (memcmp (ID, newID, 16) != 0))
	    {
	      fprintf (errlog, "Error: Private Key IDs do not match!  Bad passphrase?\n");
	      break;
	    }
	  found = 1;		/* this will end the loop */
	}
    }
  fclose (privring);
  mix_unlock ("secring", privlock);
  if (found)
    return (0);
notfound:
  if (ID == NULL)
    fprintf (errlog, "Unable to get signature key!\n");
  else
    fprintf (errlog, "Unable to get private key %s!\n", IDstr);
  return (1);
}

void
write_keyfile (void)
{
  /* read the public keys from secring.mix... */
  FILE *privring, *privlock;
  FILE *keyfile, *keylock, *keyinfo;
  BUFFER *b1, *buff, *header;
#ifdef NEW
  BUFFER *signature;
#endif
  char line[1024], IDstr[80];
  long pos;
  int i, len;
  byte tmpbyte;
  PRIVATE_KEY privkey;
  unsigned char ID[16];
  char abilities[256] = "";
#ifndef USE_RSAREF
  A_PKCS_RSA_PRIVATE_KEY *pkinfo;
#endif

  our_abilities (abilities);

  mix_lock ("secring", &privlock);
  if ((privring = open_mix_file (SECRING, "r+")) == NULL)
    {
      mix_unlock ("secring", privlock);
      return;
    }

  buff = new_buffer ();
#ifdef NEW
  str_to_buffer (buff, begin_signed);
  str_to_buffer (buff, "\n");
#endif
  while ((pos = next_key (privring)) != -1)
    {
      header = new_buffer ();

      for (;;)			/* copy the header and to a buffer */
	{
	  getline (line, sizeof (line), privring);
	  if (!strstr (line, ": "))
	    break;
	  str_to_buffer (header, line);
	}
      if (read_priv_key (privring, &privkey, ID) != 0)
	break;
      encode_ID (IDstr, ID);
      if (memcmp (line, IDstr, 32) != 0)
	{
	  fprintf (errlog, "Error: Private Key IDs do not match!  Bad passphrase?\n");
	  fclose (privring);
	  mix_unlock ("secring", privlock);
	  exit (-1);
	}

      /* write key to buff */
      if (header->length == 0)
	{			/* old format */
	  sprintf (line, "%s %s ", SHORTNAME, REMAILERADDR);
	  str_to_buffer (buff, line);
	  str_to_buffer (buff, IDstr);
	  str_to_buffer (buff, " ");
	  str_to_buffer (buff, mixmaster_protocol);
	  str_to_buffer (buff, VERSION);
	  str_to_buffer (buff, " ");
	  str_to_buffer (buff, abilities);
	  str_to_buffer (buff, "\n\n");
	  str_to_buffer (buff, begin_key);
	  str_to_buffer (buff, "\n");
	}
      else
	{
	  str_to_buffer (buff, begin_key);
	  str_to_buffer (buff, "\n");
	  add_to_buffer (buff, header->message, header->length);
	}
      str_to_buffer (buff, IDstr);
      str_to_buffer (buff, "\n");
      free_buffer (header);

      /* Armor pubkey */
      b1 = new_buffer ();
#ifdef USE_RSAREF
      /* Convert pubkey.bits to two bytes */
      i = privkey.bits;
#else
      B_GetKeyInfo ((POINTER *) & pkinfo, privkey, KI_PKCS_RSAPrivate);
      i = pkinfo->modulus.len * 8;
#endif
      tmpbyte = i & 0xFF;
      add_to_buffer (b1, &tmpbyte, 1);	/* low byte of bits */
      i = i / 256;
      tmpbyte = i & 0xFF;
      add_to_buffer (b1, &tmpbyte, 1);	/* high byte of bits */

#ifdef USE_RSAREF
      add_to_buffer (b1, privkey.modulus, MAX_RSA_MODULUS_LEN);
      add_to_buffer (b1, privkey.publicExponent, MAX_RSA_MODULUS_LEN);
#else
      add_to_buffer (b1, pkinfo->modulus.data, pkinfo->modulus.len);
      if (pkinfo->publicExponent.len < pkinfo->modulus.len)
	add_to_buffer (b1, NULL,
		       pkinfo->modulus.len - pkinfo->publicExponent.len);
      add_to_buffer (b1, pkinfo->publicExponent.data,
		     pkinfo->publicExponent.len);
#endif
      len = b1->length;
      while ((b1->length % 3) != 0)
	str_to_buffer (b1, "X");

      sprintf (line, "%d\n", len);
      str_to_buffer (buff, line);
      armor (b1);
      add_to_buffer (buff, b1->message, b1->length);
      free_buffer (b1);
      str_to_buffer (buff, end_key);
      str_to_buffer (buff, "\n");
    }
  fclose (privring);
  mix_unlock ("secring", privlock);

#ifdef NEW
  str_to_buffer (buff, begin_cfg);
  sprintf (line, "\n%s%s\n", KEY_VERSION, VERSION);
  str_to_buffer (buff, line);
  sprintf (line, "%s%s\n", CFG_REMAILER, SHORTNAME);
  str_to_buffer (buff, line);
  sprintf (line, "%s%s\n", CFG_ADDRESS, REMAILERADDR);
  str_to_buffer (buff, line);
  sprintf (line, "%s%s\n", CFG_ABILITIES, abilities);
  str_to_buffer (buff, line);
  sprintf (line, "%s%lu\n", CFG_DATE, (unsigned long) time (NULL));
  str_to_buffer (buff, line);
  str_to_buffer (buff, end_cfg);

  signature = new_buffer ();
  create_sig (buff, signature);
  armor (signature);
  str_to_buffer (buff, "\n");
  str_to_buffer (buff, begin_signature);
  str_to_buffer (buff, "\n");
  add_to_buffer (buff, signature->message, signature->length);
  str_to_buffer (buff, end_signature);
#endif

  mix_lock ("key", &keylock);
  if ((keyinfo = open_mix_file (KEYINFO, "r")) == NULL ||
      (keyfile = open_mix_file (KEYFILE, "w")) == NULL)
    {
      mix_unlock ("key", keylock);
      return;
    }
  while (getline (line, sizeof (line), keyinfo) != NULL)
    fprintf (keyfile, "%s\n", line);
  fclose (keyinfo);
  write_buffer (buff, keyfile);
  fclose (keyfile);
  mix_unlock ("key", keylock);
  free_buffer (buff);
}

int
get_pub_key (unsigned char *ID, PUBLIC_KEY * pubkey)
{
  /* must return key id and algorithm identifier */
  unsigned char line[1024], IDstr[80];
  unsigned char newID[16];
  int found = 0;
  FILE *pubring;
  FILE *publock;

  encode_ID (IDstr, ID);
  mix_lock ("pubring", &publock);
  if ((pubring = open_mix_file (PUBRING, "r")) == NULL)
    {
      mix_unlock ("pubring", publock);
      return (-1);
    }

  while (!found)
    {
      getline (line, sizeof (line), pubring);
      while (!streq (line, begin_key))
	{
	  if (getline (line, sizeof (line), pubring) == NULL)
	    {
	      fprintf (errlog, "End of file pubring.mix\n");
	      fclose (pubring);
	      mix_unlock ("pubring", publock);
	      return (-1);
	    }
	}
      getline (line, sizeof (line), pubring);
      if (strstr (line, IDstr))
	{
	  read_pub_key (pubring, pubkey, newID);
	  /* compare new ID with passed ID */
	  if (memcmp (ID, newID, 16) != 0)
	    {
	      fprintf (errlog, "Error: Public Key IDs do not match!\n");
	      break;
	    }
	  found = 1;		/* this will end the loop */
	}
    }
  fclose (pubring);
  mix_unlock ("pubring", publock);
  if (found)
    return (0);
  return (1);
}

int
read_pub_key (FILE * pubring, PUBLIC_KEY * pubkey,
	      unsigned char *newID)
{
  unsigned char line[1024];
  int i, len, length;
  unsigned char *temp;
  byte *byteptr;
  BUFFER *buff;
#ifdef USE_RSAREF
  R_DIGEST_CTX digest_context;
#else
  B_ALGORITHM_OBJ digest_obj;
  A_RSA_KEY keyinfo;
#endif

  buff = new_buffer ();
  /* read in the length */
  if ((temp = getline (line, sizeof (line), pubring)) == NULL)
    return -1;
  sscanf (line, "%d", &length);

  if ((temp = getline (line, sizeof (line), pubring)) == NULL)
    return -1;
  while (temp != NULL && !streq (line, end_key))
    {
      add_to_buffer (buff, line, strlen (line));
      temp = getline (line, sizeof (line), pubring);
    }
  temp = malloc (buff->length);	/* Longer than we need */
  if (decode_block (temp, &len, buff->message, buff->length) != 0)
    {
      fprintf (errlog, "Error: Malformatted key!\n");
      return (-2);
    }
  free_buffer (buff);
  if (len < length)
    {
      fprintf (errlog, "Error: recovered key is too small!\n");
      return (-2);
    }
  byteptr = temp;
  i = *byteptr++;
  i += (*byteptr++ * 256);
#ifdef USE_RSAREF
  if ((i + 7) / 8 > MAX_RSA_MODULUS_LEN)
    {
      fprintf (errlog, "Keysize not supported by RSAREF.\n");
      return (-1);
    }
  (*pubkey).bits = i;
  for (i = 0; i < MAX_RSA_MODULUS_LEN; i++)
    (*pubkey).modulus[i] = *byteptr++;
  for (i = 0; i < MAX_RSA_MODULUS_LEN; i++)
    (*pubkey).exponent[i] = *byteptr++;
#else
  keyinfo.modulus.len = (i + 7) / 8;
  if (keyinfo.modulus.len < MAX_RSA_MODULUS_LEN)
    keyinfo.modulus.len = MAX_RSA_MODULUS_LEN;
  keyinfo.exponent.len = keyinfo.modulus.len;

  keyinfo.modulus.data = malloc (keyinfo.modulus.len);
  memcpy (keyinfo.modulus.data, byteptr, keyinfo.modulus.len);
  byteptr += keyinfo.modulus.len;

  keyinfo.exponent.data = malloc (keyinfo.exponent.len);
  memcpy (keyinfo.exponent.data, byteptr, keyinfo.exponent.len);

  B_CreateKeyObject (pubkey);
  B_SetKeyInfo (*pubkey, KI_RSAPublic, (POINTER) & keyinfo);
#endif
  free (temp);

  /* Make Key ID */
#ifdef USE_RSAREF
  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, (*pubkey).modulus,
		  MAX_RSA_MODULUS_LEN);
  R_DigestUpdate (&digest_context, (*pubkey).exponent,
		  MAX_RSA_MODULUS_LEN);
  R_DigestFinal (&digest_context, newID, &i);
#else
  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);

  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
  B_DigestUpdate (digest_obj, keyinfo.modulus.data, keyinfo.modulus.len, NULL);
  B_DigestUpdate (digest_obj, keyinfo.exponent.data, keyinfo.exponent.len,
		  NULL);
  B_DigestFinal (digest_obj, newID, &i, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);
  free (keyinfo.modulus.data);
  free (keyinfo.exponent.data);
#endif
  return 0;
}

#ifdef NEW
verify_sig ()
{
}

get_permanent_pub_key ()
{
}

get_pub_sig_key ()
{
}

#endif

int
read_key_file (FILE * f)
{
  return 0;
}

void
expire_pub_keys (void)
{
}
