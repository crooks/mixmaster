
/* $Id: type2.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: type2.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.20  1999/01/19  02:28:13  um
 * *** empty log message ***
 *
 * Revision 2.19  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.18  1998/05/25  01:20:53  um
 * fixed sign error in check_packetID.
 *
 * Revision 2.17  1998/05/11  19:43:16  um
 * *** empty log message ***
 *
 * Revision 2.16  1998/05/10  22:16:21  um
 * Bug fix in timestamp code.
 *
 * Revision 2.15  1998/05/07  23:59:36  um
 * Format extension: timestamps in messages.
 *
 * Revision 2.14  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.13  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 * Revision 2.12  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 * Revision 2.11  1998/02/17  23:25:41  um
 * Check R_DecodePEMBlock return values.
 *
 * Revision 2.10  1998/01/31  01:31:08  um
 * removed misleading comment.
 *
 * Revision 2.9  1998/01/28  20:59:44  um
 *
 * type2.c           1997-11-08 um
 *     new function type2_dec, called from type_2.
 *
 * type2.c           1997-10-05 um
 *     DOS: empty lines of top of output file, for backward compatibility
 *      with old PI versions.
 *
 * type2.c           1997-09-17 um
 *     queue_msg bug fix.
 *
 * type2.c           1997-09-02 um
 *     additinal destination for queue_message.
 *
 * type2.c           1997-08-29 um
 *     "To: " line is added at the same time for client and remailer.
 *
 * type2.c           1997-08-26 um
 *     new option -Q to add messages to the remailer queue.
 *
 * type2.c           1997-08-17 JK
 * type2.c           1997-07-15 um
 * type2.c           1997-07-11 ad
 *     new fromanon() function for writing the From: line
 *     on anonymous messages: ANONNAME <ANONADDR>
 *
 * type2.c           1997-07-06 um
 *     DISCLAIMER definition in mixmaster.h.
 *
 * type2.c           1997-07-01 um
 *     middleman patch (disclaimer bug fixed).
 *
 * type2.c           1997-06-16 um
 *     bug fix: write intermediate hop with mix_uid
 *
 * type2.c           1997-06-14 um
 *     new disclaimer.
 *     variable name packet_type introduced for readability.
 *
 * type2.c           1997-05-30 um
 *
 * type2.c       2.7 1996-11-27 um
 *     check numdest and numsub in incoming packets.
 *     double To: line fixed.
 *     new function send_message
 *     moved chaining code to chain2.c
 *
 *     modified for DOS.
 *     applied Lance's patch: remailers can be selected by name.
 *
 * type2.c        2.6 11/2/95
 *      Destination and subject fields filled out
 *      with nulls to ensure no leakage of information.
 *      new command line flag -O.
 *        same as -o but puts a "To: " line at the top
 *
 * type2.c        2.5 9/20/95
 *      Remailer choice of 0 causes mixmaster to choose a remailer
 *      at random from type2.list
 *
 * type2.c        2.4 9/10/95
 *      Change sendmail calls to use To: in body, not command line.
 *
 *
 * type2.c        2.3 5/10/95
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/file.h>
#include <assert.h>

int
merge_packets (BUFFER * body, byte * messageID,
	       byte packet, byte numpackets)
{
  char line[1024];
  char filename[256];
  FILE *new, *old, *out;
  int i, j, tmpint;
  unsigned char fileID[16], tmparray[256];
  long int length, seconds;
  byte len[4], tmp, *byteptr, arrived;
  char foo[256];

  /* open mail file */
  sprintf (filename, "pac%02x%02x%02x%02x%02x%02x",
	   messageID[0], messageID[1], messageID[2], messageID[3],
	   messageID[4], messageID[5]);

  if ((old = try_open_mix_file (filename, "rb+")) != NULL)
    {				/* if file exists */
      strcpy (foo, "tmp1");
      out = tempfileb (foo);
      fread (tmparray, 4, 1, old);	/* dump old time stamp */
      fread (fileID, 16, 1, old);
      /* Check message ID */
      if (memcmp (fileID, messageID, 16) != 0)
	{
	  fprintf (errlog, "messageID does not match fileID!\n");
	  fclose (old);
	  fclose (out);
	  unlink (foo);
	  return (-2);
	}
      seconds = time (NULL);
      tmparray[0] = seconds & 0xFF;	/* low byte */
      seconds = seconds / 256;
      tmparray[1] = seconds & 0xFF;	/* second */
      seconds = seconds / 256;
      tmparray[2] = seconds & 0xFF;	/* third */
      seconds = seconds / 256;
      tmparray[3] = seconds & 0xFF;	/* high byte */

      fwrite (tmparray, 4, 1, out);	/* write new timestamp */
      fwrite (messageID, 16, 1, out);

      fread (&numpackets, 1, 1, old);
      fwrite (&numpackets, 1, 1, out);

      fread (&arrived, 1, 1, old);
      arrived++;
      fwrite (&arrived, 1, 1, out);

      fread (&tmp, 1, 1, old);	/* get packet number */
      j = 1;
      while (tmp < packet && j < arrived)
	{
	  j++;			/* this keeps us from running off the end of the file */
	  fwrite (&tmp, 1, 1, out);
	  fread (len, 4, 1, old);
	  fwrite (len, 4, 1, out);
	  length = len[3];
	  length = length * 256 + len[2];
	  length = length * 256 + len[1];
	  length = length * 256 + len[0];

	  /* move the this packet to the out file */
	  while (length > 0)
	    {
	      tmpint = length % 1024;
	      if (tmpint == 0)
		tmpint = 1024;
	      fread (line, tmpint, 1, old);
	      fwrite (line, tmpint, 1, out);
	      length -= tmpint;
	    }
	  fread (&tmp, 1, 1, old);	/* get next packet number */
	}

      if (tmp == packet)
	{
	  fprintf (errlog, "Problem! Packet number collision!\n");
	  fclose (old);
	  fclose (out);
	  unlink (foo);
	  return (-4);
	}
      /* put the new packet in the out file */
      fwrite (&packet, 1, 1, out);
      byteptr = body->message;
      fwrite (byteptr, 4, 1, out);	/* write the length */
      length = byteptr[3];
      length = length * 256 + byteptr[2];
      length = length * 256 + byteptr[1];
      length = length * 256 + byteptr[0];
      fwrite ((body->message) + 4, length, 1, out);

      while (j < arrived)
	{
	  j++;			/* this keeps us from running off the end of the file */
	  fwrite (&tmp, 1, 1, out);
	  fread (len, 4, 1, old);
	  fwrite (len, 4, 1, out);
	  length = len[3];
	  length = length * 256 + len[2];
	  length = length * 256 + len[1];
	  length = length * 256 + len[0];
	  /* move the this packet to the out file */
	  while (length > 0)
	    {
	      tmpint = length % 1024;
	      if (tmpint == 0)
		tmpint = 1024;
	      fread (line, tmpint, 1, old);
	      fwrite (line, tmpint, 1, out);
	      length -= tmpint;
	    }
	  fread (&tmp, 1, 1, old);
	}
      fclose (old);
      if (arrived < numpackets)
	{
	  if ((new = open_mix_file (filename, "wb")) == NULL)
	    return (-3);
	  /* move the this packet to the out file */
	  rewind (out);
	  while ((length = fread (line, 1, sizeof (line), out)) > 0)
	    {
	      fwrite (line, length, 1, new);
	    }
	  fclose (out);
	  unlink (foo);
	  fclose (new);
	  if (VERBOSE)
	    fprintf(errlog, "Succeeded storing partial message.\n");
	}
      else
	{			/* we have the whole message now */
	  unlink (filename);
	  strcpy (filename, "tmp2");
	  new = tempfileb (filename);
	  rewind (out);
	  fread (tmparray, 1, 4, out);	/* dump time stamp */

	  fread (fileID, 1, 16, out);
	  fread (&numpackets, 1, 1, out);
	  fread (&arrived, 1, 1, out);
	  for (i = 1; i <= numpackets; i++)
	    {
	      fread (&tmp, 1, 1, out);
	      fread (len, 1, 4, out);
	      length = len[3];
	      length = length * 256 + len[2];
	      length = length * 256 + len[1];
	      length = length * 256 + len[0];
	      /* move the this packet to the out file */
	      while (length > 0)
		{
		  tmpint = length % 1024;
		  if (tmpint == 0)
		    tmpint = 1024;
		  fread (line, tmpint, 1, out);
		  fwrite (line, tmpint, 1, new);
		  length -= tmpint;
		}
	    }
	  fclose (out);
	  unlink (foo);		/* out file */

	  /* ok, whole message is in new now */
	  rewind (new);
	  send_message (new, NULL, 0);
	  unlink (filename);	/* tmp file */
	  fclose (new);
	}
    }
  else
    {
      /* The file did not exist */
      /* this is a new message */
      if ((out = open_mix_file (filename, "wb")) == NULL)
	return (-3);
      seconds = time (NULL);
      /*          tmparray[0]= seconds % 256; */
      tmparray[0] = seconds & 0xFF;	/* low byte */
      seconds = seconds / 256;
      /*          tmparray[1]= seconds % 256; */
      tmparray[1] = seconds & 0xFF;	/* second */
      seconds = seconds / 256;
      /*          tmparray[2]= seconds % 256; */
      tmparray[2] = seconds & 0xFF;	/* third */
      seconds = seconds / 256;
      /*          tmparray[3]= seconds % 256; */
      tmparray[3] = seconds & 0xFF;	/* high byte */

      fwrite (tmparray, 4, 1, out);	/* write new timestamp */
      fwrite (messageID, 16, 1, out);

      fwrite (&numpackets, 1, 1, out);
      tmp = 1;
      fwrite (&tmp, 1, 1, out);	/* first message part */

      /* put the new packet in the out file */
      fwrite (&packet, 1, 1, out);	/* which part is this */
      byteptr = body->message;
      fwrite (byteptr, 4, 1, out);
      length = byteptr[3];
      length = length * 256 + byteptr[2];
      length = length * 256 + byteptr[1];
      length = length * 256 + byteptr[0];
      fwrite ((body->message) + 4, length, 1, out);
      fclose (out);
      if (VERBOSE)
	fprintf(errlog, "Succeeded storing partial message.\n");
    }
  return (0);
}

/* returns 1 if no ID number conflict. 0 if there is */
int
check_packetID (byte * ID, unsigned char *timestamp)
{
  FILE *fptr, *lockptr;
  char line[256], temp[256];
  long then, now;

  now = time (NULL);
  
  then = (timestamp[0] + 256 * timestamp[1]) * SECONDSPERDAY;
  if (then == 0)
    {
      if (VERBOSE)
	fprintf(errlog, "Ignoring message without timestamp.\n");
      return(0);
    }
  if (then > now)
    {
      if (VERBOSE)
	fprintf(errlog, "Ignoring message with future timestamp.\n");
      return (0);
    }
  if (then > 0 && now - then > IDEXP * 3600)
    {
      if (VERBOSE)
	fprintf(errlog, "Ignoring old message.\n");
      return (0);
    }
  mix_lock (IDLOG, &lockptr);
  if ((fptr = try_open_mix_file (IDLOG, "r+")) == NULL)
    {
      mix_unlock (IDLOG, lockptr);
      return (1);
    }
  encode_ID (line, ID);
  while (getline (temp, sizeof (temp), fptr) != NULL)
    {
      if (strstr (temp, line))
	{			/* if ID number is found */
	  fclose (fptr);
	  mix_unlock (IDLOG, lockptr);
	  if (VERBOSE)
	    fprintf(errlog, "Ignoring redundant message.\n");
	  return (0);
	}
    }
  /* ID number is new */
  fprintf (fptr, "%s %lu \n", line, now);
  mix_unlock (IDLOG, lockptr);
  fclose (fptr);
  return (1);
}

/* Encrypts/decrypts buffer back to the buffer. */
/* The length of the buffer must be a multiple of 8 */
int
crypt_in_buffer (unsigned char *key, unsigned char *iv,
		 BUFFER * buff, int encrypt)
     /* unsigned char *key,*iv;   key is 24 long and iv is 8 long */
     /* int     encrypt;    1 = encrypt, 0 = decrypt */
{
#ifdef USE_RSAREF
  BUFFER *tmp;
  byte *ptr, line[1024];
  int i, j, len;
  int flag = 0;
  DES3_CBC_CTX des_context;

  if (buff->length % 8)
    return (1);

  DES3_CBCInit (&des_context, key, iv, encrypt);

  tmp = new_buffer ();
  i = buff->length;
  len = i;			/* we want the same length a the end */
  ptr = buff->message;
  while (i > 0)
    {
      j = (i % 1024);
      if (j == 0)
	j = 1024;

      if ((flag = DES3_CBCUpdate (&des_context, line, ptr, j)) != 0)
	break;
      add_to_buffer (tmp, line, j);
      ptr += j;
      i -= j;
    }
  clear_buffer (buff);
  add_to_buffer (buff, tmp->message, len);
  free_buffer (tmp);
  return (flag);
#else
  byte *tmp;
  int len, tmplen;
  B_ALGORITHM_OBJ des_context;
  B_KEY_OBJ key_obj;

  B_CreateAlgorithmObject (&des_context);
  B_SetAlgorithmInfo (des_context, AI_DES_EDE3_CBC_IV8, iv);
  B_CreateKeyObject (&key_obj);
  B_SetKeyInfo (key_obj, KI_DES24Strong, key);
  if (encrypt)
    B_EncryptInit (des_context, key_obj, CHOOSER, NULL);
  else
    B_DecryptInit (des_context, key_obj, CHOOSER, NULL);

  len = buff->length;
  tmp = malloc (len);

  if (encrypt)
    B_EncryptUpdate (des_context, tmp, &tmplen, len, buff->message,
		     len, random_obj, NULL);
  else
    B_DecryptUpdate (des_context, tmp, &tmplen, len, buff->message,
		     len, random_obj, NULL);

  if (encrypt)
    B_EncryptFinal (des_context, tmp + tmplen, &tmplen, len - tmplen,
		    random_obj, NULL);
  else
    B_DecryptFinal (des_context, tmp + tmplen, &tmplen, len - tmplen,
		    random_obj, NULL);

  B_DestroyKeyObject (&key_obj);
  B_DestroyAlgorithmObject (&des_context);

  clear_buffer (buff);
  add_to_buffer (buff, tmp, len);

  return 0;
#endif
}

/*
 * the first line that needs to be worried
 * about contains "Remailer-Type:"
 */
int
type_2 (char *tmpfile)
{
  BUFFER *b1;
  char line[1024], line2[1024];
  int len;
  FILE *fptr;
  byte digest[20];

  if ((fptr = open_mix_file (tmpfile, "r")) == NULL)
    return (-1);

  /* first off, de-armor the file */
  while (getline (line, sizeof (line), fptr) != NULL)
    {
      if (streq (line, begin_remailer))
	break;
    }
  if (!streq (line, begin_remailer))
    {				/* did we find begin? */
      fprintf (errlog, "Did not find begin_remailer\n");
      fclose (fptr);
      return (-1);
    }
  getline (line, sizeof (line), fptr);	/* length of de-armored message */

  /* get the checksum line */
  if (getline (line, sizeof (line), fptr) == NULL)
    {
      fclose (fptr);
      return (-1);
    }
  if (decode_block (digest, &len, line, strlen (line)) != 0)
    {
      fprintf (errlog, "Malformatted message!\n");
      fclose (fptr);
      return (-1);
    }

  b1 = new_buffer ();
  while (getline (line, sizeof (line), fptr) != NULL)
    {
      if (streq (line, end_remailer))
	break;
      if (decode_block (line2, &len, line, strlen (line)) != 0)
	break;
      add_to_buffer (b1, line2, len);
    }
  fclose (fptr);

  return (type2_dec (b1, digest));
}

int
type2_dec (BUFFER * b1, byte * digest)
{
  BUFFER *headers[21], *body;
  char address[80];
  char line[1024];
  int i, len, keylen;
  FILE *fptr, *lockptr;
  byte innerkey[24], ivarray[NUM_IV][8];
  byte tmpbyte, packet, numpackets;
  byte new_digest[20];
  byte key[MAX_ENCRYPTED_KEY_LEN], packetID[16], timestamp[2] = "\0\0", iv[8];
  byte messageID[16], *byteptr;
  long int length;
  PRIVATE_KEY privkey;
  byte packet_type;
#ifdef USE_RSAREF
  R_ENVELOPE_CTX rsa_context;
#else
  B_ALGORITHM_OBJ rsa_context;
  B_ALGORITHM_OBJ des_context;
  B_KEY_OBJ des_key;
#endif

  if (b1->length < 20480)
    {
      fprintf (errlog, "Malformatted message!\n");
      return (-1);
    }
  else
    b1->length = 20480;

  make_digest (b1, new_digest);

  if (memcmp (digest, new_digest, 16) != 0)
    {
      fprintf (errlog, "Message checksum does not match!\n");
      return (-1);
    }
  for (i = 0; i < HOPMAX; i++)
    {				/* the current first header will be removed */
      headers[i] = new_buffer ();
      add_to_buffer (headers[i], b1->message + (i * HEADERSIZE), HEADERSIZE);
    }
  /* copy the first header to the end */
  headers[HOPMAX] = new_buffer ();
  add_to_buffer (headers[HOPMAX], headers[0]->message, headers[0]->length);

  body = new_buffer ();
  add_to_buffer (body, b1->message + (HOPMAX * HEADERSIZE), PACKETSIZE + 4);
  reset_buffer (b1);

  /* decrypt top header */
  byteptr = headers[0]->message;
  if (get_priv_key (byteptr, &privkey) != 0)
    return (-1);
  byteptr += 16;
  tmpbyte = *byteptr;
  keylen = tmpbyte;
  byteptr++;
  memcpy (key, byteptr, keylen);
  byteptr += keylen;
  memcpy (iv, byteptr, 8);
  byteptr += 8;
#ifdef USE_RSAREF
  if ((i = R_OpenInit (&rsa_context, EA_DES_EDE3_CBC, key, keylen, iv,
		       &privkey)) != 0)
    {
      fprintf (errlog, "R_OpenInit error #%d", i);
      return (-1);
    }
  R_OpenUpdate (&rsa_context, line, &len, byteptr, INNERHEAD);
  add_to_buffer (b1, line, len);
  R_OpenFinal (&rsa_context, line, &len);
  add_to_buffer (b1, line, len);
#else
  B_CreateAlgorithmObject (&rsa_context);
  B_SetAlgorithmInfo (rsa_context, AI_PKCS_RSAPrivate, 0);
  B_DecryptInit (rsa_context, privkey, CHOOSER, NULL);
  assert (keylen <= sizeof (line));
  if (B_DecryptUpdate (rsa_context, line, &len, sizeof (line), key,
		       keylen, random_obj, NULL) != 0)
    {
      fprintf (errlog, "Decryption error.\n");
      return -1;
    }
  B_DecryptFinal (rsa_context, line + len, &len,
		  keylen - len,
		  random_obj, NULL);
  B_DestroyAlgorithmObject (&rsa_context);
  B_DestroyKeyObject (&privkey);

  B_CreateAlgorithmObject (&des_context);
  B_SetAlgorithmInfo (des_context, AI_DES_EDE3_CBC_IV8, iv);
  B_CreateKeyObject (&des_key);
  B_SetKeyInfo (des_key, KI_DES24Strong, line);
  B_DecryptInit (des_context, des_key, CHOOSER, NULL);

  B_DecryptUpdate (des_context, line, &len, sizeof (line), byteptr, INNERHEAD,
		   random_obj, NULL);
  add_to_buffer (b1, line, len);
  B_DecryptFinal (des_context, line, &len,
		  INNERHEAD - len,
		  random_obj, NULL);
  add_to_buffer (b1, line, len);
  B_DestroyAlgorithmObject (&des_context);
  B_DestroyKeyObject (&des_key);
#endif
  add_to_random (b1->message, b1->length);

  free_buffer (headers[0]);

  byteptr = b1->message;
  for (i = 0; i < 16; i++)
    packetID[i] = byteptr[i];

  i = 16+24;
  packet_type = *(byteptr + i);
  i++;
  if (packet_type & P_FINAL)
    i += 16+8;
  else if (packet_type & P_PARTIAL)
    i += 1+1+16+8;
  else
    i += 152+80;
  if (memcmp (byteptr + i, TSMAGIC, sizeof(TSMAGIC)) == 0)
    i += sizeof(TSMAGIC) + 2;
  {
    char d[128];
    int len;

#ifdef USE_RSAREF
    R_DIGEST_CTX digest_context;
    
    R_DigestInit (&digest_context, DA_MD5);
    R_DigestUpdate (&digest_context, byteptr, i);
    R_DigestFinal (&digest_context, d, &len);
#else
    B_ALGORITHM_OBJ digest_obj;

    B_CreateAlgorithmObject (&digest_obj);
    B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);
    
    B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
    B_DigestUpdate (digest_obj, byteptr, i, NULL);
    B_DigestFinal (digest_obj, d, &len, 16, NULL);
    B_DestroyAlgorithmObject (&digest_obj);
#endif
    if (memcmp (byteptr + i, d, 16) != 0)
      {
	fprintf(errlog, "Message checksum does not match!\n");
	return (-1);
      }
  }

  byteptr += 16;
  memcpy (innerkey, byteptr, 24);
  byteptr += 24;
  packet_type = *byteptr++;

  if (!(packet_type & (P_FINAL | P_PARTIAL)))
    {				/* intermediate packet */
#ifdef DEBUG
      printf ("intermed hop\n");/* debug */
#endif
      for (i = 0; i < NUM_IV; i++)
	{
	  memcpy (ivarray[i], byteptr, 8);
	  byteptr += 8;
	}
      memcpy (address, byteptr, 80);
      byteptr += 80;

      if (memcmp (byteptr, TSMAGIC, sizeof(TSMAGIC)) == 0)
      {
	  byteptr += sizeof(TSMAGIC);	
	  timestamp[0] = *byteptr++;
	  timestamp[1] = *byteptr++;
      }

      crypt_in_buffer (innerkey, ivarray[BODY_IV], body, 0);	/* decrypt back into the buffer */
      add_to_random (body->message, body->length);
      for (i = 1; i <= HOPMAX; i++)
	{
	  crypt_in_buffer (innerkey, ivarray[i - 1], headers[i], 0);	/* decrypt back into the buffer */
	}
      mix_lock ("mail", &lockptr);
      strcpy (line, "mail");
      fptr = tempfile (line);
      fprintf (fptr, "temp");	/* make sure the file is created */
      fclose (fptr);
      if (check_packetID (packetID, timestamp))
	{
	  if (send_new_packet (headers, body, address, line, 0, 0) < 0)
	    {
	      unlink (line);
	      mix_unlock ("mail", lockptr);
	      return (-1);
	    }
	}
      else
	{
	  unlink (line);
	}
      mix_unlock ("mail", lockptr);
    }
  else if (packet_type & P_FINAL)
    {				/* final hop */
#ifdef DEBUG
      printf ("final hop\n");	/* debug */
#endif
      for (i = 0; i < 16; i++)
	messageID[i] = byteptr[i];
      byteptr += 16;
      for (i = 0; i < 8; i++)
	iv[i] = byteptr[i];
      byteptr += 8;

      if (memcmp (byteptr, TSMAGIC, sizeof(TSMAGIC)) == 0)
      {
	  byteptr += sizeof(TSMAGIC);	
	  timestamp[0] = *byteptr++;
	  timestamp[1] = *byteptr++;
      }

      if (!check_packetID (packetID, timestamp))
	return (-1);
      crypt_in_buffer (innerkey, iv, body, 0);	/* decrypt back into the buffer */
      add_to_random (body->message, body->length);

      byteptr = body->message;
      length = byteptr[3];	/*high byte */
      length = length * 256 + byteptr[2];	/*3rd byte */
      length = length * 256 + byteptr[1];	/*2nd byte */
      length = length * 256 + byteptr[0];	/*low byte */
      if (length < 0 || length > body->length)
	{
	  fprintf (errlog, "Bad message size.\n");
	  return (-1);
	}
      send_message (NULL, byteptr + 4, length);
    }
  else if (packet_type & P_PARTIAL)
    {				/* partial message */
#ifdef DEBUG
      printf ("packet final hop\n");	/* debug */
#endif
      packet = *byteptr++;
      numpackets = *byteptr++;
      for (i = 0; i < 16; i++)
	messageID[i] = byteptr[i];
      byteptr += 16;
      for (i = 0; i < 8; i++)
	iv[i] = byteptr[i];
      byteptr += 8;

      if (memcmp (byteptr, TSMAGIC, sizeof(TSMAGIC)) == 0)
      {
	  byteptr += sizeof(TSMAGIC);	
	  timestamp[0] = *byteptr++;
	  timestamp[1] = *byteptr++;
      }

      if (!check_packetID (packetID, timestamp))
	return (-1);
      crypt_in_buffer (innerkey, iv, body, 0);	/* decrypt back into the buffer */
      add_to_random (body->message, body->length);

      mix_lock ("pac", &lockptr);
      merge_packets (body, messageID, packet, numpackets);
      mix_unlock ("pac", lockptr);

    }
  else
    {
#ifdef DEBUG
      fprintf (stdout, "Not a known packet type\n");	/* debug */
#endif
      return (-1);
    }
  return (0);
}

/* send packet just generated */
int
send_new_packet (BUFFER ** headbuff, BUFFER * bodybuff, char *address,
		 char *outfile, int outfileflag, int client)
{
  int i, len;
  BUFFER *outbuffer, *tmpbuffer;
  FILE *fptr;
  char line[1024], *tmp;
  byte digest[20];

  tmpbuffer = new_buffer ();
  for (i = 1; i <= HOPMAX; i++)
    {
      add_to_buffer (tmpbuffer, headbuff[i]->message, headbuff[i]->length);
      reset_buffer (headbuff[i]);
    }
  add_to_buffer (tmpbuffer, bodybuff->message, bodybuff->length);
  reset_buffer (bodybuff);

  /* build output file */
  outbuffer = new_buffer ();
  /* If a client mailing directly then add a To: line */

  if (client && strlen (outfile) >= 1 && !outfileflag)
    {
      /* do not add a To: line */
#ifdef MSDOS
      str_to_buffer (outbuffer, "\n\n");	/* empty lines for backward
						   compatibility with old
						   versions of Private Idaho */
#endif
    }
  else
    {
      if (client)
	{
	  str_to_buffer (outbuffer, "To: ");
	  str_to_buffer (outbuffer, address);
	  str_to_buffer (outbuffer, "\n\n");
	}
      else
	{
	  str_to_buffer (outbuffer, intermed_hop);
	  str_to_buffer (outbuffer, "\n");
	  str_to_buffer (outbuffer, address);
	  str_to_buffer (outbuffer, "\nEND\n");
	}
    }
  str_to_buffer (outbuffer, "::\n");
  str_to_buffer (outbuffer, remailer_type);
  str_to_buffer (outbuffer, VERSION);
  str_to_buffer (outbuffer, "\n\n");
  str_to_buffer (outbuffer, begin_remailer);
  str_to_buffer (outbuffer, "\n");
  sprintf (line, "%ld\n", tmpbuffer->length);	/* Write out length */
#ifdef DEBUG
  /* debug */ fprintf (stdout, "%s\n", outbuffer->message);
  /* Write out length */
#endif
  str_to_buffer (outbuffer, line);

  /* Ok, now make a MD5 checksum and prepend it. */
  make_digest (tmpbuffer, digest);
  encode_block (line, &len, digest, 16);
  add_to_buffer (outbuffer, line, len);
  str_to_buffer (outbuffer, "\n");

  /* armor and add message */
  armor (tmpbuffer);
  add_to_buffer (outbuffer, tmpbuffer->message, tmpbuffer->length);
  free_buffer (tmpbuffer);
  str_to_buffer (outbuffer, end_remailer);
  str_to_buffer (outbuffer, "\n");

  if (strlen (outfile) < 1)
    {
      if ((fptr = open_sendmail (-2, &tmp)) == NULL)
	return (-1);
      write_buffer (outbuffer, fptr);
      close_sendmail (fptr, tmp);
    }
  else if (streq (outfile, "-"))
    write_buffer (outbuffer, stdout);
  else
    {
      if (client)
	fptr = open_user_file (outfile, "w");
      else
	fptr = open_mix_file (outfile, "w");
      if (fptr == NULL)
	return (-1);
      write_buffer (outbuffer, fptr);
      fclose (fptr);
    }
  free_buffer (outbuffer);
  if (VERBOSE)
    fprintf(errlog, "Succeeded.\n");
  return (1);
}

void
getmsg (void *p, int n, FILE * file, byte ** bp, int *kp)
{
  if (file)
    fread (p, n, 1, file);
  else
    {
      memcpy (p, *bp, n);
      *bp += n;
      *kp -= n;
    }
}

#define NUMDEST 255
#define NUMSUB 255
#define DESTSIZE 80
#define SUBSIZE 80

int
send_message (FILE * file, byte * bptr, int k)
{
  FILE *out;
  FILE *lockptr;
  char *destination[NUMDEST];
  char *subject[NUMSUB];
  byte numdest;
  byte numsub;
  char foo[256], line[1024];
  int i;
  int err;
  FILE *in;
  BUFFER *buf;

  assert ((bptr == NULL) ^ (file == NULL));

  /* get destination list */
  getmsg (&numdest, 1, file, &bptr, &k);

  if (numdest > NUMDEST)
    {
      fprintf (errlog, "Too many destinations.\n");
      numdest = NUMDEST;
    }
  for (i = 0; i < numdest; i++)
    {
      destination[i] = (char *) malloc (DESTSIZE);
      getmsg (destination[i], DESTSIZE, file, &bptr, &k);
    }
  getmsg (&numsub, 1, file, &bptr, &k);
  if (numsub > NUMSUB)
    {
      fprintf (errlog, "Too many header lines.\n");
      numsub = NUMSUB;
    }
  for (i = 0; i < numsub; i++)
    {
      subject[i] = (char *) malloc (SUBSIZE);
      getmsg (subject[i], SUBSIZE, file, &bptr, &k);
    }

  /* open mail file */
  strcpy (foo, "mail");
  mix_lock (foo, &lockptr);
  out = tempfile (foo);

  /* put the destination list in the file one per line */
  fprintf (out, "%s\n", final_hop);

  for (i = 0; i < numdest; i++)
    {
      fprintf (out, "%s\n", destination[i]);
      free (destination[i]);
    }
  fprintf (out, "END\n");

  /* put the header lines on seperate lines in file */
  for (i = 0; i < numsub; i++)
    {
      if (strlen (subject[i]) > 0)
	fprintf (out, "%s\n", subject[i]);
      free (subject[i]);
    }
  fprintf (out, "\n");

  /* Write out the message */

  err = (file) ?
    uncompress_file2file (file, out) : uncompress_b2file (bptr, k, out);
  fclose (out);

  if (err < 0)
    unlink (foo);
  else if (!MIDDLEMAN)
    {
      /* if all destinations are blocked, delete the message now */
      if ((in = open_mix_file (foo, "r")) == NULL)
	return (-1);
      buf = new_buffer ();
      getline (line, sizeof (line), in);
      i = read_header (in, buf, 1);
      fclose (in);
      free_buffer (buf);
      if (!i)
	{
	  fprintf (errlog, "No valid recipients.\n");
	  err = 1;
	  unlink (foo);
	}
    }

  mix_unlock ("mail", lockptr);

  if (VERBOSE && err == 0)
    fprintf(errlog, "Succeeded.\n");

  return (err);
}

void
queue_msg (char *dest)
{
  char line[1024];
  FILE *out, *lockptr;

  /* open mail file */
  strcpy (line, "mail");
  mix_lock (line, &lockptr);
  out = tempfile (line);
  fprintf (out, "%s\n", final_hop);
  if (dest)
    fprintf (out, "%s\n", dest);
  fputs ("END\n", out);
  while (getline (line, sizeof (line), stdin) != NULL)
    fprintf (out, "%s\n", line);
  fclose (out);
  mix_unlock ("mail", lockptr);
}
