
/* $Id: chain2.c,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 * $Log: chain2.c,v $
 * Revision 1.1  2002/08/28 20:06:49  rabbi
 * Initial revision
 *
 * Revision 2.11  1999/01/19  02:28:13  um
 * *** empty log message ***
 *
 * Revision 2.10  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.9  1998/05/07  23:59:36  um
 * Format extension: timestamp in messages.
 *
 * Revision 2.8  1998/04/22  21:04:09  um
 * Yet another change for -n.
 *
 * Revision 2.7  1998/04/21  00:53:45  um
 * Fix newly introduced bug.
 *
 * Revision 2.6  1998/04/20  22:36:37  um
 * Bug fix: Use identical packet ID for all NUMCOPIES packets.
 *
 * Revision 2.5  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.4  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 * Revision 2.3  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 *
 * chain2.c          1997-10-10 JK
 *      parse header lines without " " after the ":" correctly.
 *
 * chain2.c          1997-09-23 um
 *      print selected chain if VERBOSE is set.
 *
 * chain2.c          1997-09-06 um
 *      </PRE> marks end of reliable mixmaster list.
 *
 * chain2.c          1997-08-29 um
 *      mm_chain requires "post:" keyword.
 *
 * chain2.c          1997-08-26 um
 *      bug fix: reliability check didn't work.
 *      ignore empty lines at the end of mixmaster lists.
 *      new option -d sends dummy message.
 *
 * chain2.c          1997-08-23 um
 *      bug fix: support for the reliable mixmaster list, by Andy Dustman.
 *
 * chain2.c          1997-08-22 um
 *      bug fix: messages were deleted by mix 2.0.3.
 *
 * chain2.c          1997-08-17 JK
 *      gcc warnings eliminated.
 *
 * chain2.c          1997-08-15 um
 *     new command line options, create middleman messages, minor improvemts.
 *
 * chain2.c          1997-07-17 um
 *     yet another off-by-one error, found by Johannes Kroeger.
 *     better reliability list support patch by Andy Dustman.
 *
 * chain2.c          1997-06-30 um
 *     fixed off-by-one error in rnd_select.
 *
 * chain2.c          1997-06-18 um
 *     improved random chaining.
 *
 * chain2.c          1997-06-06 um
 *     variable name packet_type introduced for readability.
 *
 * chain2.c      0.1 1996-11-27 um
 *     check remailer abilities.
 *     remailers may be selected in mixmaster.conf
 *     read the list of reliable Mixmaster remailers.
 *
 * chain2.c      0.0 1996-10-25 um
 *     split type2.c in two files
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

#include "mix.h"
#include "crypto.h"

#include <sys/file.h>
#include <assert.h>

/* default for unlisted remailers. Will be set to 100% if no list available */
#define DEFAULTRELIABILITY 0
#define DEFAULTLATENCY 0	/* in seconds! */
#define RELLISTSEP "--------------------------------------------"

int
read_remailer_list (REMAILER * list)
{
  char line[256], tmp[256];
  int num = 0, i;
  int ID[16];
  FILE *ptr;
  int have_rel = 0;

  if ((ptr = open_mix_file (REMAILERLIST, "r")) == NULL)
    exit (-1);
  while (getline (line, sizeof (line), ptr) != NULL)
    if (strlen (line) > 0)
      {
	num++;
	memset (&list[num], 0, sizeof (list[num]));
	sscanf (line, "%s %s %s %s %s", list[num].shortname, list[num].name,
		tmp, list[num].version, list[num].abilities);
	sscanf (tmp, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		ID, ID + 1, ID + 2, ID + 3, ID + 4, ID + 5, ID + 6, ID + 7, ID + 8, ID + 9,
		ID + 10, ID + 11, ID + 12, ID + 13, ID + 14, ID + 15);
	for (i = 0; i < 16; i++)
	  list[num].key_ID[i] = ID[i];
	list[num].reliability = DEFAULTRELIABILITY;
	list[num].latency = DEFAULTLATENCY;
	strcpy (list[num].lorm, "                             ");
      }
  fclose (ptr);

  if ((ptr = try_open_mix_file (RELLIST, "r")) != NULL)
    {
      while (getline (line, sizeof (line), ptr) != NULL)
	{
	  if (streq (line, RELLISTSEP))
	    have_rel = 1;
	  else if (streq (line, "</PRE>"))
	    break;
	  else if (strlen (line) != 44 && strlen (line) > 0)
	    have_rel = 0;
	  else if (have_rel && (strlen (line) == 44))
	    {
	      sscanf (line, "%s", tmp);
	      for (i = 1; i <= num; i++)
		if (streq (tmp, list[i].shortname))
		  {
		    strncpy (list[i].lorm, line + 15, 29);

#define N(X) ((X) >= '0' && (X) <= '9' ? (X)-'0' : 0)

		    list[i].reliability = 10000 * N (line[37]) + 1000 * N (line[38]) + 100 * N (line[39]) + 10 * N (line[41]) + N (line[42]);
		    list[i].latency = 36000 * N (line[28]) + 3600 * N (line[29]) + 600 * N (line[31]) + 60 * N (line[32]) + 10 * N (line[34]) + N (line[35]);
		    list[i].reliable = (list[i].reliability >= MINREL * 100 && list[i].latency <= MAXLAT * 3600);
		  }
	    }
	}
      if (!have_rel)
	fprintf (errlog, "Unknown format: %s\n", RELLIST);
      fclose (ptr);
    }
  if (!have_rel)		/* default to 100% if no list available */
    for (i = 1; i <= num; i++)
      list[i].reliability = 10000, list[i].latency = 0, list[i].reliable = 1;
#if 1
  {
    int num_rel = 0, num_cap = 0;
    for (i = 1; i <= num; i++)
      if (list[i].reliable)
	{
	  num_rel++;
	  if (check_abilities (list[i].abilities, REQUIRE, REJECT))
	    num_cap++;
	}
    if (num_rel < MINREMAILERS)
      {
	fprintf (errlog, "Warning: Too few reliable remailers!\n");
	fprintf (errlog, "Please remove %s if it is outdated.\n", RELLIST);
      }
    else if (num_cap < 1)
      {
	fprintf (errlog, "Warning: No reliable remailers with sufficient capabilities!\n");
      }
  }
#endif
  return (num);
}

#define NUMDEST 80
#define NUMSUB 80
#define DESTSIZE 80
#define SUBSIZE 80

/* this actually makes the message block and sends it */
int
build_message (FILE * in_ptr, byte numdest,
	       char **destination, int *chain, byte numsub,
	       char **subject, char *outfile, int outfileflag,
	       REMAILER * remailer_list, int num_remailers,
	       int client)
{
  int hop, i, j, k, numpackets, packet, copy;
  long int chunk, tmpchunk;
  byte iv[8];
  byte ivarray[NUM_IV][8], innerkey[24], digest[16];
  BUFFER *sendbuff, *bodybuff, *headbuff[21], *message, *tempbuff;
  long offset;
  char line[1024];
  byte *key[5], packetID[16], commonpacketID[16], messageID[16];
  byte tmpbyte;
  byte packet_type;
#ifdef USE_RSAREF
  PUBLIC_KEY pubKey, *keyPtr[5];
  unsigned int numPubKeys, keylen;
  R_ENVELOPE_CTX rsa_context;
#else
  PUBLIC_KEY pubKey;
  unsigned int keylen;
  B_ALGORITHM_OBJ rsa_context;
  B_ALGORITHM_OBJ des_context;
  B_KEY_OBJ des_key;
#endif
  unsigned long timestamp;

  message = new_buffer ();
  /* prepend destinations to body */
  add_to_buffer (message, &numdest, 1);
  for (i = 0; i < numdest; i++)
    add_to_buffer (message, destination[i], DESTSIZE);
  /* add message header lines to body */
  add_to_buffer (message, &numsub, 1);
  for (i = 0; i < numsub; i++)
    add_to_buffer (message, subject[i], SUBSIZE);

  offset = message->length;

  /* add the file to body */
  if (in_ptr)
    {
      while ((i = fread (line, 1, sizeof (line), in_ptr)) > 0)
	{
	  if (i < 0)
	    return (-1);	/* file error */
	  add_to_buffer (message, line, i);
	}
      fclose (in_ptr);
    }

  /* message is complete. */
  add_to_random (message->message, message->length);

  /* Choose the final hop now. */
  if (chain[chain[0]] == 0)
    if (rnd_select (chain[0], chain, remailer_list, num_remailers) < 0)
      return (-1);

#ifdef USE_ZLIB
  /* should we compress this message? */
  if (message->length > PACKETSIZE &&
      check_abilities (remailer_list[chain[chain[0]]].abilities, "C", ""))
    {
      tempbuff = new_buffer ();
      if (compress_buf2buf (message, tempbuff, offset))
	{
	  free_buffer (message);
	  message = tempbuff;
	}
      else
	free_buffer (tempbuff);
    }

  /* in case it already is compressed, but should not be */
  if (!check_abilities (remailer_list[chain[chain[0]]].abilities, "C", ""))
    {
      tempbuff = new_buffer ();
      if (uncompress_buf2buf (message, tempbuff, offset))
	{
	  free_buffer (message);
	  message = tempbuff;
	}
      else
	free_buffer (tempbuff);
    }
#endif

  numpackets = message->length / PACKETSIZE;
  if (message->length % PACKETSIZE != 0)
    numpackets++;

  bodybuff = new_buffer ();
  sendbuff = new_buffer ();
  for (i = 1; i <= HOPMAX; i++)
    headbuff[i] = new_buffer ();

  our_randombytes (messageID, 16);

  /* Loop to make one packet at a time */
  for (packet = 1; packet <= numpackets; packet++)
    {
      /* put the packet in bodybuff, and put the rest back in message */
      chunk = message->length;
      if (chunk > PACKETSIZE)
	chunk = PACKETSIZE;
      clear_buffer (bodybuff);

      tmpchunk = chunk;
      tmpbyte = tmpchunk & 0xFF;
      add_to_buffer (bodybuff, &tmpbyte, 1);	/* prepend length of data low byte */
      tmpchunk = tmpchunk / 256;
      tmpbyte = tmpchunk & 0xFF;
      add_to_buffer (bodybuff, &tmpbyte, 1);	/* prepend length of data 2nd byte */
      tmpchunk = tmpchunk / 256;
      tmpbyte = tmpchunk & 0xFF;
      add_to_buffer (bodybuff, &tmpbyte, 1);	/* prepend length of data 3rd byte */
      tmpchunk = tmpchunk / 256;
      tmpbyte = tmpchunk & 0xFF;
      add_to_buffer (bodybuff, &tmpbyte, 1);	/* prepend length of data high byte */

      add_to_buffer (bodybuff, message->message, chunk);
      tempbuff = new_buffer ();
      add_to_buffer (tempbuff, (message->message) + chunk, message->length - chunk);
      free_buffer (message);
      message = tempbuff;

      if (NUMCOPIES < 1 || NUMCOPIES > 10)
	{
	  fprintf (errlog, "Error: Invalid number of copies.\n");
	  return (-1);
	}
      for (copy = 1; copy <= NUMCOPIES; copy++)
	{
	  clear_buffer (sendbuff);
	  add_to_buffer (sendbuff, bodybuff->message, bodybuff->length);
	  pad_buffer (sendbuff, PACKETSIZE + 4);

	  /* Create fake header cards */
	  for (i = chain[0] + 1; i <= HOPMAX; i++)
	    {
	      reset_buffer (headbuff[i]);
	      pad_buffer (headbuff[i], HEADERSIZE);
	    }
	  if (rnd_selectchain (chain, remailer_list, num_remailers) < 0)
	    return (-1);
	  for (hop = chain[0]; hop >= 1; hop--)
	    {
	      /* Get public key for remailer */
	      if (get_pub_key (remailer_list[abs (chain[hop])].key_ID,
			       &pubKey) != 0)
		{
		  fprintf (errlog, "Can't get public key!\n");
		  return (-1);
		}
	      key[0] = malloc (MAX_ENCRYPTED_KEY_LEN);
#ifdef USE_RSAREF
	      numPubKeys = 1;
	      keyPtr[0] = &pubKey;
	      if (R_SealInit (&rsa_context, key, &keylen, iv, numPubKeys,
			      keyPtr, EA_DES_EDE3_CBC, &random_obj) != 0)
		{
		  fprintf (errlog, "R_SealInit error %x!!!\n", i);
		  exit (-1);
		}
#else
	      B_CreateAlgorithmObject (&rsa_context);
	      B_CreateAlgorithmObject (&des_context);
	      B_SetAlgorithmInfo (rsa_context, AI_PKCS_RSAPublic, 0);
	      B_SetAlgorithmInfo (des_context, AI_DES_EDE3_CBC_IV8, iv);
	      our_randombytes (line, 24);
	      B_CreateKeyObject (&des_key);
	      B_SetKeyInfo (des_key, KI_DES24Strong, line);

	      B_EncryptInit (rsa_context, pubKey, CHOOSER, NULL);
	      B_EncryptUpdate (rsa_context, key[0], &keylen,
			       MAX_ENCRYPTED_KEY_LEN, line, 24,
			       random_obj, NULL);
	      B_EncryptFinal (rsa_context, key[0] + keylen, &k,
			      MAX_ENCRYPTED_KEY_LEN - keylen, random_obj,
			      NULL);
	      B_DestroyAlgorithmObject (&rsa_context);
	      B_DestroyKeyObject (&pubKey);
	      keylen += k;

	      B_EncryptInit (des_context, des_key, CHOOSER, NULL);
	      /* XXX Error handling! */
#endif
	      /* make packet ID and innerkey */
	      /* packet ID is unique except for duplicates in the last hop */
	      if (hop != chain[0])
		  our_randombytes (packetID, 16);
	      else
	      {
		  if (copy == 1)
		      our_randombytes (commonpacketID, 16);
	      memcpy (packetID, commonpacketID, 16);
	      }

	      our_randombytes (innerkey, 24);
	      /* make the iv array */
	      for (i = 0; i < NUM_IV; i++)
		our_randombytes (ivarray[i], 8);

	      /* Now build the current header */
	      reset_buffer (headbuff[hop]);
	      add_to_buffer (headbuff[hop], packetID, 16);	/* also like another IV */
	      add_to_buffer (headbuff[hop], innerkey, 24);	/* Key used to encrypt headers and body */
	      if (hop == chain[0])
		{		/* if this is the last hop */
		  if (numpackets == 1)
		    /* final hop */
		    packet_type = P_FINAL;
		  else
		    /* partial message */
		    packet_type = P_PARTIAL;
		  add_to_buffer (headbuff[hop], &packet_type, 1);
		  if (packet_type & P_PARTIAL)
		    {
		      tmpbyte = packet;	/* which packet is this */
		      add_to_buffer (headbuff[hop], &tmpbyte, 1);
		      tmpbyte = numpackets;	/* out of how many */
		      add_to_buffer (headbuff[hop], &tmpbyte, 1);
		    }
		  add_to_buffer (headbuff[hop], messageID, 16);
		  add_to_buffer (headbuff[hop], ivarray[BODY_IV], 8);
		}
	      else
		{		/* this is not the last hop */
		  packet_type = 0;	/* packet type = intermediate packet */
		  add_to_buffer (headbuff[hop], &packet_type, 1);
		  /* insert the array of IVs */
		  for (i = 0; i < NUM_IV; i++)
		    {
		      add_to_buffer (headbuff[hop], ivarray[i], 8);
		    }
		  add_to_buffer (headbuff[hop], remailer_list[abs (chain[hop + 1])].name, 80);
		}

	      /* Extension to original mixmaster format:
		 Use timestamp to prevent replay of old messages. */
	      add_to_buffer (headbuff[hop], TSMAGIC, sizeof(TSMAGIC));
	      /* Fuzzy timestamp: don't leak more information than necessary */
	      timestamp = time(NULL) / SECONDSPERDAY - random_number(4);
	      tmpbyte = timestamp & 0xFF;
	      add_to_buffer (headbuff[hop], &tmpbyte, 1);
	      tmpbyte = (timestamp / 256) & 0xFF;
	      add_to_buffer (headbuff[hop], &tmpbyte, 1);

	      /* Make and append an MD5 checksum of the packet */
	      make_digest (headbuff[hop], digest);
	      add_to_buffer (headbuff[hop], digest, 16);

	      /* Now pad pre-encrypted header to standard size */
	      pad_buffer (headbuff[hop], INNERHEAD);

	      /* Done building headbuff[hop] so now RSA it */
	      tempbuff = new_buffer ();
	      assert (headbuff[hop]->length <= INNERHEAD);

#ifdef USE_RSAREF
	      R_SealUpdate (&rsa_context, line, &k, headbuff[hop]->message,
			    headbuff[hop]->length);
#else
	      B_EncryptUpdate (des_context, line, &k, sizeof (line),
			       headbuff[hop]->message, headbuff[hop]->length,
			       random_obj, NULL);
#endif
	      add_to_buffer (tempbuff, line, k);
#ifdef USE_RSAREF
	      R_SealFinal (&rsa_context, line, &k);
#else
	      B_EncryptFinal (des_context, line, &k,
			      INNERHEAD - k,
			      random_obj, NULL);
	      B_DestroyAlgorithmObject (&des_context);
	      B_DestroyKeyObject (&des_key);
#endif
	      add_to_buffer (tempbuff, line, k);
	      clear_buffer (headbuff[hop]);

	      /* Prepend RSA key ID */
	      add_to_buffer (headbuff[hop], remailer_list[abs (chain[hop])].key_ID, 16);
	      /* prepend keys and IV to header */
	      tmpbyte = keylen;
	      add_to_buffer (headbuff[hop], &tmpbyte, 1);
	      add_to_buffer (headbuff[hop], key[0], tmpbyte);
	      add_to_buffer (headbuff[hop], iv, 8);
	      /* add encryped header */
	      add_to_buffer (headbuff[hop], tempbuff->message, tempbuff->length);
	      free_buffer (tempbuff);

	      /* pad out encrypted header to standard size */
	      pad_buffer (headbuff[hop], HEADERSIZE);

	      /* encrypt body */
	      crypt_in_buffer (innerkey, ivarray[BODY_IV], sendbuff, 1);

	      /* encrypt all later headers */
	      /* i is the index for ivarray */
	      for (i = 0, j = hop + 1; j <= HOPMAX; j++)
		crypt_in_buffer (innerkey, ivarray[i++], headbuff[j], 1);
	    }			/* hop loop for a given packet */
	  if (VERBOSE)
	    {
	      fprintf (errlog, "Packet chain: ");
	      for (i = 1; i <= chain[0]; i++)
		fprintf (errlog, "%s;", remailer_list[abs (chain[i])].shortname);
	      fprintf (errlog, "\n");
	    }
	  if (strlen (outfile) > 0 && (!streq (outfile, "-")) && (numpackets > 1 || NUMCOPIES > 1))
	    {
	      sprintf (line, "%s.%d", outfile, (packet - 1) * NUMCOPIES + copy);
	      send_new_packet (headbuff, sendbuff, remailer_list[abs (chain[1])].name, line, outfileflag, client);
	    }
	  else
	    {
	      send_new_packet (headbuff, sendbuff, remailer_list[abs (chain[1])].name, outfile, outfileflag, client);
	    }
	}			/* copies of one packet */
    }				/* end loop processing packets */
  free_buffer (bodybuff);
  free_buffer (sendbuff);
  free_buffer (message);
  for (i = 1; i <= HOPMAX; i++)
    free_buffer (headbuff[i]);

  return (0);
}

void
get_chain (REMAILER * remailer_list, int num_remailers, int *chain)
{
  char line[256];
  int i;

  fprintf (errlog, "\n");
  for (i = 1; i <= num_remailers; i++)
    fprintf (errlog, "%3d %c [%s] %s\n", i,
	     !remailer_list[i].reliable ? 'U' : check_abilities
	     (remailer_list[i].abilities, REQUIRE, REJECT) ? '*' : ' ',
	     remailer_list[i].lorm, remailer_list[i].name);
  fprintf (errlog, "Choose the remailers you want to use in your chain.\n");
  fprintf (errlog, "0 means random remailer. Hit return when you are done.\n");
  if (chain[0] > 1)
    {
      fprintf (errlog, "Selected:");
      for (i = 1; i < chain[0]; i++)
	fprintf (errlog, " %d", chain[i]);
      fprintf (errlog, "\n");
    }
  fprintf (errlog, "Enter remailer number: ");
  getline (line, sizeof (line), stdin);
  while (chain[0] < HOPMAX)
    {
      if (line[0] == 0)
	break;
      if ((chain[++chain[0]] =
	   select_remailer (remailer_list, num_remailers, line)) < 0)
	--chain[0];		/* failed */
      fprintf (errlog, "Enter remailer number: ");
      getline (line, sizeof (line), stdin);
    }
}

int
chain_2 (int argc, char *argv[])
{
  FILE *in;
  char line[256], filename[80] = "", *destination[NUMDEST], outfile[80] = "";
  char *subject[NUMSUB], *t;
  int chain[HOPMAX];
  byte numdest = 0, numsub = 0;
  int i, num_remailers, outfileflag = 0;
  REMAILER remailer_list[256];
  int filter = 0, rfcmsg = 0, dummy = 0;

  num_remailers = read_remailer_list (remailer_list);

  chain[0] = 0;

  /* what is in those arguments */
  /* Here is the expected format */
  /* mixmaster [-c][-f][filename][-[o,O] outfile][-to who@where][-s "subject"][-l 1 2 3 4] */
  /* if no outfile given, then pipe to sendmail. outfile = stdout send to stdout */
  for (i = 1; i < argc; i++)
    {
      if (streq (argv[i], "-c"))
	{
	  /* nop */
	}
      else if (strleft (argv[i], "-h") || streq (argv[i], "--help"))
	{
	  /* Print help and exit */
	  printf ("Mixmaster %s (C) Copyright Lance M. Cottrell 1995, 1996\n",
		  VERSION);
	  printf ("Released under the GNU public license. No warranty!\n\n");
	  printf ("Client Mode command line arguments:\n");
	  printf ("mixmaster [-c] [infile] [-f] [-m] [-s subject] [-v 'Header: text' [-v ...]]\n[-n numcopies] [-[o,O] outfile] [-to who@where] [-l 1 2 3 ...]\n");
	  exit (-1);
	}
      else if (streq (argv[i], "-f"))
	{
	  /* set filter mode */
	  filter = 1;
	}
      else if (streq (argv[i], "-m"))
	{
	  filter = 1;
	  rfcmsg = 1;
	}
      else if (streq (argv[i], "-d"))
	{
	  filter = 1;
	  destination[0] = (char *) calloc (1, DESTSIZE);
	  strcpy (destination[0], "null:");
	  numdest = 1;
	  REQUIRE[0] = '\0';
	  REJECT[0] = '\0';
	  dummy = 5 + random_number (11);
	}
      else if (streq (argv[i], "-s"))
	{
	  if (i < argc - 1)
	    i++;
	  subject[numsub] = (char *) calloc (1, SUBSIZE);
	  strcpy (subject[numsub], "Subject: ");
	  strncat (subject[numsub], argv[i], SUBSIZE - sizeof ("Subject: "));
	  numsub++;
	}
      else if (streq (argv[i], "-v"))
	{
	  if (i < argc - 1)
	    i++;
	  subject[numsub] = (char *) calloc (1, SUBSIZE);
	  subject[numsub][0] = 0;
	  strncat (subject[numsub], argv[i], SUBSIZE - 1);
	  numsub++;
	}
      else if (streq (argv[i], "-o") || streq (argv[i], "-O"))
	{
	  if (streq (argv[i], "-O"))
	    outfileflag = 1;	/* add To: line */
	  if (i < argc - 1)
	    i++;
	  if (streq (argv[i], "stdout"))
	    strcpy (outfile, "-");
	  else
	    parse_filename (outfile, argv[i]);
	}
      else if (streq (argv[i], "-n"))
	{
	  if (i < argc - 1)
	    i++;
	  sscanf (argv[i], "%d", &NUMCOPIES);
	}
      else if (streq (argv[i], "-to") && numdest < NUMDEST)
	{
	  if (i < argc - 1)
	    i++;
	  destination[numdest] = (char *) calloc (1, DESTSIZE);
	  strncpy (destination[numdest], argv[i], DESTSIZE - 1);
	  destination[numdest][DESTSIZE - 1] = '\0';
	  chop (destination[numdest]);
	  numdest++;
	}
      else if (streq (argv[i], "-l"))
	{
	  for (i++; i < argc && chain[0] < HOPMAX; i++)
	    if ((chain[++chain[0]] =
		 select_remailer (remailer_list,
				  num_remailers, argv[i])) < 0)
	      exit (-1);	/* Invalid remailer */
	}
      else
	{
	  if (strlen (filename) != 0)
	    {
	      fprintf (errlog, "problem with the command line\n");
	      return (-1);
	    }
	  strncpy (filename, argv[i], sizeof (filename));
	}
    }

  if (numdest == 0 && !rfcmsg)
    {
      if (!filter)
	fprintf (errlog, "Enter final destinations (one per line return when done).\n");
      do
	{
	  if (!filter)
	    fprintf (errlog, "Enter destination :");
	  getline (line, sizeof (line), stdin);
	  if (strlen (line) >= 2 && numdest < NUMDEST)
	    {
	      destination[numdest] = (char *) calloc (1, DESTSIZE);
	      strncpy (destination[numdest], line, DESTSIZE - 1);
	      destination[numdest][DESTSIZE - 1] = '\0';
	      numdest++;
	    }
	}
      while (strlen (line) > 0 || numdest == 0);
    }
  if (numdest == 0 && filter && !rfcmsg)
    exit (-1);			/* no destination and in filter mode */

  if (numsub == 0 && !dummy)
    {
      if (!filter)
	{
	  fprintf (errlog, "Enter message headers (one per line, return when done).\n");
	  fprintf (errlog, "You must include the header name, e.g. 'Subject: foo'\n");
	}
      do
	{
	  if (!filter)
	    fprintf (errlog, "Enter header :");
	  getline (line, sizeof (line), stdin);
	  if (rfcmsg && (strileft (line, "To:") || strileft (line, "Newsgroups:")) && numdest < NUMDEST)
	    {
	      destination[numdest] = (char *) calloc (1, DESTSIZE);
	      if (strileft (line, "To:"))
		{
		  t = line + sizeof ("To:") - 1;
		  while (*t == ' ' || *t == '\t')
		    t++;
		  strncpy (destination[numdest], t, DESTSIZE - 1);
		}
	      else
		{
		  t = line + sizeof ("Newsgroups:") - 1;
		  while (*t == ' ' || *t == '\t')
		    t++;
		  strcpy (destination[numdest], "post: ");
		  strncat (destination[numdest], t, DESTSIZE - sizeof ("post: "));
		}
	      destination[numdest][DESTSIZE - 1] = '\0';
	      numdest++;
	    }
	  else if (strlen (line) > 0 && numsub < NUMSUB)
	    {
	      subject[numsub] = (char *) calloc (1, SUBSIZE);
	      strncpy (subject[numsub], line, SUBSIZE - 1);
	      subject[numsub][SUBSIZE - 1] = '\0';
	      numsub++;
	    }
	}
      while (strlen (line) > 0);
    }

  if (!strchr (REQUIRE, 'N'))
    for (i = 0; i < numdest; i++)
      if (strileft (destination[i], "post:"))
	{
	  strcat (REQUIRE, "N");
	  break;
	}

  if (chain[0] == 0 && strlen (CHAIN))
    if (scan_remailer_list (CHAIN, chain, remailer_list, num_remailers) < 0)
      return (-1);
  if (chain[0] == 0 && dummy)
    {
      while (chain[0] < dummy)
	chain[++chain[0]] = 0;
    }
  if (chain[0] == 0 && !filter)
    {
      get_chain (remailer_list, num_remailers, chain);
    }
  if (chain[0] == 0)
    {
      return (-1);
    }
#if 1
  if ((chain[chain[0]] > 0)
      && check_abilities (remailer_list[chain[chain[0]]].abilities,
			  REQUIRE, REJECT) == 0)
    {
      fprintf (errlog, "Warning: Remailer %s has insufficient capabilities!\n",
	       remailer_list[chain[chain[0]]].shortname);
    }
#else
  while ((chain[chain[0]] > 0)
	 && check_abilities (remailer_list[chain[chain[0]]].abilities,
			     REQUIRE, REJECT) == 0)
    {
      fprintf (errlog, "Remailer %s has insufficient capabilities!\n",
	       remailer_list[chain[chain[0]]].shortname);
      if (!filter)
	{
	  chain[0]--;
	  get_chain (remailer_list, num_remailers, chain);
	}
      else
	exit (-1);
    }
#endif

  /* if file = stdin then I will take stdin */
  if (strlen (filename) == 0 && !filter)
    {
      fprintf (errlog, "Please enter the name of the file to chain: ");
      getline (filename, sizeof (filename), stdin);
    }
  if (streq (filename, "stdin"))
    strcpy (filename, "-");
  parse_filename (line, filename);
  if (dummy)
    in = NULL;
  else if (streq (filename, "-") || strlen (filename) == 0)
    {
      if (!filter)
	fprintf (errlog, "Please enter the message.\n");
      in = stdin;
    }
  else
    in = open_user_file (line, "r");
  /* ok, that should be everything we need to know */

#ifdef DEBUG
  printf ("filtermode %d\n", filter);	/*debug */
  printf ("source file %s\n", filename);	/*debug */
  printf ("#destinations %d\n", numdest);	/*debug */
  for (i = 0; i < numdest; i++)
    printf ("destination %d  %s\n", i, destination[i]);	/*debug */
  for (i = 1; i <= chain[0]; i++)
    printf ("remailer %d\n", chain[i]);	/*debug */
  for (i = 0; i < numsub; i++)
    printf ("header %d  %s\n", i, subject[i]);	/*debug */
#endif

  return (build_message (in, numdest, destination, chain,
			 numsub, subject, outfile, outfileflag,
			 remailer_list, num_remailers, 1));
}

void
mm_chain (const char *filename)
{
  FILE *in;
  FILE *fptr;
  char line[256], *destination[NUMDEST], outfile[80] = "";
  char *subject[NUMSUB], *t;
  int chain[HOPMAX];
  byte numdest = 0, numsub = 0;
  int post = 0;
  int num_remailers;
  REMAILER remailer_list[256];

  /* The first line of the packet contains the keyword "post" if the
     message is to be posted. In that case we transform "Newsgroups: "
     to "post: ". */

  num_remailers = read_remailer_list (remailer_list);
  chain[0] = 0;
  in = open_mix_file (filename, "r");
  do
    {
      getline (line, sizeof (line), in);
      if ((strileft (line, "To:") || (post && strileft (line, "Newsgroups:"))) && numdest < NUMDEST)
	{
	  destination[numdest] = (char *) calloc (1, DESTSIZE);
	  if (strileft (line, "To:"))
	    {
	      t = line + sizeof ("To:") - 1;
	      while (*t == ' ' || *t == '\t')
		t++;
	      strncpy (destination[numdest], t, DESTSIZE - 1);
	    }
	  else
	    {
	      t = line + sizeof ("Newsgroups:") - 1;
	      while (*t == ' ' || *t == '\t')
		t++;
	      strcpy (destination[numdest], "post: ");
	      strncat (destination[numdest], t, DESTSIZE - sizeof ("post: "));
	    }
	  destination[numdest][DESTSIZE - 1] = '\0';
	  numdest++;
	}
      else if (streq (line, "post:"))
	post = 1;
      else if (strlen (line) >= 2 && numsub < NUMSUB)
	{
	  subject[numsub] = (char *) calloc (1, SUBSIZE);
	  strncpy (subject[numsub], line, SUBSIZE - 1);
	  subject[numsub][SUBSIZE - 1] = '\0';
	  numsub++;
	  if (strileft (line, "Newsgroups:") && !strchr (REQUIRE, 'N'))
	    strcat (REQUIRE, "N");
	}
    }
  while (strlen (line) > 0);

  if (scan_remailer_list (FORWARDTO, chain, remailer_list, num_remailers) < 0)
    return;

  strcpy (outfile, "mail");
  fptr = tempfile (outfile);
  fprintf (fptr, "temp");	/* make sure the file is created */
  fclose (fptr);

  build_message (in, numdest, destination, chain,
		 numsub, subject, outfile, 0,
		 remailer_list, num_remailers, 0);

  if ((fptr = try_open_mix_file (outfile, "r")) != NULL)
    {
      getline (line, sizeof (line), fptr);
      fclose (fptr);
      if (streq (line, "temp"))
	unlink (outfile);
    }
}

int
select_remailer (REMAILER * remailer_list, int num_remailers, char *sel)
{
  int remailer, k;

  remailer = atoi (sel);
  if (remailer == 0 && sel[0] != '0')
    {
      for (k = 1; k <= num_remailers; k++)
	{
	  if (streq (sel, remailer_list[k].shortname))
	    remailer = k;
	  if (streq (sel, remailer_list[k].name))
	    remailer = k;
	}
      if (remailer == 0)
	{
	  fprintf (errlog, "Invalid remailer name %s.\n", sel);
	  return (-1);
	}
    }
  /* remailer = 0 means random remailer */
  if (remailer < 0 || remailer > num_remailers)
    {
      fprintf (errlog, "Invalid remailer number %s.\n", sel);
      return (-1);
    }
  return (remailer);
}

int
scan_remailer_list (char *s, int *chain,
		    REMAILER * remailer_list, int num_remailers)
{
  char *p;
  char line[256];

  for (p = s; chain[0] < HOPMAX;)
    {
      while (*p <= ' ')
	if (*p++ == 0)
	  return (0);
      sscanf (p, "%s", line);
      if ((chain[++chain[0]] =
	   select_remailer (remailer_list, num_remailers, line)) < 0)
	return (-1);
      while (*++p > ' ');
    }
  return (0);
}

int
check_abilities (char *abilities, char *require, char *reject)
     /* returns 1 if the abilities string matches our requirements */
{
  unsigned int i;

  for (i = 0; i < strlen (require); i++)
    if (require[i] >= 'A' && require[i] <= 'Z'
	&& (strchr (abilities, require[i]) == NULL))
      return (0);
  for (i = 0; i < strlen (reject); i++)
    if (reject[i] >= 'A' && reject[i] <= 'Z'
	&& (strchr (abilities, reject[i]) != NULL))
      return (0);
  return (1);
}


int
rnd_selectchain (int *chain, REMAILER * remailer_list, int num_remailers)
{
  int h;
  for (h = 1; h <= chain[0]; h++)
    if (chain[h] < 0)
      chain[h] = 0;
  for (h = 1; h <= chain[0]; h++)
    if (chain[h] == 0)
      if (rnd_select (h, chain, remailer_list, num_remailers) < 0)
	return (-1);
  return 0;
}

#define min(a,b) ((a < b) ? (a) : (b))
#define max(a,b) ((a > b) ? (a) : (b))

int
rnd_select (int thishop, int *chain, REMAILER * remailer_list, int num_remailers)
{
  int h, i, r;
  int avail;
  int best;
  byte use[256];
  int final;

  final = (thishop == chain[0]);

  for (i = 1; i <= num_remailers; i++)
    {
      if ((!remailer_list[i].reliable) || (final && !check_abilities (remailer_list[i].abilities, REQUIRE, REJECT)))
	use[i] = 0;		/* don't use unreliable remailers */
      else
	use[i] = 1;
    }

  for (h = max (thishop - DISTANCE, 1);
       h <= min (thishop + DISTANCE, chain[0]); h++)
    if (chain[h] != 0)
      use[abs (chain[h])] = 0;	/* don't use more than once */

  if (final)
    {				/* RELFINAL reliability required; use best remailer if none > RELFINAL */
      for (best = -1, i = 1; i <= num_remailers; i++)
	if (use[i] && remailer_list[i].reliability > best)
	  best = remailer_list[i].reliability;
      for (i = 1; i <= num_remailers; i++)
	if (remailer_list[i].reliability < min (RELFINAL * 100, best))
	  use[i] = 0;
    }

  for (avail = 0, i = 1; i <= num_remailers; i++)
    if (use[i])
      avail++;			/* how many remailers to choose from? */

  if (avail <= 0)
    {
      fprintf (errlog, "Error: Too few reliable remailers!\n");
      return (-1);
    }

  /* select remailer */
  for (r = random_number (avail), i = 1; r >= 0; r--, i++)
    while (!use[i])
      i++;
  i--;

  if (final)
    chain[thishop] = i;		/* for all packets */
  else
    chain[thishop] = -i;	/* for this packet */
  return 0;
}
