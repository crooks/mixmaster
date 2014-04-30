/* Mixmaster version 3.0  --  (C) 1999 - 2006 Anonymizer Inc. and others.

   Mixmaster may be redistributed and modified under certain conditions.
   This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF
   ANY KIND, either express or implied. See the file COPYRIGHT for
   details.

   Encrypt message for Mixmaster chain
   $Id$ */


#include "mix3.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>
#include <assert.h>

#define N(X) (isdigit(X) ? (X)-'0' : 0)

int prepare_type2list(BUFFER *out)
{
  FILE *list;
  char line[LINELEN], name[LINELEN], addr[LINELEN], keyid[LINELEN],
  version[LINELEN], flags[LINELEN], createdstr[LINELEN], expiresstr[LINELEN];
  int assigned;
  time_t created, expires;

  list = mix_openfile(PUBRING, "r");
  if (list == NULL)
    return (-1);
  while (fgets(line, sizeof(line), list) != NULL) {
    if (strleft(line, begin_key)) {
      while (fgets(line, sizeof(line), list) != NULL &&
	     !strleft(line, end_key)) ;
    } else if (strlen(line) > 36 && line[0] != '#') {
      assigned = sscanf(line, "%127s %127s %127s %127s %127s %127s %127s",
		 name, addr, keyid, version, flags, createdstr, expiresstr);
      if (assigned < 4)
	continue;
      if (assigned >= 6) {
	created = parse_yearmonthday(createdstr);
	if (created == 0 || created == -1) {
	  errlog(WARNING, "Cannot parse creation date of key %s.\n", keyid);
	  continue;
	};
	if (created > time(NULL)) {
	  errlog(WARNING, "Key %s created in the future.\n", keyid);
	  continue;
	};
      }
      if (assigned >= 7) {
	expires = parse_yearmonthday(expiresstr);
	if (expires == 0 || expires == -1) {
	  errlog(WARNING, "Cannot parse expiration date of key %s.\n", keyid);
	  continue;
	};
	if (expires < time(NULL)) {
	  errlog(WARNING, "Key %s has expired.\n", keyid);
	  continue;
	};
      }
      buf_appends(out, line);
    }
  }
  fclose(list);
  return (0);
}

int mix2_rlist(REMAILER remailer[], int badchains[MAXREM][MAXREM])
{
  FILE *list, *excl;
  int n, i, listed = 0;

  char line[LINELEN], name[LINELEN], addr[LINELEN], keyid[LINELEN],
  version[LINELEN], flags[LINELEN], createdstr[LINELEN], expiresstr[LINELEN];
  char textkeyid[LINELEN][MAXREM];
  int flag4log[MAXREM];
  int assigned, nw, k, rsalen;
  time_t created, expires;
  BUFFER *starex;

  starex = buf_new();
  excl = mix_openfile(STAREX, "r");
  if (excl != NULL) {
    buf_read(starex, excl);
    fclose(excl);
  }

  list = mix_openfile(PUBRING, "r");
  if (list == NULL) {
    buf_free(starex);
    return (-1);
  }
  /* Loop to fill the array starts at 1 leaving remailer[0] to represent a random choice. */
  for (n = 1; fgets(line, sizeof(line), list) != NULL && n < MAXREM;)
    if (strlen(line) > 50 && line[0] != '#') {
      flags[0] = '\0';
      assigned = sscanf(line, "%127s %127s %127s %127s %127s %127s %127s",
		 name, addr, keyid, version, flags, createdstr, expiresstr);
      if (assigned < 4)
	continue;
      expires=0;
      rsalen=0;
      while (fgets(line, sizeof(line), list) != NULL && !strleft(line, end_key))  {
          if (!rsalen) {
              if (!strcmp(line,"258\n")) rsalen=1024;
              if (!strcmp(line,"514\n")) rsalen=2048;
              if (!strcmp(line,"770\n")) rsalen=3072;
              if (!strcmp(line,"1026\n")) rsalen=4096;
          }
      }
      if (assigned >= 6) {
	created = parse_yearmonthday(createdstr);
	if (created == 0 || created == -1) {
	  errlog(WARNING, "Cannot parse creation date of key %s.\n", keyid);
	  continue;
	};
	if (created > time(NULL)) {
	  errlog(WARNING, "Key %s created in the future.\n", keyid);
	  continue;
	};
      }
      if (assigned >= 7) {
	expires = parse_yearmonthday(expiresstr);
	if (expires == 0 || expires == -1) {
	  errlog(WARNING, "Cannot parse expiration date of key %s.\n", keyid);
	  continue;
	};
	if (expires < time(NULL)) {
	  errlog(WARNING, "Key %s has expired.\n", keyid);
	  continue;
	};
      }
      /* Have we seen the same remailer multple times in the list? */
      nw=n; /* array index to write to */
      for (k=0;(k<n) && (nw==n);k++) {
          int eqname=0, eqaddr=0;
          if (strieq(name, remailer[k].name))
              eqname=1;
          if (strieq(addr, remailer[k].addr))
              eqaddr=2;
          switch (eqname+eqaddr) {
              case 0:
                  /* normal - no confusion */
                  break;
              case 1:
                  errlog(WARNING, "remailer name %s used with addresses %s and %s\n",
                                   name, addr, remailer[k].addr);
                  break;
              case 2:
                  errlog(WARNING, "remailer address %s used with names %s and %s\n",
                                   addr, name, remailer[k].name);
                  break;
              case 3:
                  /* The same remailer has appeared twice in pubring.mix which is ok but
                   * it means we must prefer one entry over another.
                   * Either keep the exiting array entry (by "continue")
                   * or proceed with this loop after setting nw=k (instead of n).
                   * Earlier expiry is preferred.
                   * A larger key size (2048 vs 1024) is preferred more strongly.
                   */
                   if ((rsalen>remailer[k].rsalen) ||
                       ((rsalen==remailer[k].rsalen) && (expires) &&
                        (expires < remailer[k].expires) && (expires > time(NULL)) )) {
/* Key expiry time is when you need to stop sending with that key */
/* so expires is compared to time() and the extra grace period is done in the remailer. */
                       nw=k;    /* overwrite earlier data with this */
                   } else {
                       nw=-1;   /* keep earlier data and ignore this */
                   }
                   flag4log[k]=1;
                  break;
              default:
	          errlog(WARNING, "unreachable code reached\n");
                  return(-1);
                  break;
          }
      }
      if (nw<0) continue;
      strncpy(remailer[nw].name, name, sizeof(remailer[nw].name));
      remailer[nw].name[sizeof(remailer[nw].name) - 1] = '\0';
      strncpy(remailer[nw].addr, addr, sizeof(remailer[nw].addr));
      remailer[nw].addr[sizeof(remailer[nw].addr) - 1] = '\0';
      remailer[nw].flags.mix = 1;
      remailer[nw].flags.cpunk = 0;
      remailer[nw].flags.nym = 0;
      remailer[nw].flags.newnym = 0;
      strncpy(textkeyid[nw],keyid,sizeof(textkeyid[nw]));  /* saves converting back to text to show in stderr */
      textkeyid[nw][sizeof(textkeyid[nw]) - 1] = '\0';
      id_decode(keyid, remailer[nw].keyid);
      remailer[nw].version = N(version[0]);
      remailer[nw].flags.compress = strfind(flags, "C");
      remailer[nw].flags.post = strfind(flags, "N");
      remailer[nw].flags.middle = strfind(flags, "M");
      remailer[nw].info[0].reliability = 0;
      remailer[nw].info[0].latency = 0;
      remailer[nw].info[0].history[0] = '\0';
      remailer[nw].flags.star_ex = bufifind(starex, name);
      remailer[nw].expires=expires;
      remailer[nw].rsalen=rsalen;
#ifdef SHOW_KEYID_SELECTION
      fprintf(stderr, "STORING nw=%d %s %s has rsalen=%d exp=%d\n",
      nw, remailer[nw].name, textkeyid[nw], remailer[nw].rsalen, remailer[nw].expires);
#endif
      if (nw == n) n++;
    }
  fclose(list);
  for (k=1;k<n;k++) { /* start from 1 */
      if (flag4log[k] && mix_global_verbose) 
          fprintf(stderr, "For %s keyid %s (%d-bit) was chosen.\n", remailer[k].name, textkeyid[k], remailer[k].rsalen);
          /* This is printed to stderr but not logged - not using errlog(). */
  }
  list = mix_openfile(TYPE2REL, "r");
  if (list != NULL) {
    while (fgets(line, sizeof(line), list) != NULL &&
	   !strleft(line, "--------------------------------------------")) {
      if (strleft(line, "Last update:")) {
        int generated;
	int now = time(NULL);
	char *tmp = line + strlen("Last update:") + 1;
	generated = parsedate(tmp);
	if (generated == -1) {
	  /* For some weird reason, this isn't rfc822 */
	  if (strleft(tmp, "Mon") ||
	      strleft(tmp, "Tue") ||
	      strleft(tmp, "Wed") ||
	      strleft(tmp, "Thu") ||
	      strleft(tmp, "Fri") ||
	      strleft(tmp, "Sat") ||
	      strleft(tmp, "Sun"))
	    tmp += 3;
          generated = parsedate(tmp);
	}
	now = time(NULL);
	if (generated != -1 && generated < now - SECONDSPERDAY)
	  errlog(WARNING, "Remailer Reliability Statistics are older than one day (check your clock?).\n");
	if (generated != -1 && generated > now)
	  errlog(WARNING, "Remailer Reliability Statistics are from the future (check your clock?).\n");
      }
    };
    while (fgets(line, sizeof(line), list) != NULL &&
	   !strleft(line, "</PRE>"))
      if (strlen(line) >= 44 && strlen(line) <= 46)
	for (i = 1; i < n; i++)
	  if (strleft(line, remailer[i].name) &&
	      line[strlen(remailer[i].name)] == ' ') {
	    strncpy(remailer[i].info[0].history, line + 15, 12);
	    remailer[i].info[0].history[12] = '\0';
	    remailer[i].info[0].reliability = 10000 * N(line[37])
	      + 1000 * N(line[38]) + 100 * N(line[39])
	      + 10 * N(line[41]) + N(line[42]);
	    remailer[i].info[0].latency = 36000 * N(line[28])
	      + 3600 * N(line[29]) + 600 * N(line[31])
	      + 60 * N(line[32]) + 10 * N(line[34])
	      + N(line[35]);
	    listed++;
	  }
    fclose(list);
  }

  parse_badchains(badchains, TYPE2REL, "Broken type-II remailer chains", remailer, n);
  if (listed < 4)		/* we have no valid reliability info */
    for (i = 1; i < n; i++)
      remailer[i].info[0].reliability = 10000;
  buf_free(starex);
  return (n);
}

static int send_packet(int numcopies, BUFFER *packet, int chain[],
		       int chainlen, int packetnum, int numpackets,
		       BUFFER *mid, REMAILER remailer[], int badchains[MAXREM][MAXREM],
		       int maxrem, char *redirect_to, int ignore_constraints_if_necessary,
		       BUFFER *feedback)
/*
 * Puts a mix packet in the pool.
 *
 * numcopies   ... how often to put this packet into the pool
 *                 i.e. send it.  required that random remailers are in the chain.
 * packet      ... the payload, 10240 bytes in size.
 * chain       ... the chain to send this message along
 * chainlen    ... length of the chain
 * packetnum   ... in multi-packet messages (fragmented) the serial of this packet
 * numpackets  ...  the total number of packets
 * mid         ... the message ID (required for fragmented packets
 * remailer    ... information about remailers, their reliabilities, capabilities, etc.
 * badchains   ... broken chain information
 * maxrem      ... the number of remailers in remailer[] and badchains[]
 * redirect_to ... if this is not-null it needs to be an email address.
 *                 in this case packet needs to be not only the body, but a
 *                 complete mixmaster packet of 20480 bytes in size (20 headers + body).
 *                 the chain given is prepended to the one already encrypted in
 *                 the existing message.  If this exceeds the allowed 20 hops in total
 *                 the message is corrupted, the last node will realize this.
 *                 This is useful if you want to reroute an existing mixmaster message
 *                 that has foo as the next hop via a chain so that the packet will
 *                 actually flow hop1,hop2,hop3,foo,....
 * ignore_constraints_if_necessary .. to be used when randhopping messages.
 *                 if a chain can not be constructed otherwhise, maxlat, minlat,
 *                 and minrel are ignored.
 * feedback    ... a buffer to write feedback to
 */
{
  BUFFER *pid, *out, *header, *other, *encrypted, *key, *body;
  BUFFER *iv, *ivarray, *temp, *hkey, *antitag, *aes_pre_key;
  BUFFER *pubkey, *aes_header_key, *aes_tte_key, *aes_body_key, *aes_iv;
  char addr[LINELEN];
  int thischain[20];
  int hop;
  int c, i;
  int timestamp = 0;
  int israndom = 0;
  int err = 1;

  body = buf_new();
  pid = buf_new();
  out = buf_new();
  header = buf_new();
  other = buf_new();
  key = buf_new();
  encrypted = buf_new();
  iv = buf_new();
  ivarray = buf_new();
  temp = buf_new();
  hkey = buf_new();
  antitag = buf_new();
  aes_pre_key = buf_new();
  aes_header_key=buf_new();
  aes_body_key=buf_new();
  aes_tte_key=buf_new();
  aes_iv=buf_new();

  temp->sensitive=1;
  hkey->sensitive=1;
  aes_pre_key->sensitive=1;
  aes_header_key->sensitive=1;
  aes_body_key->sensitive=1;
  aes_tte_key->sensitive=1;

  if (redirect_to != NULL) {
    assert(packet->length == 20480);
    buf_append(header, packet->data, 10240);
    buf_append(temp, packet->data + 10240, 10240);
    buf_clear(packet);
    buf_cat(packet, temp);
  } else 
    assert(packet->length == 10240);

  buf_setrnd(pid, 16);

  for (c = 0; c < numcopies; c++) {
    buf_set(body, packet);

    for (hop = 0; hop < chainlen; hop++)
      thischain[hop] = chain[hop];

    israndom = chain_rand(remailer, badchains, maxrem, thischain, chainlen, 0, ignore_constraints_if_necessary);
    if (israndom == -1) {
      err = -1;
      clienterr(feedback, "No reliable remailers!");
    }
    if ((numcopies > 1 || numpackets > 1) && !israndom && (chainlen != 1)) {
      clienterr(feedback,
		"Multi-packet message without random remailers!");
      err = -1;
      goto end;
    }
    for (hop = 0; hop < chainlen; hop++) {
      switch (remailer[thischain[hop]].version) {
      case 2:
      case 3:			/* not implemented yet; fall back to version 2 */
	/* create header chart to be encrypted with the session key */
	if (numcopies > 1 && hop == 0 && redirect_to == NULL)
	  buf_set(encrypted, pid);	/* same ID only at final hop */
	else
	  buf_setrnd(encrypted, 16);
	buf_setrnd(key, 24);	/* key for encrypting the body */
	buf_cat(encrypted, key);
	buf_setrnd(iv, 8);	/* IV for encrypting the body */

	if (hop > 0 || redirect_to != NULL) {
	  /* IVs for header chart encryption */
	  buf_setrnd(ivarray, 18 * 8);
	  buf_cat(ivarray, iv);	/* 19th IV equals the body IV */

	  buf_appendc(encrypted, 0);  /* packet type is intermediate */
	  buf_cat(encrypted, ivarray);
	  memset(addr, 0, 80);
	  if (hop == 0) {
	    assert(redirect_to != NULL);
	    strncpy(addr, redirect_to, 80);
	  } else {
	    assert(hop > 0);
	    strcpy(addr, remailer[thischain[hop - 1]].addr);
	  };
	  buf_append(encrypted, addr, 80);
	} else {
	  if (numpackets == 1)
	    buf_appendc(encrypted, 1);
	  else {
	    buf_appendc(encrypted, 2);
	    buf_appendc(encrypted, (byte) packetnum);
	    buf_appendc(encrypted, (byte) numpackets);
	  }
	  buf_cat(encrypted, mid);
	  buf_cat(encrypted, iv);	/* body encryption IV */
	}

	if (hop > 0 || redirect_to != NULL) {
	  /* encrypt the other header charts */
	  buf_clear(other);
	  for (i = 0; i < 19; i++) {
	    buf_clear(iv);
	    buf_clear(temp);
	    buf_append(iv, ivarray->data + 8 * i, 8);
	    buf_append(temp, header->data + 512 * i, 512);
	    buf_crypt(temp, key, iv, ENCRYPT);
	    buf_cat(other, temp);
	  }
	} else
	  buf_setrnd(other, 19 * 512);	/* fill with random data */

	/* timestamp */
	buf_appends(encrypted, "0000");
	buf_appendc(encrypted, '\0');	/* timestamp magic */
	timestamp = time(NULL) / SECONDSPERDAY - rnd_number(4);
	buf_appendi_lo(encrypted, timestamp);

        /* There's been some reordering round here to have "other" and "pubkey" known before finalising the 328-block. */
	pubkey = buf_new();
	err = db_getpubkey(remailer[thischain[hop]].keyid, pubkey);
	if (err == -1)
	  goto end;

	/* message digest for this header */
	digest_md5(encrypted, temp);
	buf_cat(encrypted, temp);
	buf_pad(encrypted, 328);

	/* encrypt message body with 3DES */
	buf_crypt(body, key, iv, ENCRYPT);

	/* create session key and IV to encrypt the header ... */
	buf_setrnd(key, 24);
	buf_setrnd(iv, 8);
	buf_crypt(encrypted, key, iv, ENCRYPT);
        if (258==pubkey->length) {
            /* traditional 24-bytes of 3DES with 1k RSA */
	    err = pk_encrypt(key, pubkey);	/* ... and encrypt the session key */
        } else {
            /* More data with the 3DES key inside the RSA encryption. */

            /* See Tom Ritter https://crypto.is/blog/tagging_attack_on_mixmaster */
            /* This is not done for 1k RSA keys to keep compatibility with old remailers. */
	    /*
             *  24    3deskey     (already in variable "key" then we append to it)
             *  64    hmac_key
             *  32    hmac(2*512 of other) (except in hop 0)
             *  32    hmac(body)
             *  32    hmac(328block)
             *  32    aes_pre_key
             */

            buf_reset(hkey);
            buf_setrnd(hkey, 64);  /* compulsory length unless extended by 0s */
            /* hmac key*/    buf_cat(key, hkey);
            /* generate aes keys */
                buf_reset(aes_pre_key);
                buf_setrnd(aes_pre_key, 32);
                derive_aes_keys(aes_pre_key, hkey,
                                aes_header_key, aes_body_key, aes_tte_key, aes_iv);

/*
               fprintf(stderr, "  BODY KEY=%s\n", showdata(aes_body_key,0));
               fprintf(stderr, "HEADER KEY=%s\n", showdata(aes_header_key,0));
               fprintf(stderr, "   TTE KEY=%s\n", showdata(aes_tte_key,0));
               fprintf(stderr, "        IV=%s\n", showdata(aes_iv,0));
*/
               buf_aescrypt(encrypted, aes_tte_key, aes_iv, ENCRYPT);
               buf_aescrypt(body, aes_body_key, aes_iv, ENCRYPT);
               buf_aescrypt(other, aes_header_key, aes_iv, ENCRYPT);

            /* Only 2*512 headers covered by digest so no remailer can tell where it is in the chain. */
                if (!hop) {
                  /* Hop 0 (final) should not have a valid HMAC of the following heaer.
                   * If it did that would tell the exit remailer whether the chain was
                   * maximum length (e.g. 10 hops with large keys).
                   */
                        buf_reset(temp);
	                buf_setrnd(temp,32);
                } else {
                        buf_reset(antitag);
                        buf_append(antitag, other->data, 2*512);
                        buf_reset(temp);
	                hmac_sha256(antitag, hkey, temp);
                }
            /* antitag */   buf_cat(key, temp);
                        buf_reset(temp);
	                hmac_sha256(body, hkey, temp);
            /* body */   buf_cat(key, temp);

                        buf_reset(temp);
	                hmac_sha256(encrypted, hkey, temp);
            /* encrypted-328-block */   buf_cat(key, temp);

            /* AES pre key */  buf_cat(key, aes_pre_key);

	    err = pk_encrypt(key, pubkey);	/* ... and encrypt the session key etc  */
        }

	buf_free(pubkey);
	if (err == -1 ||
            (key->length != 128 && key->length != 256  &&
	     key->length != 384 && key->length != 512)) {
	  clienterr(feedback, "Encryption failed!");
	  err = -1;
	  goto end;
	}

	/* now build the new header */
	buf_clear(header);
	buf_append(header, remailer[thischain[hop]].keyid, 16);
        /* one byte to show RSA length */
        switch(key->length) {
            case 128:
              /* Legacy 1024-bit RSA means 128 bytes. */
	      buf_appendc(header, 128);
              break;
            case 256:
	      buf_appendc(header, 2); /* 2048 */
              break;
            case 384:
	      buf_appendc(header, 3); /* 3072 */
              break;
            case 512:
	      buf_appendc(header, 4); /* 4096 */
              break;
            default:
	      clienterr(feedback, "RSA key size not acceptable!");
	      err = -1;
	      goto end;
              break;
        }
	buf_cat(header, key);
	buf_cat(header, iv);
	buf_cat(header, encrypted);
	buf_pad(header, key->length==128 ? 512:1024);  /* 512 bytes if RSA is 1024 bits */
        if (128==key->length) 
            buf_cat(header, other);
        else
            buf_append(header, other->data, 18*512);
	break;
      default:
	err = -1;
	goto end;
      }
    }

    /* build the message */
    buf_sets(out, remailer[thischain[chainlen - 1]].addr);
    buf_nl(out);
    buf_cat(out, header);
    buf_cat(out, body);
    assert(header->length == 10240 && body->length == 10240);
    mix_pool(out, INTERMEDIATE, -1);

    if (feedback) {
      for (hop = chainlen - 1; hop >= 0; hop--) {
	buf_appends(feedback, remailer[thischain[hop]].name);
	if (hop > 0)
	  buf_appendc(feedback, ',');
      }
      buf_nl(feedback);
    }
  }
	   
 end:
  buf_free(aes_body_key);
  buf_free(aes_header_key);
  buf_free(aes_iv);
  buf_free(aes_pre_key);
  buf_free(aes_tte_key);
  buf_free(antitag);
  buf_free(body);
  buf_free(encrypted);
  buf_free(header);
  buf_free(hkey);
  buf_free(iv);
  buf_free(ivarray);
  buf_free(key);
  buf_free(other);
  buf_free(out);
  buf_free(pid);
  buf_free(temp);

  return (err);
}

int redirect_message(BUFFER *sendmsg, char *chainstr, int numcopies, BUFFER *feedback)
{
  BUFFER *field;
  BUFFER *content;
  BUFFER *line;
  char recipient[80] = "";
  int num = 0;
  int err = 0;
  int c;
  int hop;

  REMAILER remailer[MAXREM];
  int chain[20];
  int thischain[20];
  int chainlen;
  int badchains[MAXREM][MAXREM];
  int maxrem;
  int tempchain[20];
  int tempchainlen;
  int israndom;

  field = buf_new();
  content = buf_new();
  line = buf_new();

  if (numcopies == 0)
    numcopies = NUMCOPIES;
  if (numcopies > 10)
    numcopies = 10;

  /* Find the recipient */
  while (buf_getheader(sendmsg, field, content) == 0)
    if (bufieq(field, "to")) {
      strncpy(recipient, content->data, sizeof(recipient));
      num++;
    };
  if (num != 1) {
    clienterr(feedback, "Did not find exactly one To: address!");
    err = -1;
    goto end;
  };

  /* Dearmor the message */
  err = mix_dearmor(sendmsg, sendmsg);
  if (err == -1)
    goto end;
  assert (sendmsg->length == 20480);

  /* Check the chain */
  maxrem = mix2_rlist(remailer, badchains);
  if (maxrem < 1) {
    clienterr(feedback, "No remailer list!");
    err = -1;
    goto end;
  }
  chainlen = chain_select(chain, chainstr, maxrem, remailer, 0, line);
  if (chainlen < 1) {
    if (line->length)
      clienterr(feedback, line->data);
    else
      clienterr(feedback, "Invalid remailer chain!");
    err = -1;
    goto end;
  } else if (chainlen >= 20) {
    clienterr(feedback, "A chainlength of 20 will certainly destroy the message!");
    err = -1;
    goto end;
  };


  for (c = 0; c < numcopies; c++) {
    /* if our recipient is a remailer we want to make sure we're not using a known broken chain.
     * therefore we need to pick the final remailer with care */
    for (hop = 0; hop < chainlen; hop++)
      thischain[hop] = chain[hop];
    if (thischain[0] == 0) {
      /* Find out, if recipient is a remailer */
      tempchainlen = chain_select(tempchain, recipient, maxrem, remailer, 0, line);
      if (tempchainlen < 1 && line->length == 0) {
	/* recipient is apparently not a remailer we know about */
	;
      } else {
	/* Build a new chain, based on the one we already selected but
	 * with the recipient as the final hop.
	 * This is so that chain_rand properly selects nodes based on
	 * broken chains and DISTANCE */
	assert(chainlen < 20);
	for (hop = 0; hop < chainlen; hop++)
	  thischain[hop+1] = thischain[hop];
	thischain[0] = tempchain[0];

	israndom = chain_rand(remailer, badchains, maxrem, thischain, chainlen + 1, 0, 0);
	if (israndom == -1) {
	  err = -1;
	  clienterr(feedback, "No reliable remailers!");
	  goto end;
	}

	/* Remove the added recipient hop */
	for (hop = 0; hop < chainlen; hop++)
	  thischain[hop] = thischain[hop + 1];
      };
    };

    /* queue the packet */
    if (send_packet(1, sendmsg, thischain, chainlen,
	    -1, -1, NULL,
	    remailer, badchains, maxrem, recipient, 0, feedback) == -1)
      err = -1;
  };

end:
  buf_free(field);
  buf_free(content);
  buf_free(line);
  return (err);
}

int mix2_encrypt(int type, BUFFER *message, char *chainstr, int numcopies,
		 int ignore_constraints_if_necessary,
		 BUFFER *feedback)
{
  /* returns 0 on success, -1 on error. feedback contains the selected
     remailer chain or an error message

   ignore_constraints_if_necessary .. to be used when randhopping messages.
                                   if a chain can not be constructed otherwhise,
                                   maxlat, minlat, and minrel are ignored.
     */

  REMAILER remailer[MAXREM];
  int badchains[MAXREM][MAXREM];
  int maxrem;
  BUFFER *line, *field, *content, *header, *msgdest, *msgheader, *body,
      *temp, *mid;
  byte numdest = 0, numhdr = 0;
  char hdrline[LINELEN];
  BUFFER *packet;
  int chain[20];
  int chainlen;
  int i;
  int err = 0;

  mix_init(NULL);
  packet = buf_new();
  line = buf_new();
  field = buf_new();
  content = buf_new();
  msgheader = buf_new();
  msgdest = buf_new();
  body = buf_new();
  temp = buf_new();
  mid = buf_new();
  header = buf_new();
  if (feedback)
    buf_reset(feedback);

  if (numcopies == 0)
    numcopies = NUMCOPIES;
  if (numcopies > 10)
    numcopies = 10;

  maxrem = mix2_rlist(remailer, badchains);
  if (maxrem < 1) {
    clienterr(feedback, "No remailer list!");
    err = -1;
    goto end;
  }
  chainlen = chain_select(chain, chainstr, maxrem, remailer, 0, line);
  if (chainlen < 1) {
    if (line->length)
      clienterr(feedback, line->data);
    else
      clienterr(feedback, "Invalid remailer chain!");
    err = -1;
    goto end;
  }
  if (chain[0] == 0)
    chain[0] = chain_randfinal(type, remailer, badchains, maxrem, 0, chain, chainlen, ignore_constraints_if_necessary);

  if (chain[0] == -1) {
    clienterr(feedback, "No reliable remailers!");
    err = -1;
    goto end;
  }
  switch (remailer[chain[0]].version) {
  case 2:
    if (type == MSG_NULL) {
      memset(hdrline, 0, 80);
      strcpy(hdrline, "null:");
      buf_append(msgdest, hdrline, 80);
      numdest++;
    } else
      while (buf_getheader(message, field, content) == 0) {
	if (bufieq(field, "to")) {
	  memset(hdrline, 0, 80);
	  strncpy(hdrline, content->data, 80);
	  buf_append(msgdest, hdrline, 80);
	  numdest++;
	} else if (type == MSG_POST && bufieq(field, "newsgroups")) {
	  memset(hdrline, 0, 80);
	  strcpy(hdrline, "post: ");
	  strcatn(hdrline, content->data, 80);
	  buf_append(msgdest, hdrline, 80);
	  numdest++;
	} else {
	  buf_clear(header);
	  buf_appendheader(header, field, content);
	  hdr_encode(header, 80);
	  while (buf_getline(header, line) == 0) {
	    /* paste in encoded header entry */
	    memset(hdrline, 0, 80);
	    strncpy(hdrline, line->data, 80);
	    buf_append(msgheader, hdrline, 80);
	    numhdr++;
	  }
	}
      }
    buf_appendc(body, numdest);
    buf_cat(body, msgdest);
    buf_appendc(body, numhdr);
    buf_cat(body, msgheader);

    if (type != MSG_NULL) {
      buf_rest(temp, message);
      if (temp->length > 10236 && remailer[chain[0]].flags.compress)
	buf_compress(temp);
      buf_cat(body, temp);
      buf_reset(temp);
    }
    buf_setrnd(mid, 16);	/* message ID */
    for (i = 0; i <= body->length / 10236; i++) {
      long length;

      length = body->length - i * 10236;
      if (length > 10236)
	length = 10236;
      buf_clear(packet);
      buf_appendl_lo(packet, length);
      buf_append(packet, body->data + i * 10236, length);
      buf_pad(packet, 10240);
      if (send_packet(numcopies, packet, chain, chainlen,
		      i + 1, body->length / 10236 + 1,
		      mid, remailer, badchains, maxrem, NULL, ignore_constraints_if_necessary, feedback) == -1)
	err = -1;
    }
    break;
  case 3:
    NOT_IMPLEMENTED;
    break;
  default:
    fprintf(stderr, "%d\n", chain[0]);
    clienterr(feedback, "Unknown remailer version!");
    err = -1;
  }

end:
  buf_free(packet);
  buf_free(line);
  buf_free(field);
  buf_free(content);
  buf_free(header);
  buf_free(msgheader);
  buf_free(msgdest);
  buf_free(body);
  buf_free(temp);
  buf_free(mid);
  return (err);
}
