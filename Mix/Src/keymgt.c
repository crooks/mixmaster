/* Mixmaster version 3.0  --  (C) 1999 - 2006 Anonymizer Inc. and others.

   Mixmaster may be redistributed and modified under certain conditions.
   This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF
   ANY KIND, either express or implied. See the file COPYRIGHT for
   details.

   Key management
   $Id$ */


#include "mix3.h"
#include <string.h>
#include <time.h>
#include <assert.h>

int getv2seckey(byte keyid[], BUFFER *key);
static int getv2pubkey(byte keyid[], BUFFER *key);

int db_getseckey(byte keyid[], BUFFER *key)
{
  if (getv2seckey(keyid, key) == -1)
    return (-1);
  else
    return (0);
}

int db_getpubkey(byte keyid[], BUFFER *key)
{
  if (getv2pubkey(keyid, key) == -1)
    return (-1);
  else
    return (0);
}

/* now accepts NULL keyid too, with NULL keyid any key
 * will be matched, with valid passphrase of course */
int getv2seckey(byte keyid[], BUFFER *key)
{
  FILE *keyring;
  BUFFER *iv, *pass, *temp;
  char idstr[KEY_ID_LEN+2];
  char line[LINELEN];
  int err = -1;
  char *res;
  time_t created, expires;

  pass = buf_new();
  iv = buf_new();
  temp = buf_new();
  if (keyid)
    id_encode(keyid, idstr);
  else
    idstr[0] = 0;
  strcat(idstr, "\n");
  if ((keyring = mix_openfile(SECRING, "r")) == NULL) {
    errlog(ERRORMSG, "No secret key file!\n");
  } else {
    while (err == -1) {
      buf_clear(key);
      if (fgets(line, sizeof(line), keyring) == NULL)
	break;
      if (strleft(line, begin_key)) {
	expires = 0;
	created = 0;
	do {
	  res = fgets(line, sizeof(line), keyring);
	  if (strileft(line, "created:")) {
	    created = parse_yearmonthday(strchr(line, ':')+1);
	    if (created == -1)
	      created = 0;
	  } else if (strileft(line, "expires:")) {
	    expires = parse_yearmonthday(strchr(line, ':')+1);
	    if (expires == -1)
	      expires = 0;
	  }
	  /* Fetch lines until we fail or get a non-header line */
	} while ( res != NULL && strchr(line, ':') != NULL );
	if (res == NULL)
	  break;
	if (keyid && (strncmp(line, idstr, KEY_ID_LEN) != 0))
	  continue;
	if (created != 0 && (created > time(NULL))) {
	  errlog(ERRORMSG, "Key is not valid yet (creation date in the future): %s", idstr);
	  break;
	}
	if (expires != 0 && (expires + KEYGRACEPERIOD < time(NULL))) {
	  errlog(ERRORMSG, "Key is expired: %s", idstr);
	  break;
	}
	fgets(line, sizeof(line), keyring);
	fgets(line, sizeof(line), keyring);
	buf_sets(iv, line);
	decode(iv, iv);
	for (;;) {
	  if (fgets(line, sizeof(line), keyring) == NULL)
	    break;
	  if (strleft(line, end_key)) {
	    if (decode(key, key) == -1) {
	      errlog(ERRORMSG, "Corrupt secret key.\n");
	      break;
	    }
	    buf_sets(pass, PASSPHRASE);
	    digest_md5(pass, pass);
	    buf_crypt(key, pass, iv, DECRYPT);
	    err = check_seckey(key, keyid);
	    if (err == -1)
	      errlog(ERRORMSG, "Corrupt secret key. Bad passphrase?\n");
	    break;
	  }
	  buf_append(key, line, strlen(line) - 1);
	}
	break;
      }
    }
    fclose(keyring);
  }

  buf_free(pass);
  buf_free(iv);
  buf_free(temp);
  return (err);
}

static int getv2pubkey(byte keyid[], BUFFER *key)
{
  FILE *keyring;
  BUFFER *b, *temp, *iv;
  char idstr[KEY_ID_LEN+2];
  char line[LINELEN];
  int err = 0;

  b = buf_new();
  iv = buf_new();
  temp = buf_new();
  id_encode(keyid, idstr);
  if ((keyring = mix_openfile(PUBRING, "r")) == NULL) {
    errlog(ERRORMSG, "Can't open %s!\n", PUBRING);
    err = -1;
    goto end;
  }
  for (;;) {
    if (fgets(line, sizeof(line), keyring) == NULL)
      break;
    if (strleft(line, begin_key)) {
      if (fgets(line, sizeof(line), keyring) == NULL)
	break;
      if ((strlen(line) > 0) && (line[strlen(line)-1] == '\n'))
	line[strlen(line)-1] = '\0';
      if ((strlen(line) > 0) && (line[strlen(line)-1] == '\r'))
	line[strlen(line)-1] = '\0';
      if (strncmp(line, idstr, KEY_ID_LEN) != 0)
	continue;
      fgets(line, sizeof(line), keyring);	/* ignore length */
      for (;;) {
	if (fgets(line, sizeof(line), keyring) == NULL)
	  goto done;
	if (strleft(line, end_key))
	  goto done;
	buf_append(key, line, strlen(line));
      }
      break;
    }
  }
done:
  fclose(keyring);

  if (key->length == 0) {
    errlog(ERRORMSG, "No such public key: %s\n", idstr);
    err = -1;
    goto end;
  }
  err = decode(key, key);
  if (err != -1)
    err = check_pubkey(key, keyid);
  if (err == -1)
    errlog(ERRORMSG, "Corrupt public key %s\n", idstr);
end:
  buf_free(b);
  buf_free(iv);
  buf_free(temp);
  return (err);
}

int key(BUFFER *out)
{
  int err = -1;
  FILE *f;
  BUFFER *tmpkey;

  tmpkey = buf_new();

  buf_sets(out, "Subject: Remailer key for ");
  buf_appends(out, SHORTNAME);
  buf_appends(out, "\n\n");

  keymgt(0,0,4096);

  conf_premail(out);
  buf_nl(out);

#ifdef USE_PGP
  if (PGP) {
    if (pgp_latestkeys(tmpkey, PGP_ES_RSA) == 0) {
      buf_appends(out, "Here is the RSA PGP key:\n\n");
      buf_cat(out, tmpkey);
      buf_nl(out);
      err = 0;
    }
    if (pgp_latestkeys(tmpkey, PGP_S_DSA) == 0) {
      buf_appends(out, "Here is the DSA PGP key:\n\n");
      buf_cat(out, tmpkey);
      buf_nl(out);
      err = 0;
    }
  }
#endif /* USE_PGP */
  if (MIX) {
    if (((f = mix_openfile("all_my_pubkeys.txt", "r")) != NULL) ||
        ((f = mix_openfile(KEYFILE, "r")) != NULL)) {
      buf_appends(out, "Here is the Mixmaster key:\n");
      buf_appends(out, "Use only one mixmaster key per remailer unless your client can handle multiple.\n");
      buf_appends(out, "A key length of '258' in this file means 1024-bit RSA as y=(x-2)*4.\n");
      buf_appends(out, "1024-bits offers inferior security to the larger keys that require at least version 3.0.2.\n");
      buf_appends(out, "http://www.zen19351.zen.co.uk/mixmaster302/\n\n");
      buf_appends(out, "=-=-=-=-=-=-=-=-=-=-=-=\n");
      buf_read(out, f);
      buf_nl(out);
      fclose(f);
      err = 0;
    }
  }
  if (err == -1 && UNENCRYPTED) {
    buf_appends(out, "The remailer accepts unencrypted messages.\n");
    err = 0;
  }
  if (err == -1)
    errlog(ERRORMSG, "Cannot create remailer keys!");

  buf_free(tmpkey);

  return (err);
}

int adminkey(BUFFER *out)
{
	int err = -1;
	FILE *f;

	buf_sets( out, "Subject: Admin key for the " );
	buf_appends( out, SHORTNAME );
	buf_appends( out, " remailer\n\n" );

	if ( (f = mix_openfile( ADMKEYFILE, "r" )) != NULL ) {
	        buf_read( out, f );
	        buf_nl( out );
	        fclose( f );
	        err = 0;
	}

	if ( err == -1 )
	        errlog( ERRORMSG, "Can not read admin key file!\n" );

	return err;
}

int v2keymgt(int force,long int lifeindays,long int keysize)
/*
 * Mixmaster v2 Key Management
 *
 * This function triggers creation of mix keys (see parameter force) which are
 * stored in secring.mix. One public mix key is also written to key.txt. This
 * is the key with the latest expiration date (keys with no expiration date
 * are always considered newer if they appear later in the secret mix file 
 * - key creation appends keys).
 *
 * force:
 *   0, 1: create key when necessary:
 *          - no key exists as of yet
 *          - old keys are due to expire/already expired
 *   2: always create a new mix key.
 *
 *   (force = 0 is used in mix_daily, and before remailer-key replies)
 *   (force = 1 is used by mixmaster -K)
 *   (force = 2 is used by mixmaster -G)
 */
{
  FILE *keyring, *all_pub, *f;
  char line[LINELEN];
  byte k1[16], k1_found[16];
  BUFFER *b, *temp, *iv, *pass, *pk, *pk_found, *pk_temp;
  int err = 0;
  int found, foundnonexpiring;
  time_t created, expires, created_found, expires_found;
  int need2delete=0;
  char *res;

  b = buf_new();
  temp = buf_new();
  iv = buf_new();
  pass = buf_new();
  pk = buf_new();
  pk_found = buf_new();

  foundnonexpiring = 0;
  for (;;) {
    found = 0;
    created_found = 0;
    expires_found = 0;

    all_pub = mix_openfile("all_my_pubkeys.txt", "w");
    keyring = mix_openfile(SECRING, "r");
    if (keyring != NULL) {
      for (;;) {
	if (fgets(line, sizeof(line), keyring) == NULL)
	  break;
	if (strleft(line, begin_key)) {
	  expires = 0;
	  created = 0;
	  do {
	    res = fgets(line, sizeof(line), keyring);
	    if (strileft(line, "created:")) {
	      created = parse_yearmonthday(strchr(line, ':')+1);
	      if (created == -1)
		created = 0;
	    } else if (strileft(line, "expires:")) {
	      expires = parse_yearmonthday(strchr(line, ':')+1);
	      if (expires == -1)
		expires = 0;
	    }
	    /* Fetch lines until we fail or get a non-header line */
	  } while ( res != NULL && strchr(line, ':') != NULL );
	  if (res == NULL)
	    break;
	  if ((created != 0) && (created > time(NULL))) {
	    /* Key has creation date in the future */
	    continue;
          }
	  if  ((expires != 0) && ((expires+KEYGRACEPERIOD) < time(NULL))) {
	    /* Key already is expired.*/
            need2delete=1;
	    continue;
	  }
	  id_decode(line, k1);
	  fgets(line, sizeof(line), keyring);
	  if (fgets(line, sizeof(line), keyring) == NULL)
	    break;
	  buf_sets(iv, line);
	  decode(iv, iv);
	  buf_reset(b);
	  for (;;) {
	    if (fgets(line, sizeof(line), keyring) == NULL)
	      break;
	    if (strleft(line, end_key))
	      break;
	    buf_append(b, line, strlen(line) - 1);
	  }
	  if (decode(b, b) == -1)
	    break;
	  buf_sets(temp, PASSPHRASE);
	  digest_md5(temp, pass);
	  buf_crypt(b, pass, iv, DECRYPT);
	  buf_clear(pk);
	  if (seckeytopub(pk, b, k1) == 0) {
            long pos; /* file position */
	    found = 1;
	    if (expires == 0 || (expires - KEYOVERLAPPERIOD >= time(NULL)))
	      foundnonexpiring = 1;
	    if (expires == 0 || (expires_found <= expires)) {
	      buf_clear(pk_found);
	      buf_cat(pk_found, pk);
	      memcpy(&k1_found, &k1, sizeof(k1));
	      expires_found = expires;
	      created_found = created;
	    }
            if (all_pub && ((!expires) || (expires > time(NULL)))) {
                /* write all the pub keys */
                pk_temp = buf_new();
	        buf_clear(pk_temp);
	        buf_cat(pk_temp, pk);
                pos=ftell(keyring);
                write_pubkey_file(keyring,all_pub,pk_temp,k1,created,expires);
                fseek(keyring,pos,SEEK_SET);
                buf_free(pk_temp);
            }
	  }
	}
      }
      fclose(keyring);
      if (all_pub) fclose(all_pub);
    }

    if (!foundnonexpiring || (force == 2)) {
      v2createkey(lifeindays,keysize);
      foundnonexpiring = 1;
      force = 1;
    } else
      break;
  };

  if (found) {
    if ((f = mix_openfile(KEYFILE, "w")) != NULL) {
      write_pubkey_file(keyring,f,pk_found,k1_found,created_found,expires_found);
      fclose(f);
    }
  } else
    err = -1;

  buf_free(b);
  buf_free(temp);
  buf_free(iv);
  buf_free(pass);
  buf_free(pk);
  buf_free(pk_found);

  if (need2delete) deleteoldkeys();

  return (err);
}

int keymgt(int force,long int lifeindays,long int keysize)
{
  /* force = 0: write key file if there is none
     force = 1: update key file
     force = 2: generate new key */
  int err = 0;

  if (REMAIL || force == 2) {
    if (MIX && (err = v2keymgt(force,lifeindays,keysize)) == -1)
      err = -1;
#ifdef USE_PGP
    if (PGP && (err = pgp_keymgt(force)) == -1)
      err = -1;
#endif /* USE_PGP */
  }
  return (err);
}

int deleteoldkeys(void)
{
  FILE *keyring, *newsecring;
  int show=1;
  int linecount=0;
  int expires;
  char line[LINELEN];
  BUFFER *header;
  char *res=line;

    keyring = mix_openfile(SECRING, "r");
    if (!keyring)
        return -1;
    newsecring = mix_openfile("secring.mix.new", "w");
    if (!newsecring)
        return -1;

    while (res) {
        linecount++;
        if (fgets(line, sizeof(line), keyring) == NULL)
            break;
        if (strleft(line, begin_key)) {
            expires = 0;
            header = buf_new();
            buf_clear(header);
            show = 0; /* read text to buffer but do not write to new file (yet) */
	    buf_append(header, line, strlen(line));
            do {
                linecount++;
                res = fgets(line, sizeof(line), keyring);
                switch (show) {
                case 0:
	            buf_append(header, line, strlen(line));
                    break;
                case 1:
                    fprintf(newsecring, "%s", line);
                    break;
                default:
                    /* no action */
                    break;
                }
                if (strileft(line, "expires:")) {
                    expires = parse_yearmonthday(strchr(line, ':')+1);
                    if (expires == -1)
                        expires = 2147483647; /* no expiry date means far future */
	            if  ((expires+KEYGRACEPERIOD) < time(NULL)) {
                        show=2; /* do not put this key in the new file - i.e. deletion */
	                errlog(WARNING, "Deleting expired key %s", line);
                    } else {
                        show=1; /* show this key */
                    }
                    if (1==show) buf_write(header, newsecring);
                    buf_free(header);
                }
            /* Fetch lines until end key or eof */
            if (res == NULL)
                break;  /* quit from two loops */
            } while ( !strileft(line,end_key) );
            fprintf(newsecring, "\n");
        }
    }

    if (fclose(keyring)) return -11;
    if (fclose(newsecring)) return -12;
    /* replace the file and wipe the old one */
    keyring = mix_openfile(SECRING, "r+");
    {
    /* rename the "secring.mix.new" in the MIXDIR not CWD */
    char path1[PATHMAX], path2[PATHMAX];
    mixfile(path1, "secring.mix.new");
    mixfile(path2, SECRING);
    if (rename(path1, path2)) return -14;
    }
    sync();
    if (!keyring) return -15;
    memset(line,'\n',LINELEN-1);
    line[LINELEN-1]='\0';
    for (;linecount>0;linecount--)
        fprintf(keyring,"%s",line);
    fclose(keyring);
return 0;
}

int write_pubkey_file(FILE *in, FILE *out, BUFFER *pk_found, byte *k1_found, time_t created_found, time_t expires_found)
{
  char line[LINELEN];
  int decimallength;

      id_encode(k1_found, line);
      fprintf(out, "%s %s %s %s:%s %s%s", SHORTNAME,
	      REMAILERADDR, line, mixmaster_protocol, VERSION,
	      MIDDLEMAN ? "M" : "",
	      NEWS[0] == '\0' ? "C" : (strchr(NEWS, '@') ? "CNm" : "CNp"));
      if (created_found) {
	struct tm *gt;
	gt = gmtime(&created_found);
	strftime(line, LINELEN, "%Y-%m-%d", gt);
	fprintf(out, " %s", line);
	if (expires_found) {
	  struct tm *gt;
	  gt = gmtime(&expires_found);
	  strftime(line, LINELEN, "%Y-%m-%d", gt);
	  fprintf(out, " %s", line);
	}
      }
      fprintf(out, "\n\n%s\n", begin_key);
      id_encode(k1_found, line);
      decimallength=2 + (pk_found->data[0] + 256*pk_found->data[1])/4;
      fprintf(out, "%s\n%d\n", line, decimallength);
      encode(pk_found, 40);
      buf_write(pk_found, out);
      fprintf(out, "%s\n\n", end_key);
return 0;
}
