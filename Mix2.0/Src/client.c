
/* $Id: client.c,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 * $Log: client.c,v $
 * Revision 1.1  2002/08/28 20:06:49  rabbi
 * Initial revision
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
 * Revision 2.2  1998/02/17  23:25:41  um
 * Check R_DecodePEMBlock return values.
 *
 * client.c           1997-11-08 um
 *     simple socket protocol completed.
 *
 * client.c (from Anonymous)
 */


/* Protocol description by Lance Cottrell <loki@infonex.com>:

The users has already authenticated the RSA keys of each remailer
in the chain (or at least there is no point in authenticating them more
than the sender did). The direction that trust matters is from sending
remailer (C) to receiving remailer (S) because the receiving remailer will
accept messages from anyone, but the sending remailer wants to ensure that
only the next remailer in the chain gets the message.

Variables:	A(foo) means RSA encryption of foo with A RSA key.
		K1	First half of DH key exchange
		K	DH derived key
		R1	Random number
		R1(foo) foo encrypted using R1 as a 3DES key
		H(foo)	SHA hash of foo


C sends S the DH base to be used (each remailer can have a different one).

C requests key matching key hash in message (request conf if C has key already)

C sends S	S(R1,K1,H(R1,K1))

S sends C	R1(K1,K2,H(K1,K2))	Sending K1 under Key R1
authenticates K2

C sends S	K(K2,H(K2))	Allows S to confirm correct key generation.

Done

RSA ensures only S can know R1 and K1. If we have the wrong key for S then
the user encrypted the message to the wrong person, and security has
already been compromised. Key authentication and distribution to the user
is not covered by this protocol. I assume that the user has used the
correct public key. I simply use the same public key (checked with the
fingerprint in the message) that the user encrypted to.

The purpose of the hashes in each exchange is to prevent substitution of
the contents of the packet. While an attacker could not know R1, he might
be able to change the values. The hash makes any tampering evident.

Encrypting with R1 and returning the key half K1 proves to C that the
correspondent was able to decrypt the initial message (thus proving
possession of S's private key). The final exchange acts only to allow S to
confirm that the exchange has gone correctly.*/


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/file.h>
#include "mix.h"
#include "inet.h"

R_DH_PARAMS DH_params;
unsigned char prime[DH_PRIME_LEN (1024)], generator[DH_PRIME_LEN (1024)];
unsigned char your_publicDH[DH_PRIME_LEN (1024)];
unsigned char my_publicDH[DH_PRIME_LEN (1024)];
unsigned char my_privateDH[DH_PRIME_LEN (1024)];
unsigned char agreedKey[DH_PRIME_LEN (1024)];
unsigned char RND1[16], RND2[16];
int my_privateDH_len = 700;
R_ENVELOPE_CTX rsa_context;
R_RSA_PUBLIC_KEY pubKey, *keyPtr[5];
R_DIGEST_CTX digest_context;
unsigned int numPubKeys, keylen;

int
read_status (int fd)
{
  int n;
  char line[256];

  do
    {
      n = readline (fd, line, sizeof (line));
      if (n < 0)
	return (577);
      if (line[0] < '0' || line[0] > '9' ||
	  line[1] < '0' || line[1] > '9' ||
	  line[2] < '0' || line[2] > '9')
	return (576);
    }
  while (n > 3 && line[3] == '-');
  return (0100 * (line[0] - '0') + 0010 * (line[1] - '0') + (line[2] - '0'));
}

int
read_message (FILE * fptr, BUFFER * msg, unsigned char *ID)
{
  char line[256], line2[256];
  int len;

  while (getline (line, sizeof (line), fptr) != NULL)
    if (streq (line, begin_remailer))
      break;
  getline (line, sizeof (line), fptr);	/* length of de-armored message */
  getline (line, sizeof (line), fptr);	/* checksum line */

  while (getline (line, sizeof (line), fptr) != NULL)
    {
      if (streq (line, end_remailer))
	break;
      if (decode_block (line2, &len, line, strlen (line)) != 0)
	break;
      add_to_buffer (msg, line2, len);
    }
  if (!streq (line, end_remailer))
    return (0);
  memcpy (ID, msg->message, 16);
  return (1);
}


int
remailer_info (char *address, long unsigned int *portnum)
{
  REMAILER remailer_list[256];
  int num_remailers;
  char *ptr;
  int flag = 0, j;

  num_remailers = read_remailer_list (remailer_list);

  for (j = 1; j <= num_remailers; j++)
    {
      ptr = remailer_list[j].name;
      if (strieq (address, ptr))
	{			/* We have the key */
	  ptr = strchr (remailer_list[j].abilities, 'S');
	  if (ptr)
	    {
	      flag = 1;
	      if (ptr[1] == '=')
		sscanf (ptr + 2, "%lu", portnum);
	    }
	  break;
	}
    }
  return (flag);
}

int
get_greeting (int fd)
{
  return (read_status (fd) & SC_OK);
}

int
query_key_ID (int fd, int flag, unsigned char *ID)
{
  char line[256];

  sprintf (line, "%s %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	   flag ? "SendKey" : "ConfirmKey",	/* if we don't have the key, ask for it */
	   ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7],
	   ID[8], ID[9], ID[10], ID[11], ID[12], ID[13], ID[14], ID[15]);
  if (!writestr (fd, line))
    return (0);
  return (read_status (fd));
}

int
get_server_key (int fd, unsigned char *IDstr)
{
  return 0;			/* read the RSA key */
}

int
send_DH_params (int fd)
{
  BUFFER *buff;
  unsigned char tmp;
  int i;

  DH_params.prime = prime;
  DH_params.generator = generator;
  if (get_DH (&DH_params))
    return (0);

  buff = new_buffer ();
  tmp = DH_params.primeLen;
  add_to_buffer (buff, &tmp, 1);
  add_to_buffer (buff, DH_params.prime, DH_PRIME_LEN (1024));
  tmp = DH_params.generatorLen;
  add_to_buffer (buff, &tmp, 1);
  add_to_buffer (buff, DH_params.generator, DH_PRIME_LEN (1024));

  i = writebuf (fd, buff);
  free_buffer (buff);
  return (i);
}

int
get_server_keyhalf (int fd)
{
  return (readn (fd, your_publicDH, DH_PRIME_LEN (1024)) == DH_PRIME_LEN (1024));
}

/* Generate and send public DH value, Encrypted under their public key */
int
send_keyhalf (int fd)
{
  int len, keylen, numPubKeys, i;
  unsigned char *key[5], line[1024], iv[8], tmpbyte;
  BUFFER *buf;

  buf = new_buffer ();

  /* Calculate DH key half */
  if (R_SetupDHAgreement (my_publicDH, my_privateDH, my_privateDH_len,
			  &DH_params, random_obj))
    return (0);

  /* Encrypt key half */
  numPubKeys = 1;
  keyPtr[0] = &pubKey;
  our_randombytes (iv, 8);
  key[0] = malloc (MAX_ENCRYPTED_KEY_LEN);
  /* This does not secure the key exchange against active attacks! */
  if (R_SealInit (&rsa_context, key, &keylen, iv, numPubKeys, keyPtr,
		  EA_DES_EDE3_CBC, random_obj))
    return (0);
  add_to_buffer (buf, iv, 8);
  tmpbyte = keylen;
  add_to_buffer (buf, &tmpbyte, 1);
  add_to_buffer (buf, key[0], keylen);
  R_SealUpdate (&rsa_context, line, &len, my_publicDH, DH_PRIME_LEN (1024));
  add_to_buffer (buf, line, len);
  R_SealFinal (&rsa_context, line, &len);
  add_to_buffer (buf, line, len);
  i = writebuf (fd, buf);
  free_buffer (buf);
  return (i);
}

/* encrypt and send message. */
int
sock_send_message (int fd, BUFFER * msg)
{
  unsigned char iv[8];
  unsigned char digest[16];

  if (R_ComputeDHAgreedKey (agreedKey, your_publicDH, my_privateDH,
			    my_privateDH_len, &DH_params))
    return (0);

  add_to_buffer (msg, make_digest (msg, digest), 16);

  /* pad message out to 8 byte block size */
  if ((msg->length % 8) != 0)
    pad_buffer (msg, 8 - (msg->length % 8));
  our_randombytes (iv, 8);
  crypt_in_buffer (agreedKey, iv, msg, 1);
  writen (fd, iv, 8);
  return (writebuf (fd, msg));
}

/* Was the message recieved correctly? */
int
get_server_confirmation (int fd)
{
  return (read_status (fd) & SC_OK);
}

void
send_quit (int fd)
{
  writestr (fd, "Quit\n");
}

int
client_protocol (int fd, BUFFER * msg, int key_needed, unsigned char *ID)
{
  int ok;

  ok = get_greeting (fd);
  if (!ok)
    return (ok);

  ok = query_key_ID (fd, key_needed, ID);
  if (!ok)
    return (ok);

  if (ok >= 0400)
    return (0);

  if (ok == SC_SERVERKEY)
    {
      ok = get_server_key (fd, ID);
      if (!ok)
	return (ok);
    }

  ok = send_DH_params (fd);
  if (!ok)
    return (ok);

  ok = send_keyhalf (fd);
  if (!ok)
    return (ok);

  ok = get_server_keyhalf (fd);
  if (!ok)
    return (ok);

  ok = sock_send_message (fd, msg);
  if (!ok)
    return (ok);

  ok = get_server_confirmation (fd);
  if (!ok)
    return (ok);

  send_quit (fd);
  return (1);
}

int
attempt_socket (FILE * fptr)
     /* Return 0 on fail. Leave file ptr after first line */
{
  int sockfd, key_needed, i, j;
  struct sockaddr_in serv_addr;
  struct hostent *hp;
  char address[256], line[256], hostnym[80], *ptr;
  unsigned char ID[16];
  long unsigned int portnum = SERV_TCP_PORT;
  int sent = 0;
  BUFFER *msg;

  getline (address, 256, fptr);	/* read in address */

  while (!streq (line, "END"))
    getline (line, sizeof (line), fptr);

  if (!remailer_info (address, &portnum))
    goto fail;

  msg = new_buffer ();

  if (!read_message (fptr, msg, ID))
    goto fail;

  key_needed = get_pub_key (ID, &pubKey);

  /*
   * Fill in the structure "serv_addr" with the address of the
   * server that we want to connect with.
   */

  ptr = strstr (address, "@");
  if (!ptr)
    goto fail;
  ptr++;
  i = strlen (ptr);
  strcpy (hostnym, ptr);
  for (j = 0; j < i; j++)
    {
      if (hostnym[j] <= ' ')
	hostnym[j] = 0;		/* chop of trailing spaces */
    }
  bzero ((char *) &serv_addr, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  if ((hp = gethostbyname (hostnym)) == NULL)
    return (1);
  memcpy (&serv_addr.sin_addr, hp->h_addr, hp->h_length);
  serv_addr.sin_port = htons (portnum);

  if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    goto fail;
  if (connect (sockfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    goto fail;

  signal (SIGPIPE, SIG_IGN);
  sent = client_protocol (sockfd, msg, key_needed, ID);

fail:
  if (sockfd > 0)
    close (sockfd);
  rewind (fptr);
  getline (line, sizeof (line), fptr);
  free_buffer (msg);
  return (sent);
}
