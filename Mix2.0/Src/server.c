
/* $Id: server.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: server.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.4  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.3  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.2  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 *
 * server.c           1997-11-08 um
 *     simple socket protocol completed.
 *
 * server.c (from Anonymous)
 */

#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include "mix.h"
#include "inet.h"

R_DH_PARAMS DH_params;
unsigned char prime[DH_PRIME_LEN (1024)], generator[DH_PRIME_LEN (1024)];
unsigned char your_publicDH[DH_PRIME_LEN (1024)];
unsigned char my_publicDH[DH_PRIME_LEN (1024)];
unsigned char my_privateDH[DH_PRIME_LEN (1024)];
unsigned char agreedKey[DH_PRIME_LEN (1024)];
unsigned char RND1[16], RND2[16];
int server_privateDH_len = 700;
R_ENVELOPE_CTX rsa_context;
R_RSA_PRIVATE_KEY privKey;
R_RSA_PUBLIC_KEY pubKey;
R_DIGEST_CTX digest_context;
unsigned int numPubKeys, keylen;


/* send greeting message to client program */
int
send_greeting (int fd)
{
  char line[1024];

  sprintf (line, "200-Mixmaster Version %s\n200 Welcome to %s!\n",
	   VERSION, REMAILERNAME);
  return (writestr (fd, line));
}

int
get_key_request (int fd)
{
  char line[1024], *ptr;
  int i, error;
  int t[16];
  byte ID[16];
  FILE *fptr;

  readline (fd, line, sizeof (line));
  if (strileft (line, "Quit"))
    return (0);
  if (strileft (line, "SendKey "))
    {
      ptr = line + strlen ("SendKey ");
      sscanf (ptr, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	   t, t + 1, t + 2, t + 3, t + 4, t + 5, t + 6, t + 7, t + 8, t + 9,
	      t + 10, t + 11, t + 12, t + 13, t + 14, t + 15);
      for (i = 0; i < 16; i++)
	ID[i] = t[i];
      error = get_priv_key (ID, &privKey);
      error += get_pub_key (ID, &pubKey);
      if (error)
	{
	  writestr (fd, "400 not found\n");
	  return (0);
	}
      else
	{
	  writestr (fd, "210 Sending key\n");
	  /* start sending the keyring */
	  if ((fptr = open_mix_file ("pubring.mix", "r")) == NULL)
	    {
	      writestr (fd, "500 Internal error: no key file\n");
	      return (0);
	    }
	  while (fgets (line, 1024, fptr) != NULL)
	    writestr (fd, line);
	  fclose (fptr);
	  writestr (fd, "\n-----End Key File-----\n");
	  return (1);
	}
    }
  else if (strileft (line, "ConfirmKey "))
    {
      ptr = line + strlen ("ConfirmKey ");
      sscanf (ptr, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	   t, t + 1, t + 2, t + 3, t + 4, t + 5, t + 6, t + 7, t + 8, t + 9,
	      t + 10, t + 11, t + 12, t + 13, t + 14, t + 15);
      for (i = 0; i < 16; i++)
	ID[i] = t[i];
      error = get_priv_key (ID, &privKey);
      error += get_pub_key (ID, &pubKey);
      if (error)
	{
	  writestr (fd, "400 not found\n");
	  return (0);
	}
      else
	{
	  writestr (fd, "100 Confirm key available\n");
	  return (1);
	}
    }
  writestr (fd, "400 Command unrecognized\n");
  return (0);			/* I don't know what he said */
}

/* Get the DH parameters to generate the shared key */
int
get_DH_params (int fd)
{
  unsigned char *ptr;
  BUFFER *buf;

  DH_params.prime = prime;
  DH_params.generator = generator;
  buf = new_buffer ();
  readbuf (fd, buf);
  ptr = buf->message;

  DH_params.primeLen = *ptr;
  ptr++;
  R_memcpy (DH_params.prime, ptr, DH_PRIME_LEN (1024));
  ptr += DH_PRIME_LEN (1024);
  DH_params.generatorLen = *ptr;
  ptr++;
  R_memcpy (DH_params.generator, ptr, DH_PRIME_LEN (1024));
  return (1);
}

/* Send server keyhalf for DH exchange */
int
send_server_keyhalf (int fd)
{
  /* Calculate DH key half, and agreed key using other half */
  if (R_SetupDHAgreement (my_publicDH, my_privateDH, server_privateDH_len,
			  &DH_params, random_obj))
    return (0);

  writen (fd, my_publicDH, DH_PRIME_LEN (1024));
  return (1);
}

/* Get keyhalf from client. It is encrypted to us */
int
get_client_keyhalf (int fd)
{
  int len, olen, keylen;
  unsigned char key[MAX_ENCRYPTED_KEY_LEN];
  unsigned char *ptr, iv[8];
  BUFFER *buf;

  buf = new_buffer ();
  readbuf (fd, buf);
  ptr = buf->message;
  len = buf->length;

  memcpy (iv, ptr, 8);
  ptr += 8;
  len -= 8;
  keylen = *ptr++;		/* length of encrypted key */
  len--;
  memcpy (key, ptr, keylen);
  ptr += keylen;
  len -= keylen;
  if (R_OpenInit (&rsa_context, EA_DES_EDE3_CBC, key, keylen, iv, &privKey))
    return (0);
  R_OpenUpdate (&rsa_context, your_publicDH, &olen, ptr, len);
  if (R_OpenFinal (&rsa_context, your_publicDH + olen, &olen))
    return (0);
  else
    return (1);
}

/* Get the message from the client */
int
get_message (int fd)
{
  BUFFER *msg;
  unsigned char iv[9];

  if (R_ComputeDHAgreedKey (agreedKey, your_publicDH, my_privateDH,
			    server_privateDH_len, &DH_params))
    return (0);

  msg = new_buffer ();

  /* Ok, now we get the message */
  readn (fd, iv, 8);
  readbuf (fd, msg);
  crypt_in_buffer (agreedKey, iv, msg, 0);

  if (type2_dec (msg, msg->message + msg->length - 16) == 0)
    {
      stats (FL_MESSAGE | FL_NEW, NULL);	/* count one type 2 message */
      return (1);
    }
  else
    return (0);
}

int
send_fail (int fd)
{
  return (writestr (fd, "400 Message Corrupted\n"));
}


int
send_confirmation (int fd)
{
  return (writestr (fd, "200 Message Valid\n"));
}

int
get_quit (int fd)
{
  char line[256];

  readline (fd, line, sizeof (line));
  if (strileft (line, "quit"))
    return (1);
  else
    return (0);
}

int
protocol (int fd)
{

  int ok;

  ok = send_greeting (fd);
  if (!ok)
    return (ok);

  ok = get_key_request (fd);
  if (!ok)
    return (ok);

  ok = get_DH_params (fd);
  if (!ok)
    return (ok);

  ok = get_client_keyhalf (fd);
  if (!ok)
    return (ok);

  ok = send_server_keyhalf (fd);
  if (!ok)
    return (ok);

  ok = get_message (fd);
  if (!ok)
    {
      send_fail (fd);
      return (ok);
    }

  ok = send_confirmation (fd);
  if (!ok)
    return (ok);

  ok = get_quit (fd);
  return (ok);
}

int
mix_server (int dofork)
{
  int sockfd, newsockfd, clilen, childpid = 0;
  struct sockaddr_in cli_addr, serv_addr;

  /*
   * Open a TCP socket (an Internet stream socket).
   */

  if ((sockfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
    {
      fprintf (errlog, "server: can't open stream socket\n");
      return (1);
    }
  /*
   * Bind our local address so that the client can send to us
   */

  bzero ((char *) &serv_addr, sizeof (serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl (INADDR_ANY);
  serv_addr.sin_port = htons (SERV_TCP_PORT);

  if (bind (sockfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) < 0)
    {
      fprintf (errlog, "server: can't bind local address\n");
      return (2);
    }

  if (listen (sockfd, 5) < 0)
    {
      fprintf (errlog, "server: listen failed\n");
      return (3);
    }

  signal (SIGCHLD, server_chld);/* this eliminates zombies */
  signal (SIGPIPE, server_close);

  for (;;)
    {
      /*
       * Wait for a connection from a client process.
       */

      clilen = sizeof (cli_addr);
      newsockfd = accept (sockfd, (struct sockaddr *) &cli_addr, &clilen);

      if (newsockfd < 0)
	fprintf (errlog, "server: accept error\n");

      if (dofork == 1)
	if ((childpid = fork ()) < 0)
	  {
	    fprintf (errlog, "server: fork error\n");
	    return (4);
	  }

      if (childpid == 0)
	{			/* child process */
	  close (sockfd);	/* close original socket */
	  protocol (newsockfd);
	  server_close (0);
	}

      close (newsockfd);	/* parent process */
    }
}

void
server_close (int sig)
{
  close_our_random ();
  exit (0);
}

void
server_chld (int sig)
{
  while (waitpid (-1, NULL, WNOHANG) > 0)
    ;
}
