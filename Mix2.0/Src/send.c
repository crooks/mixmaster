
/* $Id: send.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: send.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.8  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.7  1998/05/11  19:43:16  um
 * *** empty log message ***
 *
 * Revision 2.6  1998/05/10  22:16:21  um
 * Bug fix.
 *
 * Revision 2.5  1998/05/07  23:59:36  um
 * IDEXP and PACKETEXP now specify hours.
 *
 * Revision 2.4  1998/04/20  14:09:47  um
 * Bug fix for trimming ID log file, by Johannes Kroeger.
 *
 * Revision 2.3  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.2  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 *
 * send.c          1997-12-22 um
 *      bug fix from Johannes Kroeger.
 *
 * send.c          1997-12-12 um
 *      return value for attempt_socket dummy corrected.
 *
 * send.c          1997-12-08 um
 *      bug fix by Andy Dustman.
 *
 * send.c          1997-11-08 um
 *      attempt_socket now exists.
 *
 * send.c          1997-10-10 JK
 *      parse header lines without " " after the ":" correctly.
 *
 * send.c           1997-09-15 um
 *     do not try to read multi-line header if the line is empty
 *     (patch from Johannes Kroeger).
 *     fix overflow bug in reading multi-line header.
 *
 * send.c           1997-08-30 um
 *     parse multiple-line message headers.
 *
 * send.c           1997-08-29 um
 *     bug fix: add mail2news gate only for "post:" destination.
 *     headers are filtered only for the final hop.
 *
 * send.c           1997-08-15 um
 *     re-wrote process_pool.
 *
 * send.c           1997-07-01 um
 *     middleman patch.
 *
 * send.c           1997-06-08 um
 *     use random_number to select message from pool to get even distribution
 *
 * send.c           1997-05-31 um
 *     exponential pool.
 *
 * send.c           1996-11-27 um
 *     No spaces in Newsgroups: line.
 *
 *      modified for DOS.
 *      applied Lance's patch for "null:" um
 *
 * send.c        1.6 11/2/95
 *      Fixed several bugs in process_partial()
 *      Insert commas between recipients on the To line.
 *      Fixed problems from not re-initializing some variables
 *      for each mail message.
 *
 * send.c        1.5 9/13/95
 *      Mail2news now uses "Newsgroups:" not group.name@gateway.
 *
 * send.c        1.4 9/10/95
 *      "null:" sends mail to a bit bucket
 *      "post:" posts to the following newsgroup
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#if 1
int
mix_server (int dofork)
{
  return (0);			/* dummy which always reports failure (true) */
}

int
attempt_socket (FILE * fp)
{
  return (0);			/* dummy which always reports failure (true) */
}

#endif

#define MAILMSG 1
#define POSTMSG 2
#define REMAILMSG 4

int
read_header (FILE * in, BUFFER * mess, int mm)
{
  char line[8 * 1024], line2[1024], *t;
  BUFFER *maildest, *groupdest;
  int subject = 0, post = 0, r = 0;
  long p;

  maildest = new_buffer ();
  groupdest = new_buffer ();

  /* Read in the destination */
  while (getline (line, sizeof (line), in) && !streq (line, "END"))
    {
      for (;;)
	{
	  p = ftell (in);
	  if (getline (line2, sizeof (line2), in) &&
	      (line2[0] == ' ' || line2[0] == '\t'))
	    {
	      strncat (line, "\n", sizeof (line) - strlen (line) - 1);
	      strncat (line, line2, sizeof (line) - strlen (line) - 1);
	    }
	  else
	    break;
	}
      fseek (in, p, SEEK_SET);
      if (strileft (line, "null:"))
	return (0);		/* bit bucket message */
      else if (strileft (line, "post:"))
	{
	  post = 1;
	  if (strlen (line) > sizeof ("post:") - 1)
	    {
	      t = line + sizeof ("post:") - 1;
	      while (*t == ' ' || *t == '\t')
		t++;
	      add_addr (groupdest, t, &mm);	/* group name */
	    }
	}
      else if (strlen (line) > 0)
	add_addr (maildest, line, &mm);
    }

  /* Read in the header lines */
  if (mm != -1)
    while (getline (line, sizeof (line), in))
      {
	if (line[0] == '\0')
	  {
	    p = ftell (in);
	    if (getline (line2, sizeof (line2), in) && strleft (line2, "##"))
	      getline (line, sizeof (line), in);	/* paste in more headers */
	    else
	      {
		fseek (in, p, SEEK_SET);
		break;		/* end of header */
	      }
	  }
	for (;;)
	  {
	    p = ftell (in);
	    if (getline (line2, sizeof (line2), in) &&
		(line2[0] == ' ' || line2[0] == '\t'))
	      {
		strncat (line, "\n", sizeof (line) - strlen (line) - 1);
		strncat (line, line2, sizeof (line) - strlen (line) - 1);
	      }
	    else
	      break;
	  }
	fseek (in, p, SEEK_SET);
	if (strileft (line, "To:"))
	  {
	    t = line + sizeof ("To:") - 1;
	    while (*t == ' ' || *t == '\t')
	      t++;
	    add_addr (maildest, t, &mm);
	  }
	else if (strileft (line, "Newsgroups:"))
	  {
	    /* will be posted only if "post:" is set */
	    t = line + sizeof ("Newsgroups:") - 1;
	    while (*t == ' ' || *t == '\t')
	      t++;
	    add_addr (groupdest, t, &mm);
	  }
	else if (!header_block (line, &mm))
	  {
	    str_to_buffer (mess, line);
	    str_to_buffer (mess, "\n");

	    if (strileft (line, "Subject:"))
	      subject = 1;
	  }
      }

  if (groupdest->length < 1)
    post = 0;
  else if (post && (strlen (MAILtoNEWS) > 1))
    add_addr (maildest, MAILtoNEWS, &mm);

  if (maildest->length > 1)
    {
      str_to_buffer (mess, "To: ");
      str_to_buffer (mess, maildest->message);
      str_to_buffer (mess, "\n");
    }

  if (groupdest->length > 1)
    {
      str_to_buffer (mess, "Newsgroups: ");
      str_to_buffer (mess, groupdest->message);
      str_to_buffer (mess, "\n");
    }

  if (mm >= 2)
    r |= REMAILMSG;
  if (maildest->length > 1)
    r |= MAILMSG;
  if (post)
    r |= POSTMSG;

  free_buffer (maildest);
  free_buffer (groupdest);

  if (post && !subject)
    str_to_buffer (mess, "Subject: none\n");

  str_to_buffer (mess, "\n");

  /* Read in the message body */
  while (getline (line, sizeof (line), in))
    {
      str_to_buffer (mess, line);
      str_to_buffer (mess, "\n");
    }

  return (r);
}

int
process_pool (void)
{
  FILE *fptr, *in, *lockptr;
  char **names, line[256], *tmp;
  int pool, i, j, final, dest;
  time_t start_time = time (NULL);
  BUFFER *mess;

  /* For the sake of ruthless efficiency, we will only build the list once. */
  mix_lock ("mail", &lockptr);
  i = file_list ("mail*", NULL);
  names = malloc (i * sizeof (*names));
  pool = file_list ("mail*", names);
  mix_unlock ("mail", lockptr);
  i = (i * RATE) / 100;		/* exponential pool */
  if (i < 1)
    i = 1;

  for (; pool > POOLSIZE && i > 0
       && (POOLTIMEOUT == 0 || time (NULL) - start_time < POOLTIMEOUT); i--)
    {
      mix_lock ("mail", &lockptr);
      final = 0;

      j = random_number (pool);	/* 0 to (pool-1) */
      if ((in = open_mix_file (names[j], "r")) == NULL)
	{
	  mix_unlock ("mail", lockptr);
	  return (0);
	}
      /* Is it a final hop? */
      getline (line, sizeof (line), in);
      if (streq (line, final_hop))
	final = 1;
      else
	{
	  /* is it also not an intermed hop ? */
	  if (!streq (line, intermed_hop))
	    {
	      fclose (in);
	      strcpy (line, "bad-");
	      in = tempfile (line);
	      fprintf (in, "Placeholder\n");
	      fclose (in);
	      fprintf (errlog, "%s not a valid mail file!\nMoving to %s\n",
		       names[j], line);
	      if (rename (names[j], line) == -1)
		fprintf (errlog, "Failed!\n");
	      continue;		/* Try another mail file */
	    }
	}

      if (!final)
	{
	  if (attempt_socket (in))	/* try to open a socket */
	    goto skip;		/* attempt socket returns 0 if it fails */
	}

      /* Send message by mail */
      mess = new_buffer ();

      /* Read in the message header */
      dest = read_header (in, mess, final ? MIDDLEMAN : -1);
      if (final && MIDDLEMAN && !(dest & REMAILMSG))
	{
	  /* message will be sent directly. filter the header properly */
	  rewind (in);
	  getline (line, sizeof (line), in);
	  clear_buffer (mess);
	  dest = read_header (in, mess, 0);
	}

      if (dest & (MAILMSG | REMAILMSG))
	{			/* There are mail addresses */
	  if ((fptr = open_sendmail (final ?
				     (dest & REMAILMSG ? 2 : -1) : -2,
				     &tmp)) == NULL)
	    goto skip;
	  if ((dest & POSTMSG) && (dest & REMAILMSG))
	    fprintf (fptr, "post:\n");
	  write_buffer (mess, fptr);
	  close_sendmail (fptr, tmp);
	}
      if ((dest & POSTMSG) && !(dest & REMAILMSG) && strlen (NEWS) > 1)
	{			/* Post through inews */
	  if ((fptr = open_pipe (NEWS, "w")) == NULL)
	    goto skip;
	  fromanon (fptr);
	  if (strlen (ORGANIZATION) > 0)
	    fprintf (fptr, "Organization: %s\n", ORGANIZATION);
	  write_buffer (mess, fptr);
	  close_pipe (fptr);
	}
      free_buffer (mess);

    skip:			/* Skip to here if message is for bit bucket */
      fclose (in);
      stats (FL_LATENCY, names[j]);
      unlink (names[j]);
      mix_unlock ("mail", lockptr);
      free (names[j]);
      if (pool > 0)
	names[j] = names[--pool];
    }
  return (1);
}

void
process_latent (void)
{
  int num, i;
  unsigned long ctime, stime;
  FILE *fptr, *out;
  char *names[256], line[256], foo[80];

  num = file_list ("latent*", names);
  for (i = 0; i < num; i++)
    {
      if ((fptr = open_mix_file (names[i], "r")) != NULL)
	{
	  getline (line, sizeof (line), fptr);
	  sscanf (line, "%s %lu", foo, &stime);
	  ctime = time (NULL);
	  if (ctime > stime)
	    {
	      /* now open up a mail file and put the body there */
	      unlink (names[i]);
	      sprintf (foo, "mail");
	      out = tempfile (foo);
	      while (getline (line, sizeof (line), fptr) != NULL)
		fprintf (out, "%s\n", line);
	      fclose (out);
	      fclose (fptr);
	    }			/* passed time */
	}			/* if could open latent */
    }				/* for */
}

void
process_partial (void)
{
  int num, i;
  unsigned char j;
  unsigned long ctime, stime;
  FILE *fptr, *lockptr;
  char *names[256];

  mix_lock ("pac", &lockptr);
  num = file_list ("pac*", names);
  for (i = 0; i < num; i++)
    {
      if ((fptr = open_mix_file (names[i], "r")) != NULL)
	{
	  fread (&j, 1, 1, fptr);
	  stime = (unsigned long) j;
	  fread (&j, 1, 1, fptr);
	  stime += (unsigned long) j *256;
	  fread (&j, 1, 1, fptr);
	  stime += (unsigned long) j *256 * 256;
	  fread (&j, 1, 1, fptr);
	  stime += (unsigned long) j *256 * 256 * 256;

	  ctime = time (NULL);

	  if ((ctime - stime) > PACKETEXP * 3600)
	    {			/* packet is too old */
	      fclose (fptr);
	      unlink (names[i]);
	    }
	  else
	    {
	      fclose (fptr);
	    }			/* passed expiration time */
	}			/* if could open packet */
    }				/* for */
  mix_unlock ("pac", lockptr);
}

int
packetID_housekeeping (void)
{
  FILE *fptr, *lockptr;
  char line[256], ID[50];
  unsigned long now, then;
  BUFFER *buff;

  if (IDEXP == 0)
      return (0);

  mix_lock (IDLOG, &lockptr);
  buff = new_buffer ();
  now = time (NULL);
  if ((fptr = try_open_mix_file (IDLOG, "r")) == NULL)
    return (-1);

  while (getline (line, sizeof (line), fptr) != NULL)
    {
      sscanf (line, "%s %lu", ID, &then);
      if ((now - then) < IDEXP * 3600)
      {
	  str_to_buffer (buff, line);
	  str_to_buffer (buff, "\n");
      }
    }
  fclose (fptr);
  if ((fptr = open_mix_file (IDLOG, "w")) == NULL)
    return (-1);
  write_buffer (buff, fptr);
  fclose (fptr);
  free_buffer (buff);
  mix_unlock (IDLOG, lockptr);
  return (0);
}
