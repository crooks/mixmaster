
/* $Id: util.c,v 1.2 2002/09/10 05:24:14 rabbi Exp $
 * $Log: util.c,v $
 * Revision 1.2  2002/09/10 05:24:14  rabbi
 * replaced an mktemp() to make OpenBSD happy.
 *
 * Revision 1.1.1.1  2002/08/28 20:06:50  rabbi
 * Mixmaster 2.0.5 source.
 *
 * Revision 2.8  1999/01/19  02:28:13  um
 * *** empty log message ***
 *
 * Revision 2.7  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.6  1998/05/07  23:59:36  um
 * Use PCRE library. Changes to rxmatch from freedom 2.3 by Johannes Kroeger.
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
 * Revision 2.2  1998/01/12  21:48:00  um
 * simpler strleft() function (Johannes Kroeger)
 *
 * util.c          1997-12-22 um
 *      bug fix from Johannes Kroeger.
 *
 * util.c          1997-12-15 um
 *      rxmatch patch by Johannes Kroeger.
 *
 * util.c          1997-11-08 um
 *      new function make_digest.
 *
 * util.c          1997-10-20 um
 *      strifind bugfix (Andy Dustman).
 *
 * util.c          1997-10-10 JK
 *      parse header lines without " " after the ":" correctly.
 *
 * util.c          1997-09-23 um
 *      new function mailfile() - create an output file.
 *
 * util.c          1997-09-18 um
 *      new function strieq().
 *
 * util.c          1997-08-26 um
 *      mixmaster terminates if tempfile() fails.
 *
 * util.c          1997-08-19 um
 *      accept lines with one character in blocking files.
 *      support destination blocking with regexps.
 *
 * util.c          1997-08-17 JK
 *      gcc warnings eliminated.
 *
 * util.c          1997-08-15 um
 *      new functions open_sendmail, close_sendmail, modified
 *      destination blocking, new string comparison functions.
 *
 * util.c          1997-07-11 ad
 *      new fromanon() function for sending anonymous messages.
 *
 * util.c          1997-07-06 um
 *      new functions strileft(), strifind().
 *
 * util.c          1997-07-01 um
 *      middleman patch, with new function to().
 *
 * util.c          1997-06-18 um
 *      file_list bug <medusa-admin@weasel.owl.de>.
 *
 * util.c          1997-06-18 um
 *      new function header_filter.
 *
 * util.c          1997-06-16 um
 *      open_mix_file writes error message, new function try_open_mix_file.
 *
 * util.c          1997-06-12 um
 *      file_to_out bug fix <medusa@weasel.owl.de>.
 *
 * util.c          1997-05-30 um
 *      new function for ASCII armor.
 *
 * util.c          1997-05-30 um
 *      merged with getfrom.c
 *
 * getfrom.c       1997-05-30 um
 *      return address in original case.
 *
 * getfrom.c       1996-11-27 um
 *      delete the newline after the address.
 *
 * getfrom.c        1.0 4/23/95
 *
 * util.c          1996-11-27 um
 * new function parse_filename. users can use "~/filename" now
 *
 * util.c          1996-10-23 um
 * switch UIDs.
 * destination.block bug fixed. added destination.allow
 *
 * modified for DOS.
 * use readdir() rather than ls
 * moved fclose() in destination_block
 *
 * util.c        1.1 11/2/95
 *      Changed fclose to pclose for pipes
 *
 * util.c        1.0 4/23/95
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>
#include <assert.h>

#ifndef LOCK_SH
#define LOCK_SH	1		/* shared lock */
#define LOCK_EX 2		/* exclusive lock */
#define LOCK_NB 4		/* don't block when locking */
#define LOCK_UN 8		/* unlock */
#endif

#ifdef USE_RX
#include "pcre.h"

int
rxmatch(const char *string, const char *pattern)
{
  int errptr, match;
  const char *error;
  pcre *compiled;

  if ((compiled = pcre_compile(pattern, PCRE_CASELESS, &error, &errptr))) {
    match = pcre_exec(compiled, NULL, string, strlen(string),
		      PCRE_CASELESS, NULL, 0);
    free(compiled);
    return (match >= 0);
  }
  else
    return 0;
}
#else
int
rxmatch (const char *string, const char *pattern)
{
  return strifind (string, pattern);
}

#endif /* USE_RX */

FILE *
tempfile (char *rootname)
     /* Takes the root name to which will be added 6 characters.
      * Returns file pointer to new file. Array containing name
      * Must be at least 6 characters longer than the name.
      */
{
  char tmp[256];
  FILE *f;
  int fptr;

#ifdef SHORTNAMES
  if (strlen (rootname) > 2)
    rootname[2] = 0;
#endif
  sprintf (tmp, "%sXXXXXX", rootname);
  strcpy (rootname, tmp);
  fptr = mkstemp(rootname);
  if (fptr > 0)
    close(fptr);
  else
    exit(-1);
  f = open_mix_file (rootname, "w+");
  if (f == NULL)
    exit (-1);			/* we are in deep trouble and may as well exit */
  return (f);
}


FILE *
tempfileb (char *rootname)
     /* Takes the root name to which will be added 6 characters.
      * Returns file pointer to new file. Array containing name
      * Must be at least 6 characters longer than the name.
      */
{
  char tmp[256];
  FILE *f;
  int fptr;

#ifdef SHORTNAMES
  if (strlen (rootname) > 2)
    rootname[2] = 0;
#endif
  sprintf (tmp, "%sXXXXXX", rootname);
  strcpy (rootname, tmp);
  fptr = mkstemp(rootname);
  if (fptr > 0)
    close(fptr);
  else
    exit(-1);
  f = open_mix_file (rootname, "wb+");
  if (f == NULL)
    exit (-1);			/* we are in deep trouble and may as well exit */
  return (f);
}

int
file_list (const char *search, char **names)
{				/* returns the number of files */
  DIR *dptr;
  char *name;
  struct dirent *de;
  int i;

  if ((dptr = opendir (".")) == NULL)
    return (-1);
  i = 0;

  while ((de = readdir (dptr)) != NULL)
    {
      assert (search[strlen (search) - 1] == '*');
      name = de->d_name;

      if
#ifdef SHORTNAMES
	((strncmp (search, name, 2) == 0) && (strchr (name, '.') == NULL))
	/* kludge: no dot in filenames... */
#else
	(strncmp (search, name, strlen (search) - 1) == 0)
#endif
      {
	if (names != NULL)
	  {
	    names[i] = (char *) malloc (strlen (name) + 1);
	    strcpy (names[i], name);
	  }
	i++;
      }
    }
  closedir (dptr);
  return i;
}

FILE *
open_mix_file (const char *s, const char *attr)
     /* Routine to open a file in mix_dir */
{
  FILE *fptr;
  if ((fptr = try_open_mix_file (s, attr)) == NULL)
    {
      if (strstr (attr, "w"))
	fprintf (errlog, "Error: Could not open file %s for writing!\n", s);
      else
	fprintf (errlog, "Error: Could not open file %s!\n", s);
    }
  return fptr;
}

FILE *
try_open_mix_file (const char *s, const char *attr)
     /* Routine to open a file in mix_dir */
{
  FILE *fptr;
  fptr = fopen (s, attr);
  return fptr;
}

FILE *
open_user_file (const char *s, const char *attr)
{
  FILE *fptr;
  user_uid ();
  fptr = fopen (s, attr);
  if (fptr == NULL)
    {
      fprintf (errlog, "Could not open file %s\n", s);
      exit (-1);
    }
  mix_uid ();
  return fptr;
}

int
file_to_out (const char *filename)
     /* dumps a file to stdout. */
{
  int len;
  FILE *fp;
  char chunk[1024];

  if ((fp = open_mix_file (filename, "r")) == NULL)
    return (-1);
  while ((len = fread (chunk, 1, sizeof (chunk), fp)) > 0)
    {
      fwrite (chunk, 1, len, stdout);
    }
  fclose (fp);
  return (len == 0 ? 0 : (-1));
}

FILE *
open_sendmail (int mode, char **filename)
{
  FILE *f;

  if (mode > 1)
    {
      *filename = malloc (256);
      strcpy (*filename, "tmpS");
      f = tempfile (*filename);
    }
  else
    {
      *filename = NULL;
      if (strieq (SENDMAIL, "outfile"))
	{
	  *filename = "outfile";
	  f = mailfile ();
	}
      else
	f = open_pipe (SENDMAIL, "w");
      if (f == NULL)
	exit (-1);
      if (mode == -1)
	fromanon (f);
      else if (mode >= 0)
	from (f);
    }
  return f;
}

void
close_sendmail (FILE * f, char *filename)
{
  if (filename)
    {
      fclose (f);
      if (!strieq (filename, "outfile"))
	{
	  mm_chain (filename);
	  unlink (filename);
	  free (filename);
	}
    }
  else
    close_pipe (f);
}

/* returns 0 if mode is locked */
/* returns 1 if file is not locked, and creates lock file */

#ifdef SHORTNAMES
int
mix_lock (const char *name, FILE ** fptr)
{
  char buff[128];
  int status;

  strcpy (buff, name);
  strcat (buff, ".lck");
  if ((*fptr = fopen (buff, "r+")) == NULL)
    {				/* file exists */
      if ((*fptr = fopen (buff, "w")) == NULL)
	{			/* create file */
	  fprintf (errlog, "Error, could not create %s\n", buff);
	  return (0);		/* if cant create lock, treat as locked */
	}
      return (1);
    }
  return (0);
}

void
mix_unlock (const char *name, FILE * fptr)
{
  char buff[128];

  strcpy (buff, name);
  strcat (buff, ".lck");
  if (fptr != NULL)
    {
      fclose (fptr);
      unlink (buff);
    }
}

#else
int
mix_lock (const char *name, FILE ** fptr)
{
  char buff[128];
  int status;
  struct flock lockstruct;

  strcpy (buff, "lock.");
  strcat (buff, name);
  if ((*fptr = try_open_mix_file (buff, "r+")) == NULL)
    {				/* file exists */
      if ((*fptr = open_mix_file (buff, "w")) == NULL)
	return (0);		/* if cant create lock, treat as locked */
    }
  lockstruct.l_type = F_WRLCK;
  lockstruct.l_whence = 0;
  lockstruct.l_start = 0;
  lockstruct.l_len = 0;
  status = fcntl (fileno (*fptr), F_SETLKW, &lockstruct);
  if (status == -1)
    return (0);
  return (1);
}

void
mix_unlock (const char *name, FILE * fptr)
{
  char buff[128];
  struct flock lockstruct;

  strcpy (buff, "lock.");
  strcat (buff, name);
  if (fptr != NULL)
    {
      lockstruct.l_type = F_UNLCK;
      lockstruct.l_whence = 0;
      lockstruct.l_start = 0;
      lockstruct.l_len = 0;
      fcntl (fileno (fptr), F_SETLKW, &lockstruct);
      fclose (fptr);
    }
}

#endif /* SHORTNAMES */

void
add_addr (BUFFER * dest, char *addr, int *mm)
{
  if (!destination_block (addr, mm))
    {
      if (dest->length > 1)
	str_to_buffer (dest, ",");
      str_to_buffer (dest, addr);
    }
}

int
destination_block (const char *destination, int *mm)
{
  /* *mm: flag for destination checking:
     0 == normal blocking
     1 == check if message should be remailed
     2 >= no blocking, message will be remailed */

  FILE *block;
  char buff[256];
  int blocked = 0;

  if (*mm >= 2)
    return (0);			/* no blocking */
  if (*mm == 1)
    return (destination_allow (destination, mm));

  /* handle blocked destinations */
  if ((block = try_open_mix_file (DESTBLOCK, "r")) != NULL)
    {
      while (getline (buff, sizeof (buff), block) != NULL)
	{
	  if (buff[0] == '#' || strlen (buff) < 1)
	    continue;		/* skip blank lines */
	  if (rxmatch (destination, buff))
	    blocked = 1;
	}			/* while not at end of blocked list */
      fclose (block);
    }
  else
    fprintf (errlog, "Could not open %s.\n", DESTBLOCK);

  if (blocked)
    fprintf (errlog, "Blocked destination %s\n", destination);

  return (blocked);
}

int
destination_allow (const char *destination, int *mm)
{
  FILE *block;
  char buff[256];
  int allowed = 0;

  if ((block = try_open_mix_file (DESTALLOW, "r")) != NULL)
    {
      while (getline (buff, sizeof (buff), block) != NULL)
	{
	  if (buff[0] == '#' || strlen (buff) < 1)
	    continue;		/* skip blank lines */
	  if (rxmatch (destination, buff))
	    allowed = 1;
	}			/* while not at end of blocked list */
      fclose (block);
    }
  if (!allowed)
    *mm = 2;
  return (0);
}

int
header_block (const char *header, int *mm)
{
  FILE *block;
  char buff[256];
  int blocked = 0;

  if (*mm >= 2)
    return (0);			/* no blocking */

  /* filter blocked header lines */
  if ((block = try_open_mix_file (HDRFILTER, "r")) != NULL)
    {
      while (getline (buff, sizeof (buff), block) != NULL)
	{
	  if (buff[0] == '#' || strlen (buff) < 1)
	    continue;		/* skip blank lines */
	  if (
	       rxmatch (header, buff)
	     || (strileft (header, "Cc:") && destination_block (header, mm))
	   || (strileft (header, "Bcc:") && destination_block (header, mm)))
	    blocked = 1;
	}			/* while not at end of blocked list */
      fclose (block);
    }

  if (blocked)
    fprintf (errlog, "Blocked header line %s\n", header);

  return (blocked);
}

FILE *
open_pipe (char *prog, char *attr)
{
  FILE *ptr;
  ptr = popen (prog, attr);
  if (ptr == NULL)
    fprintf (errlog, "Error: Unable to open pipe to %s\n", prog);
  return ptr;
}

int
close_pipe (FILE * fp)
{
  return (pclose (fp));
}

void
parse_filename (char *out, const char *in)
{
  if (in[0] == '/'
#ifdef MSDOS
      || in[0] == '\\' || in[1] == ':'
#endif
  )
    strcpy (out, in);
  else if ((in[0] == '~') && (in[1] == '/') && getenv ("HOME"))
    sprintf (out, "%s/%s", getenv ("HOME"), in + 1);
  else if (streq (in, "-"))
    strcpy (out, "-");
  else
    sprintf (out, "%s/%s", cur_dir, in);
}

void
chop (char *s)
{
  int l;
  if (*s != 0)
    {
      l = strlen (s);
      if (s[l - 1] < ' ')
	s[l - 1] = 0;
    }
}

/*
 * When the mail system starts the remailer as user nobody, it must run
 * suid to access its files. We drop our privileges when the user has
 * set MIXPATH, tries to access files or to generate keys.
 */

#define USER 1
#define MIX 2

static uid_t umix;
static uid_t uuser;
static int u = 0;

void
user_uid (void)
{
#ifndef MSDOS
  if (u == 0)
    {
      umix = geteuid ();
      uuser = getuid ();
    }
  if (umix != uuser)
    {
      u = USER;
      setuid (uuser);
    }
#endif
}

void
mix_uid (void)
{
#ifndef MSDOS
  if (umix != uuser)
    {
      u = MIX;
      setuid (umix);
    }
#endif
}

void
drop_mix_uid (void)
{
#ifndef MSDOS
  user_uid ();
  umix = uuser;
#endif
}

void
from (FILE * f)
{
  fprintf (f, "From: %s <%s>\n", REMAILERNAME, REMAILERADDR);
}

void
fromanon (FILE * f)
{
  fprintf (f, "From: %s <%s>\n", ANONNAME, ANONADDR);
  fprintf (f, DISCLAIMER);
}

void
to (FILE * f, const char *address)
{
  fprintf (f, "To: %s\n", address);
}

void
get_from (const char *tmpname, char *from)
     /* pass filename, and string to hold address */
{
  /*
     * Modified to use sscanf and check for Reply-To: header; added
     * some comments -Futplex <futplex@pseudonym.com> 95/07/28
   */

  char input[256], *t;
  int i;
  int BestFound = 2;
  FILE *fptr;

  static char *Header[] =
  {
    "reply-to:",
    "from:"
  };

  from[0] = '\0';

  /* RFC 822 <URL: http://ds.internic.net/rfc/rfc822.txt> recommends
   * that automatic replies be directed to originating address(es)
   * according to the following priority:
   * (0) contents of Reply-To: header, if present
   * (1) contents of From: header, if no Reply-To: header is present
   */

  /* open the file for reading */
  if ((fptr = open_mix_file (tmpname, "r")) == NULL)
    return;

  /* read headers a line at a time */
  while (getline (input, sizeof (input), fptr) != NULL)
    {
      /* empty line delineates the header/body boundary  */
      if (input[0] == '\0')
	break;

      /* look for an RFC 822 preferred reply header (case insensitive match) */
      for (i = 0; i < BestFound; i++)
	{
	  if (strileft (input, Header[i]))
	    {
	      t = input + strlen (Header[i]);
	      while (*t == ' ' || *t == '\t')
		t++;
	      strcpy (from, t);
	      BestFound = i;
	    }
	}
      /* stop looking if we've already found a Reply-To: header */
      if (BestFound == 0)
	break;
    }

  /* close the input file, and return the reply address */
  fclose (fptr);
}

/* Base 64 encoding adapted from George Barwood's public domain package
   Pegwit: BAS64 armour by Mr. Tines <tines@windsong.demon.co.uk> */

static byte bintoasc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static byte asctobin[] =
{
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0x80, 0x80, 0076, 0x80, 0x80, 0x80, 0077,
  0064, 0065, 0066, 0067, 0070, 0071, 0072, 0073,
  0074, 0075, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0000, 0001, 0002, 0003, 0004, 0005, 0006,
  0007, 0010, 0011, 0012, 0013, 0014, 0015, 0016,
  0017, 0020, 0021, 0022, 0023, 0024, 0025, 0026,
  0027, 0030, 0031, 0x80, 0x80, 0x80, 0x80, 0x80,
  0x80, 0032, 0033, 0034, 0035, 0036, 0037, 0040,
  0041, 0042, 0043, 0044, 0045, 0046, 0047, 0050,
  0051, 0052, 0053, 0054, 0055, 0056, 0057, 0060,
  0061, 0062, 0063, 0x80, 0x80, 0x80, 0x80, 0x80
};

static void
encode_bytes (byte * enc, byte * data, int len)
{
  byte p[3];
  p[0] = data[0], p[1] = data[1], p[2] = data[2];
  if (len < 3)
    {
      p[len] = 0;
      enc[2] = enc[3] = '=';
    }
  enc[0] = bintoasc[p[0] >> 2];
  enc[1] = bintoasc[((p[0] << 4) & 0x30) | ((p[1] >> 4) & 0x0F)];
  if (len > 1)
    {
      enc[2] = bintoasc[((p[1] << 2) & 0x3C) | ((p[2] >> 6) & 0x03)];
      if (len > 2)
	enc[3] = bintoasc[p[2] & 0x3F];
    }
}

int
encode_block (byte * enc, int *enclen, byte * data, int datalen)
{
  *enclen = 0;
  while (datalen > 0)
    {
      encode_bytes (enc, data, datalen);
      enc += 4, *enclen += 4, data += 3, datalen -= 3;
    }
  return 0;
}

int
decode_block (byte * data, int *datalen, byte * enc, int enclen)
{
  unsigned int bytes, e0, e1, e2, e3, c0, c1, c2, c3;

  *datalen = 0;
  while (enclen > 0)
    {
      if (enclen < 4)
	return -1;

      if (strileft (enc, "=46"))/* accept quoted printable encoded F */
	{
	  e0 = 'F', enc += 2, enclen -= 2;
	  if (enclen < 4)
	    return -1;
	}
      else
	e0 = enc[0];
      e1 = enc[1], e2 = enc[2], e3 = enc[3];

      if (strileft (enc + 2, "=3d=3d"))
	bytes = 1, e2 = e3 = 'A', enc += 4, enclen -= 4;
      else if (strileft (enc + 3, "=3d"))
	bytes = 2, e3 = 'A', enc += 2, enclen -= 2;
      else if (strileft (enc + 2, "=="))
	bytes = 1, e2 = e3 = 'A';
      else if (strileft (enc + 3, "="))
	bytes = 2, e3 = 'A';
      else
	bytes = 3;

      if (enclen < 4)
	return -1;

      if (e0 & 0x80 || (c0 = asctobin[e0]) & 0x80 ||
	  e1 & 0x80 || (c1 = asctobin[e1]) & 0x80 ||
	  e2 & 0x80 || (c2 = asctobin[e2]) & 0x80 ||
	  e3 & 0x80 || (c3 = asctobin[e3]) & 0x80)
	return -1;

      data[0] = (unsigned char) ((c0 << 2) | (c1 >> 4));
      data[1] = (unsigned char) ((c1 << 4) | (c2 >> 2));
      data[2] = (unsigned char) ((c2 << 6) | c3);

      data += bytes, *datalen += bytes, enc += 4, enclen -= 4;
    }
  return 0;
}

void
armor (BUFFER * buff)
{
  byte *temp, *byteptr;
  int i;

  temp = malloc (4 * (buff->length) / 3 + 3);
  byteptr = temp;
  encode_block (byteptr, &i, (unsigned char *) buff->message,
		buff->length);

  reset_buffer (buff);

  while (i > ARMOREDLINE)
    {
      add_to_buffer (buff, byteptr, ARMOREDLINE);
      add_to_buffer (buff, "\n", 1);
      i -= ARMOREDLINE;
      byteptr += ARMOREDLINE;
    }
  add_to_buffer (buff, byteptr, i);
  add_to_buffer (buff, "\n", 1);
  free (temp);
}

int
dump_to_file (char *filename)
     /* dumps stdin to a tempfile. Returns the name of the file in filename. */
{
  int fd, len, in;
  char chunk[1024], name[80] = "";
  FILE *fptr;

  in = fileno (stdin);
  strcpy (name, "tmpM");
  fptr = tempfile (name);
  fd = fileno (fptr);
  strcpy (filename, name);
  while ((len = read (in, chunk, sizeof (chunk))) > 0)
    {
      write (fd, chunk, len);
    }
  fclose (fptr);
  if (len == 0)
    return (1);
  unlink (name);
  return (0);
}

int
strileft (const char *string, const char *keyword)
{
  unsigned int i;

  for (i = 0; i < strlen (keyword); i++)
    if (tolower (string[i]) != tolower (keyword[i]))
      return 0;
  return 1;
}

int
strleft (const char *string, const char *keyword)
{
  return (strstr (string, keyword) == string);
}

int
streq (const char *s1, const char *s2)
{
  return (strcmp (s1, s2) == 0);
}

int
strifind (const char *string, const char *keyword)
{
  unsigned int i, j;

  for (i = 0, j = 0; i < strlen (string); i++)
    if (tolower (string[i]) == tolower (keyword[j]))
      {
	if (++j >= strlen (keyword))
	  return 1;
      }
    else
      j = 0;			/* Reset search on non-match */
  return 0;
}

int
strieq (const char *s1, const char *s2)
{
  unsigned int i;

  if (strlen (s1) != strlen (s2))
    return 0;

  for (i = 0; i <= strlen (s1); i++)
    if (tolower (s1[i]) != tolower (s2[i]))
      return 0;
  return 1;
}

FILE *
mailfile (void)
{
  int i = 0;
  char fn[12];
  FILE *f;
  for (;;)
    {
      sprintf (fn, "outfile.%i", i);
      f = fopen (fn, "r");
      if (f == 0)
	{
	  return fopen (fn, "w");
	}
      fclose (f);
      i++;
    }
}

char *
make_digest (BUFFER * b, char *new_digest)
{
  char d[128];
  int len;

#ifdef USE_RSAREF
  R_DIGEST_CTX digest_context;

  R_DigestInit (&digest_context, DA_MD5);
  R_DigestUpdate (&digest_context, b->message, b->length);
  R_DigestFinal (&digest_context, d, &len);
#else
  B_ALGORITHM_OBJ digest_obj;

  B_CreateAlgorithmObject (&digest_obj);
  B_SetAlgorithmInfo (digest_obj, AI_MD5, NULL);

  B_DigestInit (digest_obj, NULL, CHOOSER, NULL);
  B_DigestUpdate (digest_obj, b->message, b->length, NULL);
  B_DigestFinal (digest_obj, d, &len, 16, NULL);
  B_DestroyAlgorithmObject (&digest_obj);
#endif

  add_to_random (d, len);
  memcpy (new_digest, d, 16);
  return (new_digest);
}

char *
getline (char *line, int size, FILE * fptr)
{
  char *r;
  int l;

  if ((r = fgets (line, size, fptr)) != NULL)
    {
      l = strlen (r);
      /* CRLF in the input file is treated as LF */
      if (l > 0 && r[l - 1] == '\n')
	{
	  r[l - 1] = '\0';
	  if (l > 1 && r[l - 2] == '\r')
	    r[l - 2] = '\0';
	}
    }
  return r;
}
