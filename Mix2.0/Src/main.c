/* $Id: main.c,v 1.3 2002/10/18 22:37:50 rabbi Exp $
 * 
 * $Log: main.c,v $
 * Revision 1.3  2002/10/18 22:37:50  rabbi
 * We prepend the protocol version string to the software version number in
 * the type 2 capstring. This is necessary to allow existing Mixmaster
 * versions to interoperate with future versions of Mixmaster.
 *
 * This isn't strictly necessary with versions 2.x, but I'm making this
 * change for consistency.
 *
 * Revision 1.2  2002/08/29 19:54:47  rabbi
 * Fixed compilation error in main.c. The value of errlog is now assigned in
 * main().
 *
 * Revision 1.1.1.1  2002/08/28 20:06:50  rabbi
 * Mixmaster 2.0.5 source.
 *
 * Revision 2.13  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.12  1998/05/07  23:59:36  um
 * Moved IDEXP and PACKETEXP to mixmaster.conf.
 *
 * Revision 2.11  1998/04/20  14:13:59  um
 * Added support for type1 PGP-only remailers.
 *
 * Revision 2.9  1998/04/13  23:22:29  um
 * re-indented.
 *
 * Revision 2.8  1998/04/06  21:58:29  um
 * read_conf* macro bug fix by Johannes Kroeger.
 *
 * Revision 2.7  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 * Revision 2.6  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 * Revision 2.4  1998/02/17  23:25:41  um
 * Check for DecodePEM return value.
 *
 * Revision 2.2  1998/01/13  17:34:38  um
 * Increased version number.
 *
 * main.c         1997-12-08 um
 *      bug fix by Andy Dustman.
 *
 * main.c         1997-11-10 um
 *      source block Reply-To and Sender address.
 *
 * main.c         1997-11-07 um
 *      mix server command line option -D1 for single protocol run.
 *      -GD to generate DH parameter.
 *
 * main.c         1997-10-10 um
 *      parse header lines without " " after the ":" correctly. bug fix from
 *        Johannes Kroeger.
 *
 * main.c         1997-10-07 um
 *      bug fix from Johannes Kroeger: skip blank lines in source.block.
 *      bug fix for opening mixmaster.conf under DOS.
 *      removed read_conf_wt macro.
 *
 * main.c         1997-09-23 um
 *      new mixmaster.conf entry VERBOSE.
 *
 * main.c         1997-09-18 um
 *      help/key/stats requests must be case-insensitive exact match.
 *
 * main.c         1997-09-15 um
 *      string size check for $HOME/Mix corrected.
 *
 * main.c         1997-09-07 um
 *      Win95: try opening mixmaste.con if mixmaster.conf doesn't exist.
 *
 * main.c         1997-09-02 um
 *      -Q takes additional destination as optional argument.
 *
 * main.c         1997-08-26 um
 *      bug fixes in init_mix().
 *
 * main.c         1997-08-20 JK
 *      bug fix in init_mix(), regexp source blocking.
 *
 * main.c         1997-08-17 JK
 *      support for additional type1 headers.
 *      improved configuration lines.
 *
 * main.c         1997-08-15 um
 *
 * main.c         1997-07-11 ad
 *     support for ANONNAME (long name for anonymous messages).
 *
 * main.c         1997-07-01 um
 *     middleman patch.
 *
 * main.c         1997-06-18 um
 *     new mixmaster.conf entries.
 *
 * main.c         1997-06-13 um
 *     use capital letters for remailer functions (-K, -X)
 *
 * main.c         1997-06-08 um
 *     call init_our_random also if mixmaster.conf can't be read.
 *
 * main.c         1996-12-11 um
 *      new option -k for key management.
 *
 * main.c         1996-10-26 um
 *      additional entries in mixmaster.conf
 *      remailer message: 1st non-empty line begins with ::
 *
 * main.c         1996-07-11 um
 *      new option -x to seed the random number generator
 *
 *      modified for DOS. um
 *
 * main.c        1.4 11/9/95
 *      Mixmaster now chdir's to mix_dir rather than prepending
 *      That directory to every filename.
 *      Magic strings now defined here rather than in mixmaster.h
 *
 *      -P prints out three lines,
 *              current mix_dir
 *              filename containing the list of remailers
 *              current version of Mixmaster.
 *
 * main.c        1.3 5/10/95
 *      -t and To: replaces destination on command line
 *
 * main.c        1.2 5/10/95
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

#include "version.h"

#include "mix.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

char remailer_type[] = "Remailer-Type: Mixmaster ";
char mixmaster_protocol[] = "2:";
char begin_remailer[] = "-----BEGIN REMAILER MESSAGE-----";
char end_remailer[] = "-----END REMAILER MESSAGE-----";
char begin_key[] = "-----Begin Mix Key-----";
char end_key[] = "-----End Mix Key-----";
char begin_cfg[] = "-----Begin Mix Config-----";
char end_cfg[] = "-----End Mix Config-----";
char begin_signed[] = "-----Begin Mix Signed Data-----";
char begin_signature[] = "-----Begin Mix Signature-----";
char end_signature[] = "-----End Mix Signature-----";
char intermed_hop[] = "-----Intermediate Hop-----";
char final_hop[] = "-----Final Hop-----";

char mix_dir[256] = "";
char cur_dir[256];
char KEYFILE[256] = "mix.key";
char HELPFILE[256] = "mix.help";
char KEYINFO[256] = "keyinfo.txt";
char REMAILERNAME[256] = "Anonymous Remailer";
char SHORTNAME[256] = "foo";
char REMAILERADDR[256] = "";
char ANONADDR[256] = "";
char ANONNAME[256] = "";
char COMPLAINTS[256] = "";
int POOLSIZE = 0;
int POOLTIMEOUT = 0;
int RATE = 100;
char REMAILERLIST[256] = "type2.list";
char IDLOG[256] = "id.log";
char STATS[256] = "stats.log";
char SECRING[256] = "secring.mix";
char PUBRING[256] = "pubring.mix";
char SOURCEBLOCK[256] = "source.block";
char DESTALLOW[256] = "destination.allow";
char DESTBLOCK[256] = "destination.block";
char HDRFILTER[256] = "headers.del";
char MIXRAND[256] = "mixrand.bin";
/* the -t option tells sendmail to expect a To: header in stdin */
char SENDMAIL[256] = "/usr/lib/sendmail -t";
char NEWS[256] = "";
char ORGANIZATION[256] = "";
char MAILtoNEWS[256] = "mail2news@nym.alias.net";
char TYPE1[256] = "";		/* Default is no Type 1 support */
int T1PGPONLY = 0;
char REJECT[256] = "M";
char REQUIRE[256] = "";
char CHAIN[256] = "";
int DISTANCE = 2;
char RELLIST[256] = "mix.list";
char FORWARDTO[256] = "0";
int MINREL = 98;
int RELFINAL = 99;
int MAXLAT = 24;		/* in hours!  Default: one day */
int MINREMAILERS = 1;
int NUMCOPIES = 1;
int VERBOSE = 0;
int CREATEKEYS = 0;
int KEYVALIDITY = 30;
int KEYOVERLAP = 5;
int MIDDLEMAN = 0;
/*Expiration time for old packets and id numbers in hours */
int PACKETEXP = 7 * 24;
int IDEXP = 7 * 24;
int ERRSTDOUT = 0;
FILE *errlog;

#ifdef USE_BSAFE
B_ALGORITHM_METHOD *CHOOSER[] =
{
  &AM_DESX_CBC_DECRYPT,
  &AM_DESX_CBC_ENCRYPT,
  &AM_DES_CBC_DECRYPT,
  &AM_DES_CBC_ENCRYPT,
  &AM_DES_EDE3_CBC_DECRYPT,
  &AM_DES_EDE3_CBC_ENCRYPT,
  &AM_DH_KEY_AGREE,
  &AM_DH_PARAM_GEN,
  &AM_DSA_KEY_GEN,
  &AM_DSA_PARAM_GEN,
  &AM_DSA_SIGN,
  &AM_DSA_VERIFY,
  &AM_MAC,
  &AM_MD,
  &AM_MD2,
  &AM_MD2_RANDOM,
  &AM_MD5,
  &AM_MD5_RANDOM,
  &AM_RC2_CBC_DECRYPT,
  &AM_RC2_CBC_ENCRYPT,
  &AM_RC4_DECRYPT,
  &AM_RC4_ENCRYPT,
  &AM_RC4_WITH_MAC_DECRYPT,
  &AM_RC4_WITH_MAC_ENCRYPT,
  &AM_RC5_CBC_DECRYPT,
  &AM_RC5_CBC_ENCRYPT,
  &AM_RSA_CRT_DECRYPT,
  &AM_RSA_CRT_ENCRYPT,
  &AM_RSA_DECRYPT,
  &AM_RSA_ENCRYPT,
  &AM_RSA_KEY_GEN,
  &AM_SHA,
  NULL
};
#endif

#ifdef MSDOS
void
cdcurdir (void)
{
  chdir (cur_dir);
}

#endif

/* read word from mixmaster.conf */
#define read_conf(t) \
if (strncmp (line, #t, sizeof (#t) - 1) == 0 && isspace (line[sizeof (#t) - 1]))\
   sscanf (line, "%s %s", junk, t);

/* read line from mixmaster.conf, with whitespace */
#define read_conf_w(t) \
if (strncmp (line, #t, sizeof (#t) - 1) == 0 && isspace (line[sizeof (#t) - 1])) {\
   foo = line;\
   while (*foo > ' ') foo++; /* scan to first space */ \
   while (*foo > '\0' && *foo <= ' ') foo++; /* scan to first non whitespace */ \
   strcpy(t, foo);\
   chop (t);}

/* read number from mixmaster.conf */
#define read_conf_i(t) \
if (strncmp (line, #t, sizeof (#t) - 1) == 0 && isspace (line[sizeof (#t) - 1]))\
   sscanf (line, "%s %d", junk, &t);

int
init_mix (void)
{
  FILE *fptr, *tmp;
  char line[256], junk[256], *foo;

  umask (077);
  mix_dir[0] = 0;
  strncat (mix_dir, SPOOL, sizeof (mix_dir) - 1);
  /* environment variable replaces defined value */
  if ((foo = getenv ("MIXPATH")) != NULL)
    {
      mix_dir[0] = 0;
      strncat (mix_dir, foo, sizeof (mix_dir) - 1);
    }
  if (!getcwd (cur_dir, sizeof (cur_dir)))
    {				/*could not get current dir */
      fprintf (errlog, "Could not get current directory!\n");
      strcpy (cur_dir, mix_dir);/* So set cur_dir to mix_dir */
    }
  if (cur_dir[strlen (cur_dir) - 1] != '/')
    strcat (cur_dir, "/");
#ifdef MSDOS
  atexit (cdcurdir);
#endif
  if (mix_dir[0] == '\0')
    {
      if ((foo = getenv ("HOME")) != NULL)	/* try ~/Mix */
	{
	  strncat (mix_dir, foo, sizeof (mix_dir) - 1);
	  strncat (mix_dir, "/Mix", sizeof (mix_dir) - strlen (mix_dir) - 1);
	}
    }
  if (!streq (SPOOL, mix_dir))
    drop_mix_uid ();
  if ((mix_dir[0] != '\0') && (chdir (mix_dir) != 0))
    fprintf (errlog, "Error changing to directory %s.\n", mix_dir);

  init_our_random ();

#ifdef MSDOS
  strcpy (SENDMAIL, "outfile");
#endif

#ifdef SHORTNAMES
  if ((fptr = (FILE *) try_open_mix_file ("mixmaster.conf", "r")) != NULL
      || (fptr = (FILE *) open_mix_file ("mixmaste.con", "r")) != NULL)
#else
  if ((fptr = (FILE *) open_mix_file ("mixmaster.conf", "r")) != NULL)
#endif
    {
      while (getline (line, sizeof (line), fptr) != NULL)
	{
	  if (line[0] != '#' && strlen (line) > 1)
	    {
	      if (strleft (line, "mix_dir"))
		{
		  sscanf (line, "%s %s", junk, mix_dir);
		  if (chdir (mix_dir) != 0)
		    {
		      fprintf (errlog, "Error changing to mix_dir %s\n", mix_dir);
		    }
		}
	      if (strncmp (line, "help", 4) == 0)
		sscanf (line, "%s %s", junk, HELPFILE);
	      if (strncmp (line, "key", 3) == 0)
		sscanf (line, "%s %s", junk, KEYFILE);
	      read_conf (KEYINFO);
	      read_conf (SHORTNAME);
	      read_conf (REMAILERADDR);
	      read_conf (ANONADDR);
	      read_conf_w (ANONNAME);
	      read_conf_w (REMAILERNAME);
	      read_conf_w (TYPE1);
	      read_conf_i (T1PGPONLY);
	      read_conf (COMPLAINTS);
	      read_conf_i (POOLSIZE);
	      read_conf_i (POOLTIMEOUT);
	      read_conf_i (RATE);
	      read_conf (REMAILERLIST);
	      read_conf (IDLOG);
	      read_conf (STATS);
	      read_conf (SECRING);
	      read_conf (PUBRING);
	      read_conf (SOURCEBLOCK);
	      read_conf (DESTALLOW);
	      read_conf (DESTBLOCK);
	      read_conf (HDRFILTER);
	      read_conf (MIXRAND);
	      read_conf (MAILtoNEWS);
	      read_conf_w (SENDMAIL);
	      read_conf_w (NEWS);
	      read_conf_w (ORGANIZATION);
	      read_conf (REQUIRE);
	      read_conf (REJECT);
	      read_conf_w (CHAIN);
	      read_conf_i (DISTANCE);
	      read_conf (RELLIST);
	      read_conf_w (FORWARDTO);
	      read_conf_i (MINREL);
	      read_conf_i (RELFINAL);
	      read_conf_i (MAXLAT);
	      read_conf_i (MINREMAILERS);
	      read_conf_i (NUMCOPIES);
	      read_conf_i (VERBOSE);
	      read_conf_i (CREATEKEYS);
	      read_conf_i (KEYVALIDITY);
	      read_conf_i (KEYOVERLAP);
	      read_conf_i (MIDDLEMAN);
	      read_conf_i (PACKETEXP);
	      read_conf_i (IDEXP);
	      read_conf_i (ERRSTDOUT);
	    }			/* if not comment */
	}
      fclose (fptr);
    }
  if (ERRSTDOUT == 1)
    errlog = stdout;
  if (ANONNAME[0] == '\0')
    strcpy (ANONNAME, REMAILERNAME);
  if (ANONADDR[0] == '\0')
    strcpy (ANONADDR, REMAILERADDR);
  if (COMPLAINTS[0] == '\0')
    strcpy (COMPLAINTS, REMAILERADDR);
  if (strstr (NEWS, "mail-to-news"))
    NEWS[0] = '\0';
  else
    MAILtoNEWS[0] = '\0';
  /* middleman flag:
         0 = normal remailer
         1 = middle only remailer
         2 = middleman (hidden remailer)
         3 = middleman, remail intermediate hops */
  if (MIDDLEMAN > 0)
    MIDDLEMAN++;
  else if ((tmp = try_open_mix_file (DESTALLOW, "r")) != NULL)
    {
      MIDDLEMAN = 1;
      fclose (tmp);
    }
  if (IDEXP != 0 && IDEXP < 4 * 24)
      IDEXP = 4 * 24;
  return (0);
}

int
extract_type2_message (FILE * fptr, char *filename)
     /* Fetch the next type2 message from the stream fptr.
      * Place in a temporary file and return its file name in filename. */
{
  char line[256];
  FILE *temp_fptr;

  strcpy (filename, "tmpM");
  temp_fptr = tempfile (filename);

  /* Find the first line of the type2 message */
  while (getline (line, sizeof (line), fptr) != NULL)
    {
      if (streq (line, begin_remailer))
	break;
    }

  if (!streq (line, begin_remailer))
    {				/* did we find begin? */
      fclose (temp_fptr);
      unlink (filename);
      return (0);
    }
  fprintf (temp_fptr, "%s\n", line);	/* put begin remail line */
  while (getline (line, sizeof (line), fptr) != NULL)
    {
      fprintf (temp_fptr, "%s\n", line);
      if (streq (line, end_remailer))
	break;
    }

  fclose (temp_fptr);
  return 1;
}

void
help_files (int type, char *tmpfile)
{
  char address[256], *outfile = "", line[256], *tmp;
  FILE *fp, *pp;

  get_from (tmpfile, address);
  if (strlen (address) <= 1)
    return;

  switch (type)
    {
    case 100:
      outfile = HELPFILE;
      break;
    case 101:
      stats (FL_STATS, address);
      return;			/* send useage stats */
    case 200:
      outfile = KEYFILE;
      break;
    case 201:
      abilities (address);
      return;
    }
  if (strlen (outfile) > 1)
    {
      if ((fp = open_mix_file (outfile, "r")) == NULL)
	return;
      if ((pp = open_sendmail (MIDDLEMAN, &tmp)) == NULL)
	return;
      to (pp, address);
      while (getline (line, sizeof (line), fp) != NULL)
	fprintf (pp, "%s\n", line);
      fclose (fp);
      close_sendmail (pp, tmp);
    }
}

int
kind_of_message (char *filename)
     /*
        Returns -1 if error
        Returns 0 if not a remailer message
        Returns 1 if normal remailer message
        Returns 2 if a type 2 remailer
        Returns 100 this is a request for the help file
        Returns 101 this is a request for the remailer usage statistics
        Returns 200 request for the remailer's public key
        Returns 201 request for remailer configuration line (flags indicating
        abilities)
      */
{
  FILE *fptr, *block;
  char line[256], *t, buff[256];
  int type = 0;

  if ((fptr = open_mix_file (filename, "r")) == NULL)
    return (-1);
  getline (line, sizeof (line), fptr);
  while (line[0] != '\0' && line[0] != ':')
    {
      if (strileft (line, "Subject:"))
	{
	  t = line + sizeof ("Subject:") - 1;
	  while (*t == ' ' || *t == '\t')
	    t++;
	  if (strieq (t, "help"))
	    type = 100;
	  if (strieq (t, "remailer-help"))
	    type = 100;
	  if (strieq (t, "remailer-stats"))
	    type = 101;
	  if (strieq (t, "remailer-key"))
	    type = 200;
	  if (strieq (t, "remailer-conf"))
	    type = 201;
	  if (strieq (t, "freedom-help") ||
	      strieq (t, "freedom-stats") ||
	      strieq (t, "freedom-key") ||
	      strieq (t, "freedom-conf"))
	    type = 1;
	}
      if (strileft (line, "encrypted:"))
	type = 1;
      if (!T1PGPONLY && (strileft (line, "anon-to:") ||
			 strileft (line, "request-remailing-to:") ||
			 strileft (line, "remail-to:") ||
			 strileft (line, "anon-post-to:") ||
			 strileft (line, "post-to:") ||
			 strileft (line, "anon-send-to:") ||
			 strileft (line, "send-to:")))
	type = 1;
      if (type != 0)
	{
	  fclose (fptr);
	  return (type);
	}
      if (strileft (line, "From") || strileft (line, "Reply-To") ||
	  strileft (line, "Sender"))
	{
	  if ((block = try_open_mix_file (SOURCEBLOCK, "r")) != NULL)
	    {
	      while (getline (buff, sizeof (buff), block) != NULL)
		{
		  if (buff[0] == '#' || strlen (buff) < 1)
		    continue;	/* skip blank lines */
		  if (rxmatch (line, buff))
		    {		/* if buff is in From line */
		      fclose (block);
		      fclose (fptr);
		      return (-1);	/* blocked address treated as an error */
		    }
		}
	      fclose (block);
	    }
	  else
	    fprintf (errlog, "Could not open %s.\n", SOURCEBLOCK);
	}
      if (getline (line, sizeof (line), fptr) == NULL)
	break;			/* scan for first blank line */
    }
  while (line[0] == '\0' && getline (line, sizeof (line), fptr) != NULL);
  /*read in next line till not blank again */
  if (strncmp (line, "::", 2) != 0)
    {				/* if first non blank is not :: then
				   not a remailer message */
      type = 0;
    }
  else
    {				/* It is a remailer */
      getline (line, sizeof (line), fptr);
      if (strileft (line, "Remailer-Type:"))
	/* All Type 2 messages start with this ... */
	type = 2;
      else if (T1PGPONLY && !strileft (line, "Encrypted:"))
	type = 0;		/* don't remail plaintext messages */
      else
	type = 1;
    }
  fclose (fptr);
  return (type);
}

int
main (int argc, char *argv[])
{
  FILE *fptr, *lockptr;
  char tmpfile[80], tmpfile2[80];
  int i, error, type;
  int rem = 0, snd = 0, lat = 0, chain = 0, gen = 0, keymgt = 0;
  int path = 0, type_list = 0, demon = 0, randseed = 0, queue = 0;
  errlog = stderr;

  init_mix ();

  for (i = 1; i < argc; i++)
    {
      if (strchr (argv[i], '-') != NULL)
	{
	  if (streq (argv[i], "-R"))
	    rem = 1;
	  if (streq (argv[i], "-r"))
	    rem = 1;		/* some aliases don't allow caps */
	  if (streq (argv[i], "-S"))
	    snd = 1;
	  if (streq (argv[i], "-L"))
	    lat = 1;
	  if (streq (argv[i], "-G"))
	    gen = 1;
	  if (streq (argv[i], "-GD"))
	    gen = 2;
	  if (streq (argv[i], "-K"))
	    keymgt = 1;
	  if (streq (argv[i], "-P"))
	    path = 1;
	  if (streq (argv[i], "-T"))
	    type_list = 1;
	  if (streq (argv[i], "-D"))
	    demon = 1;
	  if (streq (argv[i], "-D1"))
	    demon = 2;
	  if (streq (argv[i], "-c"))
	    chain = 1;
	  if (streq (argv[i], "-X"))
	    randseed = 1;
	  if (streq (argv[i], "-Q"))
	    {
	      queue = 1;
	      if ((i + 1 < argc) && (argv[i + 1][0] != '-'))
		queue_msg (argv[++i]);
	      else
		queue_msg (NULL);
	    }
	}
    }

  if (!rem && !snd && !lat && !gen && !keymgt && !path && !type_list && !demon && !randseed && !queue)
    chain = 1;

  if (path)
    {
      printf ("%s\n", mix_dir);	/* note no trailing slash here */
      printf ("%s\n", REMAILERLIST);
      printf ("%s\n", VERSION);
    }
  if (type_list)
    {
      file_to_out (REMAILERLIST);
    }
  if (randseed)
    {
      get_randomness ();
    }
  if (chain)
    {
      chain_2 (argc, argv);
      rem = snd = lat = 0;	/* chain kills all others */
    }
  if (rem)
    {
      error = dump_to_file (tmpfile);
      if (error == 0)
	exit (1);
      type = kind_of_message (tmpfile);
      if (type == -1)
	unlink (tmpfile);
      if (type == 0)
	{
	  file_to_out (tmpfile);
	  unlink (tmpfile);
	}
      if (type == 1)
	{
	  if (strlen (TYPE1) > 1)
	    {			/* is there a type 1 handler defined */
	      type_1 (tmpfile);
	      stats (FL_MESSAGE | FL_OLD, NULL);
	    }
	  unlink (tmpfile);
	}
      if (type == 2)
	{
	  /*
	   * changing this section to allow multiple Mixmaster
	   * Messages in one file going to Mixmaster
	   */
#if 0
	  if (type_2 (tmpfile) == 0)
	    {
	      stats (FL_MESSAGE | FL_NEW, NULL);	/* count one type 2 message */
	    }
	  unlink (tmpfile);
#endif
	  if ((fptr = open_mix_file (tmpfile, "r")) != NULL)
	    while (extract_type2_message (fptr, tmpfile2))
	      {
		if (type_2 (tmpfile2) == 0)
		  {
		    stats (FL_MESSAGE | FL_NEW, NULL);	/* count one type 2 message */
		  }
		unlink (tmpfile2);
	      }
	  unlink (tmpfile);
	}
      if (type > 2)
	{
	  help_files (type, tmpfile);
	  unlink (tmpfile);
	}
    }
  if (snd)
    {
      if (process_pool () <= 0)
	fprintf (errlog, "Error in sending mail from the pool!\n");
      mix_lock ("mail", &lockptr);
      packetID_housekeeping ();
      process_partial ();
      mix_unlock ("mail", lockptr);
    }
  if (gen == 2)
    generate_DH ();
  else if (gen)
    {
      generate_permanent_key ();
      update_keys (NULL);
    }
  if (keymgt)
    {
      if (!isatty (fileno (stdin)))
	update_keys (stdin);	/* new keys */
      else
	update_keys (NULL);
    }
  if (lat)
    {
      mix_lock ("latent", &lockptr);
      process_latent ();
      mix_unlock ("latent", lockptr);
    }
  if (demon)
    {
      mix_server (demon);
    }
  close_our_random ();

  return (0);
}
