
/* $Id: stats.c,v 1.1 2002/08/28 20:06:50 rabbi Exp $
 * $Log: stats.c,v $
 * Revision 1.1  2002/08/28 20:06:50  rabbi
 * Initial revision
 *
 * Revision 2.4  1998/08/21  13:26:08  um
 * *** empty log message ***
 *
 * Revision 2.3  1998/05/13  09:41:59  um
 * Bug fix for remailer-stats with an incomplete database.
 *
 * Revision 2.2  1998/04/13  23:22:29  um
 * re-indented.
 *
 *
 * stats.c            1997-09-18 um
 *      latency stats patch from Andy Dustman.
 *      use fputs to print arbitrary text (patch from Johannes Kroeger).
 *
 * stats.c            1997-08-25 um
 *      remailer-conf includes mixmaster version.
 *
 * stats.c            1997-08-23 um
 *      minor modifications to statistics output.
 *
 * stats.c            1997-08-20 ad
 *      Scaled bar graph for statistics with mix/cpunk stacked bars,
 *      by Andy Dustman
 *
 * stats.c            1997-08-15 um
 *
 * stats.c            1997-07-01 um
 *      middleman patches.
 *
 * stats.c            1997-06-12 um
 *      improved output format, by Johannes Kroeger
 *
 * stats.c            1997-05-30 um
 * stats.c            1996-11-27 um
 *      output for remailer_conf
 *
 * stats.c        1.3 11/22/95
 *      Info on news posting setings printed at end of stats.
 *
 * stats.c        1.2 9/10/95
 *      Added automatic creation of non-existant stats.log file,
 *      and reinit to default if there is a problem
 *      Sendmail now uses To: not command line for destination.
 *
 *      (c) Copyright 1995 by Lance Cottrell. All right reserved.
 *      The author assumes no liability for damages resulting from the
 *      use of this software, even if the damage results from defects in
 *      this software. No warranty is expressed or implied.
 *
 *      This software is being distributed under the GNU Public Licence,
 *      see the file GNU.license for more details.
 *
 *      This software is slightly modified from Matt Ghio's "stats.c"
 *      distributed as part of his anonymous remailer.
 *
 *                      - Lance Cottrell (loki@obscura.com) 4/23/95
 *
 */

#include "mix.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <sys/stat.h>

#ifndef LOCK_SH
#define LOCK_SH 1		/* shared lock */
#define LOCK_EX 2		/* exclusive lock */
#define LOCK_NB 4		/* don't block when locking */
#define LOCK_UN 8		/* unlock */
#endif

/* this creates an empty stats file */
void
rebuild_stats ()
{
  int x;
  FILE *datafile;

  if ((datafile = open_mix_file (STATS, "w")) == NULL)
    return;			/* big problem */
  fprintf (datafile, "0\n");	/*dafault to zero hours */
  fprintf (datafile, "0 0 0\n");/* default no messages ever */
  for (x = 0; x < 24; x++)
    {
      fprintf (datafile, "tmp 1 0 0 0\n");	/* tmp for month. First day, no messages */
    }
  fclose (datafile);
}

void
stats (int flag, char *address)
{
  int m[24];
  int ccm, mmax = 0;
  float mscale;
  int p[24];
  int ccpgp;
  int l[24];
  int ccl;
  int s[24];
  int ccsent = 0;
  unsigned long int latent[24];
  unsigned long int cclatent = 0L;
  char month[24][80];
  int date[24];
  int hour;
  int currenthour;
  FILE *datafile, *pp, *statlock;
  int x;
  int x0;
  int y;
  int problem;
  char line[256], *tmp;

  struct tm *curtime;
  time_t now;

  now = time (NULL);
  curtime = localtime (&now);

  mix_lock ("stats", &statlock);
  if ((datafile = try_open_mix_file (STATS, "r")) == NULL)
    {
      rebuild_stats ();
      mix_unlock ("stats", statlock);
      return;
    }
  problem = 0;
  fgets (line, 80, datafile);
  sscanf (line, "%d", &hour);
  fgets (line, 80, datafile);
  sscanf (line, "%d %d %d %d %lu", &ccm, &ccpgp, &ccl, &ccsent, &cclatent);
  if (hour > 24 || hour < 0)
    problem = 1;
  if (ccm < 0 || ccpgp < 0 || ccl < 0)
    problem = 1;
  if (ccm > 10000 || ccpgp > 10000 || ccl > 10000)
    problem = 1;
  for (x = 0; x < 24; x++)
    {
      if (fgets (line, 80, datafile) == NULL)
	{
	  problem = 1;
	  break;
	}
      s[x] = 0;
      latent[x] = 0L;
      sscanf (line, "%s %d %d %d %d %d %lu", month[x], &date[x], &m[x], &p[x],
	      &l[x], &s[x], &latent[x]);
      if (strlen (month[x]) > 5)
	problem = 1;
      if (date[x] < 1 || date[x] > 31)
	problem = 1;
      if (m[x] < 0 || p[x] < 0 || l[x] < 0)
	problem = 1;
      if (m[x] > 10000 || p[x] > 10000 || l[x] > 10000)
	problem = 1;
    }

  if (problem)
    {
      fclose (datafile);
      rebuild_stats ();
      mix_unlock ("stats", statlock);
      return;
    }
  /*
     fscanf(datafile,"%d",&hour);
     fscanf(datafile,"%d %d %d",&ccm,&ccpgp,&ccl);
     for(x=0;x<24;x++) {
     fscanf(datafile,"%s %d %d %d %d",month[x],&date[x],&m[x],&p[x],&l[x]); }
   */
  fclose (datafile);
  mix_unlock ("stats", statlock);

  currenthour = curtime->tm_hour;

  x = hour;
  while (x != currenthour)
    {
      if (x > 0)
	{
	  strcpy (month[x], month[x - 1]);
	  date[x] = date[x - 1];
	}
      else
	{
	  strftime (month[0], 5, "%b", curtime);
	  date[0] = curtime->tm_mday;
	}
      m[x] = 0;
      p[x] = 0;
      l[x] = 0;
      s[x] = 0;
      latent[x] = 0;
      x++;
      if (x > 23)
	x = 0;
    }

  if (hour != currenthour)
    {
      m[hour] = ccm;
      p[hour] = ccpgp;
      l[hour] = ccl;
      s[hour] = ccsent;
      latent[hour] = cclatent;
      ccm = 0;
      ccpgp = 0;
      ccl = 0;
      ccsent = 0;
      cclatent = 0L;
    }
  if (flag & FL_MESSAGE)
    ccm++;
  if (flag & FL_OLD)
    ccpgp++;
  if (flag & FL_NEW)
    ccl++;
  if (flag & FL_LATENCY)
    {
      struct stat outmessage;
      time_t then;

      if (stat (address, &outmessage))
	{
	  fprintf (errlog, "stats: couldn't stat %s\n", address);
	}
      else
	{
	  then = outmessage.st_mtime;
	  cclatent += difftime (now, then) * difftime (now, then);
	  ccsent++;
	}
    }

  mix_lock ("stats", &statlock);
  if ((datafile = open_mix_file (STATS, "w")) == NULL)
    {
      mix_unlock ("stats", statlock);
      return;
    }
  fprintf (datafile, "%d\n", currenthour);
  fprintf (datafile, "%d %d %d %d %lu\n", ccm, ccpgp, ccl, ccsent, cclatent);
  for (x = 0; x < 24; x++)
    {
      fprintf (datafile, "%s %d %d %d %d %d %lu\n", month[x], date[x], m[x],
	       p[x], l[x], s[x], latent[x]);
    }

  fclose (datafile);
  mix_unlock ("stats", statlock);

  if (flag & FL_STATS)
    {
      if ((pp = open_sendmail (MIDDLEMAN, &tmp)) == NULL)
	return;
      fprintf (pp, "Subject: Re: Remailer Statistics\n");
      to (pp, address);		/* Here is the address now */
      fprintf (pp, "\n");
      fprintf (pp, "Statistics for last 24 hours from anonymous remailer\n");
      fprintf (pp, "%s\n", REMAILERNAME);
      fprintf (pp, "\n");
      if (streq (month[23], "tmp"))
      {
	  strcpy(month[23], month[0]);
	  date[23] = date[0] - 1;
      }
      fprintf (pp, "Number of messages per hour from %s %2d %02d:00 to %s %2d %02d:59\n",
	       month[23], date[23], currenthour, month[0], date[0], (currenthour + 23) % 24);
      fprintf (pp, "\n");
      /*ccm=0;ccpgp=0;ccl=0; */
      cclatent /= 3600;		/* prevent overflow */
      for (x = 0; x < 24; x++)
	mmax = (m[x] > mmax) ? m[x] : mmax;
      mscale = (mmax > 67) ? 67.0 / mmax : 1.0;
      for (x0 = 0; x0 < 24; x0++)
	{
	  x = (x0 + currenthour) % 24;
	  fprintf (pp, "%02d:00 (%3d) ", x, m[x]);
	  if (m[x] > 0)
	    {
	      for (y = 0; y < l[x] * mscale; y++)
		fprintf (pp, "*");
	      for (y = 0; y < p[x] * mscale; y++)
		fprintf (pp, "+");
	      ccm += m[x];
	      ccpgp += p[x];
	      ccl += l[x];
	      ccsent += s[x];
	      cclatent += latent[x] / 3600;
	    }
	  fprintf (pp, "\n");
	}
      fprintf (pp, "\n");
      if (strlen (TYPE1) > 1)
	{			/* We support type 1 messages */
	  fprintf (pp, "Total messages remailed in last 24 hours:\t%5d\n", ccm);
	  fprintf (pp, "Number of Mixmaster remailer messages:\t\t%5d\n", ccl);
	  fprintf (pp, "Number of Cypherpunk remailer messages:\t\t%5d\n", ccpgp);
	}
      else
	{			/* Mixmaster only */
	  fprintf (pp, "Number of messages remailed in last 24 hours:\t%5d\n", ccm);
	}
      fprintf (pp, "Current message reordering pool size:\t\t%5d\n", POOLSIZE);
      if (ccsent > 0)
	fprintf (pp, "Root-mean-square queuing latency (min):\t\t%5.1f\n",
		 sqrt (cclatent / ccsent));

      close_sendmail (pp, tmp);
    }
}


void
abilities (char *address)
{
  FILE *pp, *fp;
  char abilities[256], line[256], *tmp;

  if ((pp = open_sendmail (MIDDLEMAN, &tmp)) == NULL)
    return;
  fprintf (pp, "Subject: Capabilities of the %s remailer\n", SHORTNAME);
  to (pp, address);		/* Here is the address now */
  fprintf (pp, "\n%s%s\n", remailer_type, VERSION);
  our_abilities (abilities);
  fprintf (pp, "%s %s %s\n\n", SHORTNAME, REMAILERADDR, abilities);
  if ((fp = try_open_mix_file (DESTALLOW, "r")) != NULL)
    {
      fprintf (pp, "This remailer is restricted to mailing to these addresses:\n");
      fprintf (pp, "Mixmaster remailers\n");
      while (fgets (line, sizeof (line), fp) != NULL)
	{
	  if (line[0] == '#' || strlen (line) < 1)
	    continue;		/* skip blank lines */
	  fputs (line, pp);
	}
      fclose (fp);
    }
  else
    {
      /* Report on this remailer's ability to post to news */
      if (strlen (MAILtoNEWS) > 1)
	{
	  fprintf (pp, "This remailer supports posting to news through the\n");
	  fprintf (pp, "%s mail-to-news gateway.\n", MAILtoNEWS);
	  fprintf (pp, "These are not entirely reliable, you should test\n");
	  fprintf (pp, "to be sure that you can reach the groups you want.\n");
	}
      else if (strlen (NEWS) > 1)
	{
	  fprintf (pp, "This remailer supports direct posting to news.\n");
	  fprintf (pp, "Remember that not all news servers support all groups.\n");
	}
      else
	{
	  fprintf (pp, "This remailer does not support posting to news.\n");
	}
    }
  close_sendmail (pp, tmp);
}

void
our_abilities (char *abilities)
{
  abilities[0] = '\0';
  if (MIDDLEMAN)
    strcat (abilities, "M");
#ifdef USE_ZLIB
  strcat (abilities, "C");
#endif
  if (strlen (NEWS) > 1)
    strcat (abilities, "Np");
  else if (strlen (MAILtoNEWS) > 1)
    strcat (abilities, "Nm");
}
