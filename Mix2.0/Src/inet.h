/* $Id: inet.h,v 1.1 2002/08/28 20:06:49 rabbi Exp $
 * $Log: inet.h,v $
 * Revision 1.1  2002/08/28 20:06:49  rabbi
 * Initial revision
 *
 */

/* Definitions for TCP and UDP client/server programs. */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SERV_TCP_PORT	22069

/* Status codes */
#define SC_INF 0100 /* info */
#define SC_OK 0200  /* OK */
#define SC_CON 0300 /* continue */
#define SC_CLI 0400 /* client error */
#define SC_SER 0500 /* server error */

#define SC_SERVERKEY 0210
