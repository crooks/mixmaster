/* $Id: mix.h,v 1.2 2002/10/18 22:37:50 rabbi Exp $
 * $Log: mix.h,v $
 * Revision 1.2  2002/10/18 22:37:50  rabbi
 * We prepend the protocol version string to the software version number in
 * the type 2 capstring. This is necessary to allow existing Mixmaster
 * versions to interoperate with future versions of Mixmaster.
 *
 * This isn't strictly necessary with versions 2.x, but I'm making this
 * change for consistency.
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
 * Revision 2.6  1998/05/25  01:20:53  um
 * fixed sign error in check_packetID prototype.
 *
 * Revision 2.5  1998/05/07  23:59:36  um
 * Moved IDEXP and PACKETEXP to mixmaster.conf.
 *
 * Revision 2.4  1998/04/20  14:09:47  um
 * Added T1PGPONLY.
 *
 * Revision 2.3  1998/03/02  16:37:21  um
 * fuction getline() replaces fgets() + chop().
 *
 * Revision 2.2  1998/02/26  02:25:32  um
 * Changes for BSAFEeay.
 *
 *
 * mix.h                  1997-12-08 um
 *      POOLTIMEOUT
 *
 * mix.h                  1997-11-07 um
 *      client.c and server.c prototypes.
 *
 * mix.h                  1997-11-05 um
 *      no default for SPOOL.
 *
 * mix.h                  1997-09-08 um
 *      file name changed because of Windows filename restrictions.
 *
 * mixmaster.h            1997-08-20 JK
 *      prototype for rxmatch().
 *
 * mixmaster.h            1997-08-17 JK
 *
 * mixmaster.h            1997-07-06 um
 *      new definition: DISCLAIMER.
 *
 * mixmaster.h            1997-06-16 um
 *      comments for function prototypes.
 *
 * mixmaster.h            1997-06-12 um
 *      buffer definitions from buffers.h
 *
 * mixmaster.h            1997-05-30 um
 *      new prototypes.
 *
 * mixmaster.h            1996-11-27 um
 *      ANSI prototypes.
 *
 * mixmaster.h        1.2 11/2/95
 *      Some new comments, PASSPHRASE no longer
 *      set here, now set at compile time.
 *      magic strings now declared in main.c
 *
 * mixmaster.h        1.1 4/30/95
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

#ifndef MIX_H
#define MIX_H

#define DISCLAIMER \
"Comments: This message did not originate from the Sender address above.\n" \
"\tIt was remailed automatically by anonymizing remailer software.\n" \
"\tPlease report problems or inappropriate use to the\n" \
"\tremailer administrator at <%s>.\n", COMPLAINTS

#define SECONDSPERDAY 86400

#ifndef PASSPHRASE
#define PASSPHRASE "none"
#endif
#ifndef SPOOL
#define SPOOL ""
#endif

typedef unsigned char byte;

#include "crypto.h"
#include <stdio.h>

#define PACKETSIZE 10236	/* 10240 - 4 (length bytes) */
#define HEADERSIZE 512
#define INNERHEAD  328
#define HOPMAX 20

#define NUM_IV (HOPMAX - 1)
#define BODY_IV (NUM_IV - 1)

#define ARMOREDLINE 40

#define FL_MESSAGE 1
#define FL_OLD     2
#define FL_NEW     4
#define FL_STATS   8
#define FL_LATENCY 16

/* packet types */
#define P_FINAL 1
#define P_PARTIAL 2

#define TSMAGIC "0000" /* magic cookie for timestamp format extension */

#define KEY_VERSION "Version: "
#define KEY_TYPE "Key-Type: "
#define KEY_EXPIRES "Expires: "
#define KEY_VALID "Valid: "
#define CFG_REMAILER "Remailer: "
#define CFG_ADDRESS "Address: "
#define CFG_ABILITIES "Abilities: "
#define CFG_DATE "Date: "

extern char VERSION[];
extern char remailer_type[];
extern char mixmaster_protocol[];
extern char begin_remailer[];
extern char end_remailer[];
extern char begin_signed[];
extern char begin_signature[];
extern char end_signature[];
extern char begin_key[];
extern char end_key[];
extern char end_cfg[];
extern char begin_cfg[];
extern char intermed_hop[];
extern char final_hop[];

extern char mix_dir[];
extern char cur_dir[];
extern char KEYFILE[];
extern char KEYINFO[];
extern char REMAILERADDR[];
extern char ANONADDR[];
extern char ANONNAME[];
extern char REMAILERNAME[];
extern char SHORTNAME[];
extern char COMPLAINTS[];
extern int POOLSIZE;
extern int POOLTIMEOUT;
extern int RATE;
extern char REMAILERLIST[];
extern char IDLOG[];
extern char STATS[];
extern char SECRING[256];
extern char PUBRING[256];
extern char SOURCEBLOCK[256];
extern char DESTALLOW[256];
extern char DESTBLOCK[256];
extern char HDRFILTER[256];
extern char MIXRAND[256];
extern char SENDMAIL[];
extern char NEWS[];
extern char MAILtoNEWS[];
extern char ORGANIZATION[];
extern char TYPE1[];
extern int T1PGPONLY;
extern char REJECT[];
extern char REQUIRE[];
extern char CHAIN[];
extern int DISTANCE;
extern char RELLIST[];
extern char FORWARDTO[];
extern int MINREL;
extern int RELFINAL;
extern int MAXLAT;
extern int MINREMAILERS;
extern int NUMCOPIES;
extern int VERBOSE;
extern int KEYVALIDITY;
extern int KEYOVERLAP;
extern int CREATEKEYS;
extern int MIDDLEMAN;
extern int mmflag;
extern int PACKETEXP;
extern int IDEXP;
extern int ERRSTDOUT;
extern FILE *errlog;

extern RANDOM random_obj;

typedef struct
  {
    byte *message;
    long length;
    long size;
  }

BUFFER;

/* We allocate buffers in units of QUANTA bytes to try to avoid too much
   heap fragmentation */
#define QUANTA	128

enum message_type_enum
  {
    NONE, REMAIL, POST, RETURNADDRESS, PGP
  };
typedef enum message_type_enum message_type;

typedef struct
  {
    char name[80];
    char shortname[80];
    unsigned char key_ID[16];
    char version[80];
    unsigned char IPaddress[16];
    char abilities[256];
    char lorm[30];
    int reliability;
    long latency;
    byte reliable;
  }

REMAILER;

/*** main.c **************************************************************/

/* cdcurdir - return to the original directory (MSDOS). */
void cdcurdir (void);

/* init_mix - initialize Mixmaster

 * Input:       none
 * Returns:     0 on success
 *             -1 if no configuration file available.
 */
int init_mix (void);

/* extract_type2_message - Fetch the next type2 message from the stream fptr.
 *            Place in a temporary file and return its file name in *filename.
 *
 * Input:     stream fptr, pointer for file name
 * Returns:   1 on success; file name in *filename
 *            0 on error
 */
int extract_type2_message (FILE * fptr, char *filename);

/* help_files - process help request

 * Input:    help type, file name of request message
 * Returns:  -
 */
void help_files (int type, char *tmpfile);

/* kind_of_message - determine kind of message

 * Input:     filename
 * Returns:  -1 if error
 *            message type otherwise
 */
int kind_of_message (char *filename);

/* main */
int main (int argc, char *argv[]);

/*** type2.c *************************************************************/
/* merge_packets - merge partial message packets

 * Input:   buffer with message, message ID, packet number, total packets
 * Returns:   0 on success
 *          < 0 on error
 */
int merge_packets (BUFFER * body, byte * messageID, byte packet,
		   byte numpackets);

/* check_packetID - check for ID conflict

 * Input:   packet IS
 * Returns: 1 if no conflict
 *          0 if there is
 */
int check_packetID (byte * ID, unsigned char *timestamp);

/* disclaimer - write disclaimer

 * Input:   output stream
 * Returns: -
 */
void disclaimer (FILE * f);

/* crypt_in_buffer - encrypt/decrypt buffer back to the buffer

 * Input:   key, IV, buffer, encryption flag (1=encrypt, 0=decrypt)
 * Returns: 0 on success
 *          1 on error
 */
int crypt_in_buffer (unsigned char *key, unsigned char *iv,
		     BUFFER * buff, int encrypt);

/* type_2 - process type 2 message

 * Input:   filename
 * Returns: 0 on success
 *         -1 on error
 */
int type_2 (char *tmpfile);

/* type_2 - decrypt type 2 message

 * Input:   message buffer, digest
 * Returns: 0 on success
 *         -1 on error
 */
int type2_dec (BUFFER *b1, byte *digest);


/* send_new_packet - send generated packet

 * Input:   header buffers, body buffer, address, outfile, flag if client
 * Returns: 1 on success
 *         -1 on error
 */
int send_new_packet (BUFFER ** headbuff, BUFFER * bodybuff, char *address,
		     char *outfile, int outfileflag, int client);

/* getmsg - get message header from buffer of file

 * Input:   pointer to char array, length, input file or buffer
 * Returns: - (message header in array)
 */
void getmsg (void *p, int n, FILE * file, byte ** bp, int *kp);

/* send_message - write message to mailXXXXXX

 * Input:     file or buffer
 * Returns:   0 on success
 *          < 0 on error
 */
int send_message (FILE * file, byte * bptr, int k);

/* queue_message - add message from stdin to message pool */
void queue_msg (char *dest);


/*** chain2.c ************************************************************/
/* read_remailer_list - read type2 list and list of reliable remailers

 * Input:   pointer for remailer list
 * Returns: number of remailers
 */
int read_remailer_list (REMAILER * list);

/* build_message - actually makes the message block and sends it

 * Input: stream, destinations, remailer chain, headers,
 *        output files, remailer list, client mode flag
 * Returns: 0 on success
 *         -1 on error
 */
int build_message (FILE * in_ptr, byte numdest,
		   char **destination, int *remailer_chain, byte numsub,
		   char **subject, char *outfile, int outfileflag,
		   REMAILER * remailer_list, int num_remailers,
		   int client);

/* get_chain - get remailer chain from user

 * Input:   remailer list, pointer for chain
 * Returns: -
 */
void get_chain (REMAILER * remailer_list, int num_remailers, int *chain);

/* chain_2 - chaining mode

 * Input:   command line arguments
 * Returns: 0 on success
 *          -1 on error
 */
int chain_2 (int argc, char *argv[]);

/* mm_chain - send middleman message

 * Input:   message file name
 * Returns: -
 */
void mm_chain (const char *filename);

/* select_remailer - remailer number from short name

 * Input:   remailer list, pointer to remailer select string
 * Returns: remailer number on success
 *          print error message and return -1 on error
 */
int select_remailer (REMAILER * remailer_list, int num_remailers, char *sel);

/* scan_remailer_list - get numbers from remailer chain as a string

 * Input:   string, pointer to put chain, remailer list
 * Returns: 0 on success
 *         -1 on error
 */
int scan_remailer_list (char *s, int *chain, REMAILER * remailer_list, int num_remailers);

/* check_abilities - check if abilities match requirements

 * Input:   abilities string, required abilities, abilities to reject
 * Returns: 1 if match
 *          0 otherwise
 */
int check_abilities (char *abilities, char *require, char *reject);

/* rnd_select - randomly select remailers

 * Input:   hop to select, list with remailer chain, remailer list
 * Returns: 0 on success (random remailers as negative in chain)
 *         -1 on error
 */
int rnd_select (int hop, int *chain, REMAILER * remailer_list, int num_remailers);

/* rnd_selectchain - randomly select remailers

 * Input:   list with remailer chain, remailer list
 * Returns: 0 on success (random remailers as negative in chain)
 *         -1 on error
 */
int rnd_selectchain (int *chain, REMAILER * remailer_list, int num_remailers);


/*** type1.c *************************************************************/
/* type_1 - send type1 message to program

 * Input:    filename
 * Returns:  0 on success
 *           > 0 on error
 */
int type_1 (const char *filename);


/*** send.c **************************************************************/
/* read_header - read message packet header
 * Input:    input file, output buffer,
 *           middleman mode flag: -1 = intermediate hop
 *                                 0 = not middleman
 *                                 1 = check if message should be remailed
 *                                 2 = message will be remailed
 * Returns: 0 if no message, 1 on success, -1 if message must be remailed
 */
int read_header (FILE * in, BUFFER * out, int mm);

/* process_pool - process the message pool

 * Input:   -
 * Returns: 0 if no message to send
 *          1 if sent messages
 *         -1 on error
 */
int process_pool (void);

/* process_latent - process latent messages */
void process_latent (void);

/* process_partial - process partial messages */
void process_partial (void);

/* packetID_housekeeping - delete old packet IDs

 * Input:   -
 * Returns: 0 on success
 *         -1 on error
 */
int packetID_housekeeping (void);


/*** stats.c *************************************************************/
/* rebuild_stats - create an empty stats file */
void rebuild_stats (void);

/* stats - update stats; send stats to user

 * Input:   flag; addess or NULL
 * Returns: -
 */
void stats (int flag, char *address);

/* abilities - send abilities to user

 * Input:   addess
 * Returns: -
 */
void abilities (char *address);

/* our_abilities - create abilities string

 * Input:   char array
 * Returns: - (abilities string in array)
 */
void our_abilities (char *abilities);


/*** keymgt.c ************************************************************/
int generate_DH (void);
int get_DH (DH_PARAMS * DH_parms);

/* generate_permanent_key - generate permanent key pair

 * Input:   -
 * Returns: 0 on success
 *         -1 on error
 */
int generate_permanent_key (void);

/* get_pub_key - get public key from pubring.mix

 * Input:   key ID, pointer for RSA key
 * Returns: 0 on success
 *         -1 on error
 *          1 if key not found
 */
int get_pub_key (unsigned char *ID, PUBLIC_KEY * pubkey);

/* get_priv_key - read private key

 * Input:   ID to identify the key, pointer for RSA key
 * Returns: 1 on success
 *         -1 on error
 */
int get_priv_key (unsigned char *ID, PRIVATE_KEY * privkey);

/* update_keys - update key ring

 * Input:   stream with new key certs (NULL or stdin)
 * Returns: -
 */
void update_keys (FILE * keys);

/* next_key - skip to next key

 * Input:   stream
 * Returns: position in stream
 */
long next_key (FILE * key);

/* keyheader - get header from key cert

 * Input:   stream, position, header type, character array for value
 * Returns: 0 on success
 *         -1 on error
 */
int keyheader (FILE * key, long pos, const char *type, char *value);

/* generate_key - generate key pair

 * Input:   string with headers for key cert
 * Returns: 0 on success
 *         -1 on error
 */
int generate_key (const char *header);

/* write_keyfile - create mix.key */
void write_keyfile (void);

/* create_sig - sign buffer

 * Input:   data buffer, buffer for signature
 * Returns: 0 on success
 *         -1 on error
 */
int create_sig ();

/* read_priv_key - read secret key from stream

 * Input:   secring stream, pointer for RSA key, pointer for key ID
 * Returns:  0 on success
 *         < 0 on error
 */
int read_priv_key (FILE * privring, PRIVATE_KEY * privkey,
		   unsigned char *newID);

/* read_pub_key - read public key from stream

 * Input:    pubring stream, pointer for RSA key, pointer for key ID
 * Returns:  0 on success
 *         < 0 on error
 */
int read_pub_key (FILE * pubing, PUBLIC_KEY * pubkey,
		  unsigned char *newID);

/* encode_ID - make printable ID

 * Input:   pointer to char array, ID
 * Returns: - (encoded ID in IDstr)
 */
void encode_ID (unsigned char *IDstr, const unsigned char *ID);

/* print_ID - print ID to file

 * Input:   ID, stream
 * Returns: -
 */
void print_ID (FILE * f, unsigned char *ID);


/* read_key_file - read new keys

 * Input:   stream (stdin)
 * Returns: 0 on success
 */
int read_key_file (FILE * f);

/* expire_pub_keys - delete old public keys

 * Input:
 * Returns:
 */
void expire_pub_keys (void);

/* generate_permanent_key -

 * Input:
 * Returns:
 */
int generate_permanent_key (void);

/* get_permanent_pub_key -

 * Input:
 * Returns:
 */
int get_permanent_pub_key ();

/* get_priv_sig_key -

 * Input:
 * Returns:
 */
int get_priv_sig_key (PRIVATE_KEY * privkey);

/* get_priv_permanent_key -

 * Input:
 * Returns:
 */
int get_priv_permanent_key (PRIVATE_KEY * privkey);

/* get_pub_sig_key -

 * Input:
 * Returns:
 */
int get_pub_sig_key ();

/* verify_sig -

 * Input:
 * Returns:
 */
int verify_sig ();



/*** buffers.c ***********************************************************/
/* add_to_buffer - add data to buffer

 * Input:   buffer, byte array (or NULL), length
 * Returns: - (data added to buffer)
 */
void add_to_buffer (BUFFER * buffer, const byte * mess, int len);

/* str_to_buffer - add null-terminated string to buffer

 * Input:   buffer, string
 * Returns: -
 */
void str_to_buffer (BUFFER * buffer, const char *s);

/* *new_buffer - create new buffer

 * Input:   -
 * Returns: pointer to empty buffer
 */
BUFFER *new_buffer (void);

/* free_buffer - free buffer

 * Input:   buffer
 * Returns: -
 */
void free_buffer (BUFFER * b);

/* clear_buffer - clear buffer

 * Input:   buffer
 * Returns: - (buffer content deleted)
 */
void clear_buffer (BUFFER * b);

/* reset_buffer - set buffer length to 0

 * Input:   pointer to buffer
 * Returns: - (buffer reset)
 */
void reset_buffer (BUFFER * b);

/* write_buffer - write buffer content to file

 * Input:   buffer, stream
 * Returns: number of bytes written
 */
int write_buffer (BUFFER * buff, FILE * f);

/* pad_buffer - pad buffer to fixed yize

 * Input:   buffer, size
 * Returns: - (buffer filled with random bytes)
 */
void pad_buffer (BUFFER * buffer, int len);

/*** random.c ************************************************************/

/* init_our_random - initialize random number generator */
void init_our_random (void);

/* close_our_random - close random number generator */
void close_our_random (void);

/* our_randombytes - get random bytes

 * Input:   pointer to byte array, number of bytes
 * Returns: pointer (bytes filled with random numbers)
 */
byte *our_randombytes (byte * b, int n);

/* our_randombyte - generate random byte

 * Input:   -
 * Returns: random byte
 */
byte our_randombyte (void);

/* random_number - generate random number

 * Input:   range
 * Returns: random number (0 .. n-1)
 */
int random_number (int n);

/* add_to_random - add arbitrary data to randomness pool

 * Input:   pointer to bytes, length
 * Returns: -
 */
void add_to_random (unsigned char *buff, int len);

/* get_noise - get random noise from system */
void get_noise (void);

/* get_randomness - get randomness from system or user */
void get_randomness (void);

/* rnd_time - add system time to RNG

 * Input:   -
 * Returns: interval large enough?
 */
int rnd_time (void);

/* kbd_echo - turn echo on/off

 * Input:   0 = off, 1 = on
 * Returns: 0 on success
 *         -1 on error
 */
int kbd_echo (int on);


/*** sockio.c ************************************************************/

/* writen - write n bytes to socket

 * Input:   file descriptor, pointer to bytes, number of bytes
 * Returns: number of bytes sent
 *          <0 on error
 */
int writen (int fd, char *ptr, int nbytes);

/* readn - read n bytes from socket

 * Input:   file descriptor, pointer to bytes, number of bytes
 * Returns: number of bytes written
 *          <0 on error
 */
int readn (int fd, char *ptr, int nbytes);

/* readline - read line from socket

 * Input:   file descriptor, pointer for line, maximum length
 * Returns: number of characters
 *          -1 on error
 */
int readline (register int fd,
	      register char *ptr,
	      register int maxlen);

/* writestr - write string to socket

 * Input:   file descriptor, pointer to string
 * Returns: 1 if written
 *          0 on error
 */
int writestr (int fd, char *s);

/* writebuf - write buffer to socket

 * Input:   file descriptor, pointer to buffer
 * Returns: 1 if written
 *          0 on error
 */
int writebuf (int fd, BUFFER *b);

/* readbuf - read buffer from socket

 * Input:   file descriptor, pointer to buffer
 * Returns: 1 if read
 *          0 on error
 */
int readbuf (int fd, BUFFER *b);


/*** client.c ************************************************************/

/* read_status - read protocol status line

 * Input:   file descriptor
 * Returns: status (3 digit octal number)
 */
int read_status(int fd);

/* read_message - read message file

 * Input:   file, pointer to buffer, pointer for key ID
 * Returns: 0 on error
 *          1 on success
 */
int read_message (FILE *fptr, BUFFER *msg, unsigned char *ID);

/* remailer_info - check if socket available

 * Input:   remailer address, pointer for port number
 * Returns: 1 if socket supported, port number is set
 *          0 otherwise
 */
int remailer_info (char *address, long unsigned int *portnum);

/* get_greeting - wait for server greeting message

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_greeting (int fd);

/* query_key_ID - ask server to confirm key ID

 * Input:   file descriptor, flag if key needed, key ID
 * Returns: 0 on error
 *          1 on success
 */
int query_key_ID (int fd, int flag, unsigned char *ID);

/* get_server_key - receive the server's public key

 * Input:   file descriptor, key ID
 * Returns: 0 on error
 *          1 on success
 */
int get_server_key (int fd, unsigned char *ID);

/* send_DH_params - sent global DH parameter

 * Input:   file descriptor
 * Returns: 0 on error
 *          1 on success
 */
int send_DH_params (int fd);

/* get_server_keyhalf - wait for server to send public DH value

 * Input:   file descriptor
 * Returns: 0 on error
 *          1 on success
 */
int get_server_keyhalf (int fd);

/* send_keyhalf - generate and send public DH value

 * Input:   file descriptor
 * Returns: 0 on error
 *          1 on success
 */
int send_keyhalf (int fd);

/* sock_send_message - encrypt and send message

 * Input:   file descriptor, message buffer
 * Returns: 0 on error
 *          1 on success
 */
int sock_send_message (int fd, BUFFER *msg);

/* get_server_confirmation - determine if the message was received

 * Input:   file descriptor
 * Returns: 0 on error
 *         >0 on success
 */
int get_server_confirmation (int fd);

/* send_quit - quit transfer

 * Input:   file descriptor
 * Returns: -
 */
void send_quit (int fd);

/* client_protocol - transfer the message

 * Input:   file descriptor, message, flag if key needed, server key ID
 * Returns: 0 on error
 *          1 on success
 */
int client_protocol (int fd, BUFFER *msg, int key_needed, unsigned char *ID);

/* attempt_socket - try to send message via socket

 * Input:   stream with message to send
 * Returns: 0 on failure
 *          1 on success. Leave file ptr after first line
 */
int attempt_socket (FILE * fp);

/*** server.c ************************************************************/

/* send_greeting - send greeting message to client program

 * Input:   file descriptor
 * Returns: 0 on error
 *          1 on success
 */
int send_greeting (int fd);

/* get_key_request - handle key request from the client

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_key_request (int fd);

/* get_DH_params - get the global DH parameter

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_DH_params (int fd);

/* send_server_keyhalf - generate and send public DH value

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int send_server_keyhalf (int fd);

/* get_client_keyhalf - get public DH value from client

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_client_keyhalf (int fd);

/* get_message - get the message from the client
 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_message (int fd);

/* send_fail - report failure to client

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int send_fail (int fd);

/* send_confirmation - confirm receipt

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int send_confirmation (int fd);

/* get_quit - wait for protocol termination

 * Input:   file handle
 * Returns: 0 on error
 *          1 on success
 */
int get_quit (int fd);

/* protocol - socket communication protocol (server part)
 * Input:   file descriptor
 * Output:  0 on failure
 *          1 on success
 */
int protocol (int fd);

/* server_chld - eliminate zombies (signal handler) */
void server_chld(int sig);

/* server_close - close server */
void server_close(int sig);

/* mix_server - server waiting for socket connection

 * Input:   1 for forking server, 2 for single protocol run
 * Returns: >0 on failure
 */
int mix_server (int dofork);

/*** util.c **************************************************************/
/* rxmatch - find regular expression pattern in string (case insensitive)

 * Input:    string, pattern
 * Returns:  0 if not found
 *           1 if found
 */
int rxmatch (const char *string, const char *pattern);

/* tempfile - Create tempfile from root name

 * Input:    Pointer to root name
 * Returns:  pointer to file; name in *rootname
 *            exit on error
 */
FILE *tempfile (char *rootname);
FILE *tempfileb(char *rootname); /* open as binary */

/* file_list - list files matching a given search string

 * Input:     search string, pointer for name list (or NULL)
 * Returns:   number of files; list of pointers to file names in **names
 *            -1 on error
 */
int file_list (const char *search, char **names);

/* open_mix_file - open file in mix_dir

 * Input:      file name, mode
 * Returns:    stream on success
 *             prints error message and returns NULL on error
 */
FILE *open_mix_file (const char *s, const char *attr);

/* try_open_mix_file - try to open file in mix_dir

 * Input:      file name, mode
 * Returns:    stream on success
 *             NULL if can't open file
 */
FILE *try_open_mix_file (const char *s, const char *attr);

/* open_user_file - open a file supplied by the user

 * Input:     file name, mode
 * Returns:   stream on success
 *            prints error message and exits on error
 */
FILE *open_user_file (const char *s, const char *attr);

/* file_to_out - dumps a file to stdout.

 * Input:    filename
 * Returns:  0 on success
 *          -1 on error
 */
int file_to_out (const char *filename);

/* open_sendmail - open file handle to send mail

 * Input:   flag: -2 intermediat, -1 = from anon,
 *                 0 = from remailer, 2 = middleman
 *          pointer for temp filename
 * Returns: file, NULL on error
 */
FILE *open_sendmail (int middleman, char **filename);

/* close_sendmail - close mail file handle

 * Input:   file, temp filename or NULL
 * Returns: -
 */
void close_sendmail (FILE * f, char *filename);

/* mix_lock - lock mix file, wait if locked

 * Input:    name, pointer for lock file
 * Returns:  1 on success
 *           0 on error
 */
int mix_lock (const char *name, FILE ** fptr);

/* mix_unlock - release file lock

 * Input:    name, lock file
 * Returns:  -
 */
void mix_unlock (const char *name, FILE * fptr);

/* tolower_str - convert null-terminated string to lowercase

 * Input:    string
 * Returns:  -
 */
void tolower_str (char *string);

/* add_addr - add address to destination
 * Input:     destination, address, middleman mode flag
 * Returns:   -
 */
void add_addr (BUFFER * dest, char *addr, int *flag);

/* destination_block - handle remailing restrictions

 * Input:     mail destination, middleman mode flag
 * Returns:   0 if address not blocked
 *            1 if blocked
 */
int destination_block (const char *destination, int *flag);

/* destination_allow - handle remailing restrictions

 * Input:     mail destination, middleman mode flag
 * Returns:   0, sets mode flag to 0 if destination not allowed
 */
int destination_allow (const char *destination, int *flag);

/* header_block - filter header lines

 * Input:     mail header line, middleman mode flag
 * Returns:   0 in not blocked
 *            1 if blocked
 */
int header_block (const char *header, int *flag);

/* open_pipe - opens pipe to a programm

 * Input:    command string, mode
 * Returns:  stream on success
 *           prints error message and exits on error
 */
FILE *open_pipe (char *prog, char *attr);

/* close_pipe - close pipe

 * Input:     stream
 * Returns:   0 on success
 *           -1 on error
 */
int close_pipe (FILE * fp);

/* parse_filename - expand file path

 * Input:    pointer for output; pointer to file name
 * Returns:  - (absolute path in *out)
 */
void parse_filename (char *out, const char *in);

/* chop - remove trailing newline

 * Input:    string pointer
 * Returns:  -
 */
void chop (char *s);

/* user_uid - run with user's privileges */
void user_uid (void);

/* mix_uid - run with Mixmaster privileges */
void mix_uid (void);

/* drop_mix_uid - give up Mixmaster privileges */
void drop_mix_uid (void);

/* from - print From line

 * Input:   stream
 * Returns: -
 */
void from (FILE * fp);

/* fromanon - print From line for anonymous messages

 * Input:   stream
 * Returns: -
 */
void fromanon (FILE * fp);

/* to - print To line

 * Input:   stream, address
 * Returns: -
 */
void to (FILE * fp, const char *address);

/* get_from - get From line from file

 * Input:    input file name, pointer to hold address
 * Returns:  - (address in *from, empty string on error)
 */
void get_from (const char *filename, char *from);

/* encode_block - base64 encode block

 * Input:     pointer for encoded block, pointer for block size,
 *            pointer to binary data, length of data
 * Returns:   0
 */
int encode_block (byte *enc, int *enclen, byte *data, int datalen);

/* decode_block - decode base64 encoded block

 * Input:     pointer for binary data, pointer for length of data,
 *            pointer to encoded block, size of encoded block
 * Returns:   0 on success, other values on error
 */
int decode_block (byte *data, int *datalen, byte *enc, int enclen);

/* armor - base64 encode buffer

 * Input:    buffer
 * Returns:  - (buffer armored)
 */
void armor (BUFFER * data);

/* dump_to_file - dumps stdin to a tempfile.

 * Input:    pointer for file name
 * Returns:  1 on success, name of the file in *filename
 *           0 on error
 */
int dump_to_file (char *filename);

/* strileft - compare left part of string to keyword (case insensitive)

 * Input:    string, keyword
 * Returns:  0 if not equal
 *           1 if equal
 */
int strileft (const char *string, const char *keyword);

/* strleft - compare left part of string to keyword (case sensitive)

 * Input:    string, keyword
 * Returns:  0 if not equal
 *           1 if equal
 */
int strleft (const char *string, const char *keyword);

/* streq - compare strings

 * Input:    string1, string2
 * Returns:  0 if not equal
 *           1 if equal
 */
int streq (const char *string1, const char *string2);

/* strifind - find keyword in string (case insensitive)

 * Input:    string, keyword
 * Returns:  0 if not found
 *           1 if found
 */
int strifind (const char *string, const char *keyword);

/* strieq - compare strings, case insensitive

 * Input:    string1, string2
 * Returns:  0 if not equal
 *           1 if equal
 */
int strieq (const char *string1, const char *string2);

/* mailfile - create an output file

 * Input:   -
 * Returns: FILE pointer
 */
FILE *mailfile (void);

/* make_digest - calculate MD5 for buffer

 * Input:    buffer, space for digest
 * Output:   pointer to digest
 */
char *make_digest (BUFFER *b, char *new_digest);

/* getline - read line from file

 * Input:    space for data, maximal size, input file pointer
 * Output:   pointer to data or NULL
 */
char *getline (char *line, int size, FILE *fptr);


/*** compress.c **********************************************************/
/* gzheader - parse gzip header.

 * Input:    byte pointer, length of gzip data
 * Returns:  pointer to start of compressed data
 *           print error msg and return NULL for unknown compression format
 */

/* uncompress_b2file - decompress from memory to file

 * Input:    pointer to compressed data, length, output stream
 * Returns:  0 on success
 *          -1 on error
 */
int uncompress_b2file (byte * b, int length, FILE * out);

/* uncompress_file2file - decompress in from input to output stream

 * Input:    input stream, output stream
 * Returns:  0 on success
 *          -1 on error
 */
int uncompress_file2file (FILE * in, FILE * out);

/* compressed_buf - test if buffer is compressed

 * Input:    buffer, offset for uncompressed header
 * Returns:  0 if uncompressed
 *           1 if compressed
 */
int compressed_buf (BUFFER * b, long offset);

/* uncompress_buf2buf - compress buffer with offset bytes compressed header

 * Input:     input buffer, output buffer, offset
 * Returns:   1 on success
 *            0 if input is not compressed
 *           -1 on error
 */
int uncompress_buf2buf (BUFFER * in, BUFFER * out, long offset);

/* compress_buf2buf - compress buffer, leaving offset bytes uncompressed

 * Input:     input buffer, output buffer, offset
 * Returns:   1 on success
 *           -1 on error
 *            0 if input is compressed
 */
int compress_buf2buf (BUFFER * in, BUFFER * out, long offset);

#endif /* MIX_H */
