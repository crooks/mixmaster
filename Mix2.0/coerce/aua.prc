NEWSGROUPS="`formail -xNewsgroups: -xNewsgroup:` $TO"

# Mangle the From: address.

FROMADDR=`formail -z -xFrom:`
SENDMAILBV=`$SENDMAIL -bv -- "$FROMADDR"`
USERADDR=`echo $SENDMAILBV | sed -e 's/^.*, user //'`

:0
*! SENDMAILBV ?? mailer e?smtp
{ USERADDR="${USERADDR}@${LOCALHOST}" }

AUTHORADDR=`echo $USERADDR | sed  -e 's/@/ <AT> /' -e 's/\./ <DOT> /g'`
USERFROM=`echo $FROMADDR | sed -e "s/$USERADDR/Use-Author-Address-Header@[127.1]/"`

:0 fh
| formail -fb "-IFrom: $USERFROM" \
	"-IAuthor-Address: $AUTHORADDR"

# If binary posts are disabled, pass them to replay.
# Designed for Mixmaster 2.0.4 (and 2.0.5). Change "replay" to the 
# appropriate number if still using 2.0.3.

:0 B
* DISABLEBINARYPOSTS ?? (yes|on)
* -999^0
* 500^.5 NEWSGROUPS ?? binaries
* HB ?? 500^0 ^Content-Transfer-Encoding: base64
* 500^0 ^begin [0-9]+ .*
* 1^1.1 ^M............................................................$
| formail -bf -IFrom: -ITo: -IComments: -IMessage-ID: \
	| $MIXMASTER -f -to $TO -l replay

# Anti-Spam-Bait Recipe summary:
# Obviously somebody has been paying attention. The spam baiting check
# is now sufficiently complicated to warrent an external program for
# testing. It is defined in SPAMBAITTEST. If it returns a non-zero exit
# code, addresses are mangled a la _nospam.

:0 B
* MANGLESPAMBAITS ?? (yes|on)
* ! ? $SPAMBAITTEST
{
	REPLYTO=`formail -z -xReply-To: \
	| sed -e 's/\(\w\+\)@\(\w\)/\1 <AT> \2/g' \
	-e 's/\(\w\+\)\.\(\w\)/\1 <DOT> \2/g'`

:0 fh
*! REPLYTO ?? ^$
| formail -fb "-IReply-To: \"$REPLYTO\" <nobody@$HOSTNAME>" 

:0 fh
| formail -fb "-aX-Comments: apparent spam-bait, addresses mangled"

:0 bf
| sed -e 's/\(\w\+\)@\(\w\)/\1 <AT> \2/g' \
	-e 's/\(\w\+\)\.\(\w\)/\1 <DOT> \2/g'
}

# Add _nospam to the mail2news address for gateways which support it
# (alpha.jpunix.com, anon.lcs.mit.edu, nym.alias.net). It turns out
# nym.alias.net didn't really support this, even though it is the
# same as anon.lcs.mit.edu. This has been fixed. Some people now have
# the habit of sending to multiple gateways, which confused the old
# recipe. This one is more precise.

:0
* ADDNOSPAM ?? (yes|on)
* TO ?? (alpha\.jpunix\.com|anon\.lcs\.mit\.edu|nym\.alias\.net)
{
	GATEWAY=`formail -z -xTo: | \
	sed -e 's/\(mail2news\|m2n\)\([^@]*\)@\(anon.lcs.mit.edu\|nym.alias.net\|alpha.jpunix.com\)/\1_nospam\2@\3/g' \
	-e 's/_nospam_nospam/_nospam/g'`

	:0 fh
	| formail -fb "-ITo: $GATEWAY"
}

# Add [IGNORE] to Subject: for posts to test groups if not already
# present.

SUBJECT=`formail -z -xSubject:`
IGNORESUBJECT="$SUBJECT [IGNORE]"

:0 fh
* ADDIGNORE ?? (yes|on)
* NEWSGROUPS ?? test
* ! SUBJECT ?? ignore
| formail -fb "-ISubject: $IGNORESUBJECT"

# Create USENET Message-ID: based on body.
UMID="<`sed -e '1,/^$/d' | md5sum | sed 's/\([0-9a-f]*\).*/\1@anonymous.poster/'`>"
