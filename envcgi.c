// (c) 1997 Andrews & Arnold Ltd
// Adrian Kennard
// This software is provided under the terms of the GPL v2 or later.
// This software is provided free of charge with a full "Money back" guarantee.
// Use entirely at your own risk. We accept no liability. If you don't like that - don't use it.
// 
// Executes as a CGI script taking GET or POST arguments (key=value pairs)
// and storing in the environment... Then execs the arguments with that
// environment.
//
// Use -dNOFORK to avoid fork and debug error
//
//#define DEBUG

#ifndef SECURITYTAG             // Env/tag for security
#define SECURITYTAG     *       // Default tag
#endif
#ifndef	SECURITYOK              // Variable that indicates security check was OK
#define	SECURITYOK	SECURITY_OK     // Default OK variable
#endif

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <sqllib.h>
#include <syslog.h>
#include <execinfo.h>
#include <openssl/sha.h>
#include "errorwrap.h"

#define MAX 110240
#define MAXF 50

#define Q(x) #x                 // Trick to quote defined fields
#define QUOTE(x) Q(x)

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *q;
char post = 0;
int peek = 0;

#ifdef PLUGIN
int PLUGIN (const char *);

#endif

// read next actual charge from query
int
qget (void)
{
   int r = 0;

   if (post)
   {
      if (!feof (stdin))
         r = fgetc (stdin);
   } else
   {
      if (q && *q)
         r = *q++;
   }
   if (r < ' ')
      r = 0;
   return r;
}

// return unescaped next char in query
// and move on
int
qnext (void)
{
   int c = peek;

   peek = qget ();
   if (c == '+')
      c = ' ';
   else if (c == '%')
   {
      c = 0;
      if (peek >= 'a' && peek <= 'f')
         c = (peek - 'a' + 10) * 16;
      if (peek >= 'A' && peek <= 'F')
         c = (peek - 'A' + 10) * 16;
      if (peek >= '0' && peek <= '9')
         c = (peek - '0') * 16;
      peek = qget ();
      if (peek >= 'a' && peek <= 'f')
         c += (peek - 'a' + 10);
      if (peek >= 'A' && peek <= 'F')
         c += (peek - 'A' + 10);
      if (peek >= '0' && peek <= '9')
         c += (peek - '0');
      peek = qget ();
   }
   return c;
}

struct e_s
{
   struct e_s *next;
   char *name;
   char *value;
} *e = NULL;

void
store (char *var)
{
   char *v = strchr (var, '=');
   if (!v)
   {
      warnx ("Bad env store [%s]", var);
      return;
   }
   char *n = strndup (var, v - var);
   v++;
   if (getenv (n) || !strcmp (n, "HOSTTYPE") || !strcmp (n, "VENDOR") || !strcmp (n, "OSTYPE") || !strcmp (n, "MACHTYPE")
       || !strcmp (n, "SHLVL") || !strcmp (n, "PWD") || !strcmp (n, "LOGNAME") || !strcmp (n, "USER") || !strcmp (n, "GROUP")
       || !strcmp (n, "HOST"))
   {                            // Clash with shell variables.
      if (!n || strcmp (v, n))
         warnx ("Not setting %s=%s / %s", n, v, getenv (n));
      free (n);
      return;
   }
   v = strdup (v);
   struct e_s *q;
   for (q = e; q && strcmp (q->name, n); q = q->next);
   if (q)
   {                            // Multiple
      char *old = q->value;
      if (asprintf (&q->value, "%s\t%s", old, v) < 0)
         errx (1, "malloc");
      free (old);
      free (n);
      free (v);
   } else
   {
      q = malloc (sizeof (*q));
      q->name = n;
      q->value = v;
      q->next = e;
      e = q;
   }
}

void
check_security (const char *security, int age)
{
   if (!security)
      return;                   // Security tags not in use
#ifdef	SECURITYOK
   unsetenv (QUOTE (SECURITYOK));       // default is not OK
#else
   unsetenv (QUOTE (SECURITYTAG) "OK"); // default is not OK
#endif
   // Make a security token
   unsigned char hash[SHA_DIGEST_LENGTH + sizeof (time_t)];
   time_t now = time (0);
   memmove (hash + SHA_DIGEST_LENGTH, &now, sizeof (time_t));
   {
      SHA_CTX c;
      SHA1_Init (&c);
      SHA1_Update (&c, security, strlen (security));
      SHA1_Update (&c, hash + SHA_DIGEST_LENGTH, sizeof (time_t));
      SHA1_Final (hash, &c);
      size_t q;
      for (q = SHA_DIGEST_LENGTH; q < sizeof (hash); q++)
         hash[q] ^= hash[q - SHA_DIGEST_LENGTH];
   }
   char b64[sizeof (hash) * 8 / 6 + 4];
   {                            // Generate base64
      size_t v = 0,
         b = 0,
         i = 0,
         o = 0;
      while (i < sizeof (hash))
      {
         b += 8;
         v = (v << 8) + hash[i++];
         while (b >= 6)
         {
            b -= 6;
            b64[o++] = BASE64[(v >> b) & 0x3F];
         }
      }
      if (b)
      {
         b += 8;
         v <<= 8;
         b -= 6;
         b64[o++] = BASE64[(v >> b) & 0x3F];
         while (b)
         {
            while (b >= 6)
            {
               b -= 6;
               b64[o++] = '=';
            }
            if (b)
               b += 8;
         }
      }
      b64[o] = 0;
   }
   const char *form = getenv (QUOTE (SECURITYTAG));
   setenv (QUOTE (SECURITYTAG), b64, 1);
   if (form)
   {                            // Check security passed in (form or get)
      size_t v = 0,
         b = 0,
         i = 0,
         o = 0;
      while (form[i] && o < sizeof (hash))
      {
         char *q = strchr (BASE64, form[i] == ' ' ? '+' : form[i]);     // Note that + changes to space if used raw in a URL
         if (!q)
            break;
         i++;
         b += 6;
         v = (v << 6) + (q - BASE64);
         while (b >= 8)
         {
            b -= 8;
            hash[o++] = (v >> b);
         }
      }
      while (form[i] == '=')
         i++;
      if (!form[i] && o == sizeof (hash))
      {                         // Looks good, check hash
         time_t when;
         int q;
         for (q = sizeof (hash); q > SHA_DIGEST_LENGTH; q--)
            hash[q - 1] ^= hash[q - SHA_DIGEST_LENGTH - 1];
         memmove (&when, hash + SHA_DIGEST_LENGTH, sizeof (time_t));
         if (when <= now && when + age > now)
         {                      // In sane time frame
            unsigned char check[SHA_DIGEST_LENGTH];
            SHA_CTX c;
            SHA1_Init (&c);
            SHA1_Update (&c, security, strlen (security));
            SHA1_Update (&c, hash + SHA_DIGEST_LENGTH, sizeof (time_t));
            SHA1_Final (check, &c);
            if (!memcmp (check, hash, SHA_DIGEST_LENGTH))
            {
               char temp[10];
               sprintf (temp, "%d", (int) (now - when));
#ifdef	SECURITYOK
               setenv (QUOTE (SECURITYOK), temp, 1);    // Indicate security OK (and how old)
#else
               setenv (QUOTE (SECURITYTAG) "OK", temp, 1);      // Indicate security OK (and how old)
#endif
            } else
               fprintf (stderr, "Bad security hash %s\n", form);
         } else
            fprintf (stderr, "Bad security time %d\n", (int) (now - when));
      } else
         fprintf (stderr, "Bad security string %s\n", form);
   }
}

int
main (int argc, char *argv[])
{
   char *session = NULL;
   // Check args
#ifndef PLUGIN
   if (argc <= 1 && !q)
   {
      fprintf (stderr,
               "envcgi (c) 1997-2014 Andrews & Arnold ltd\n"
               "Arguments are a command to execute and its arguments\n"
               "This is a CGI command shell storing data in the environment\n");
      return -1;
   }
#endif
   int nocookie = 0;
   int nooptions = 0;
   int nopost = 0;
   int nonocache = 0;
   int allfile = 0;
   while (argc > 1)
   {
#ifdef EXTRAARG1
      {
         const char extraarg1[] = "--" QUOTE (EXTRAARG1) "=";
         if (!strncmp (argv[1], extraarg1, sizeof (extraarg1) - 1))
         {
            extern char *EXTRAARG1;
            EXTRAARG1 = argv[1] + sizeof (extraarg1) - 1;
            char *s = strchr (EXTRAARG1, ' ');
            if (s)
            {
               *s++ = 0;
               argv[1] = s;
            } else
               argv++;
         }
      }
#endif
      if (!strncmp (argv[1], "--all-file", 10))
      {
         if (argv[1][10] == ' ')
            argv[1] += 11;
         else
         {
            argc--;
            argv++;
         }
         allfile++;
      } else if (!strncmp (argv[1], "--no-cookie", 11))
      {
         if (argv[1][11] == ' ')
            argv[1] += 12;
         else
         {
            argc--;
            argv++;
         }
         nocookie++;
      } else if (!strncmp (argv[1], "--no-options", 12))
      {
         if (argv[1][12] == ' ')
            argv[1] += 13;
         else
         {
            argc--;
            argv++;
         }
         nooptions++;
      } else if (!strncmp (argv[1], "--no-post", 9))
      {
         if (argv[1][9] == ' ')
            argv[1] += 10;
         else
         {
            argc--;
            argv++;
         }
         nopost++;
      } else if (!strncmp (argv[1], "--no-nocache", 9))
      {
         if (argv[1][9] == ' ')
            argv[1] += 10;
         else
         {
            argc--;
            argv++;
         }
         nonocache++;
      } else
         break;
   }

   {                            // Forwarder logic
      char *i = getenv ("REMOTE_ADDR");
      if (i)
      {
         char *x = getenv ("HTTP_X_FORWARDED_FOR");     // Note envcgi does not allow setting of HTTP_ fields
         if (x && *x)
         {                      // Seems to be relayed
            // Integrity check - how do we know to trust this header - it has to be one of our machines relaying
            // Logic we are using is IPv6 and same /48 for server and relay, then trust forwarded for (works for A&A)
            unsigned char i6[16],
              s6[16];
            char *s = getenv ("SERVER_ADDR");
            if (i && s && inet_pton (AF_INET6, i, i6) > 0 && inet_pton (AF_INET6, s, s6) > 0 && !memcmp (i6, s6, 48 / 8))
            {
               char *c = strrchr (x, ',');      // Last entry is ours, earlier ones could be sent by client
               if (c)
               {
                  x = c + 1;
                  while (isspace (*x))
                     x++;
               }
               setenv ("RELAY_ADDR", i, 1);
               i = x;
               char *h = getenv ("HTTP_X_FORWARDED_HOST");
               if (h)
               {
                  setenv ("HTTP_HOST", h, 1);
                  setenv ("SERVER_NAME", h, 1);
               }
            }
         }
         // Normalise the IP
         unsigned char buf[16];
         char out[40] = "?";
         if (inet_pton (AF_INET, i, buf) > 0)
            inet_ntop (AF_INET, buf, out, sizeof (out));
         else if (inet_pton (AF_INET6, i, buf) > 0)
            inet_ntop (AF_INET6, buf, out, sizeof (out));
         setenv ("REMOTE_ADDR", out, 1);
      }
   }

   q = getenv ("REQUEST_METHOD");
   if (!nooptions && q && !strcasecmp (q, "OPTIONS"))
   {
      printf ("Allow: GET, POST, OPTIONS\r\n\r\n");
      return 0;                 // no content
   }
   if (q && !strcasecmp (q, "POST") && !nopost)
      post = 1;
#ifdef DEBUG
   printf ("Content-Type: text/plain\n\nDebugging\n\n");
#endif

   if (!getenv ("NOHEADERS") && !nonocache)
   {
      printf ("Cache-Control: no-cache\n");
      fflush (stdout);
   }
#ifdef  REFERER                 // Referer checking
   {
      q = getenv ("HTTP_REFERER");
      if (q)
      {
         char *query = getenv ("QUERY_STRING");
         char *method = getenv ("REQUEST_METHOD");
         if ((query && *query) || (method && strcasecmp (method, "get")))
         {                      // Direct link with no query or post is allowed
            while (isalnum (*q))
               q++;
            if (*q == ':')
               q++;
            if (*q == '/')
               q++;
            if (*q == '/')
               q++;
            char *d = q;
            while (isalnum (*q) || *q == '-' || *q == '.')
               q++;
            if (q > d)
            {
               int l = (int) (q - d);
               char *host = getenv ("HTTP_HOST");
               if (l != strlen (host) || strncasecmp (d, host, l))
               {                // External referrer to site, check if allowed
                  const char referer[] = REFERER;
                  int r = sizeof (referer) - 1;
                  if (!(((*referer == '.' && l > r) || (*referer != '.' && l == r)) && !strncasecmp (q - r, referer, r)))
                  {
                     fprintf (stderr, "Referer fail from %s\n", password_ip ());
                     setenv ("HTTP_BAD_REFERER", referer, 1);
                  }
               }
            }
         }
      }
   }
#endif

   // Check method and query
   q = getenv ("CONTENT_LENGTH");
   if (q && !atoi (q))
      post = 0;                 // nothing posted
   q = getenv ("CONTENT_TYPE");
   if (q && !strncasecmp (q, "text/", 5))
      post = 0;                 // handled by app directly
   if (q && !strncasecmp (q, "application/json", 16))
      post = 0;                 // handled by app directly
   if (q && !strncasecmp (q, "application/pgp", 15))
      post = 0;                 // handled by app directly
   int files = 0;
   char fname[MAXF][20];
   FILE *f = NULL;
   if (post && q && !strncasecmp (q, "multipart/form-data; boundary=", 30))
   {                            /* multipart POST */
      char *boundary = q + 30;
      size_t blen = strlen (boundary);
      char buf[1024];
      int var = 0;
      size_t len,
        pos = 0;
      char ev[MAX];
      char name[100];
      char filename[200];
      int dofile = allfile;
      *name = 0;
      *filename = 0;
      while (1)
      {
         size_t eol = 0;
         len = read (fileno (stdin), buf + pos, sizeof (buf) - pos);
         if (len > 0)
            pos += len;
         else if (!pos)
            break;
         if (eol < pos && buf[eol] == '\r')
            eol++;
         if (eol < pos && buf[eol] == '\n')
            eol++;
         while (eol < pos && buf[eol] != '\n' && buf[eol] != '\r')
            eol++;
         if (f || var)
         {                      /* loading file or defining variable */
            if (eol >= 4 + blen && !memcmp (buf, "\r\n--", 4) && !memcmp (buf + 4, boundary, blen))
            {                   /* eof */
               if (f)
                  fclose (f), f = 0;
               else if (var)
               {
                  ev[var] = 0;
                  store (ev);
                  var = 0;
               }
            } else if (f)
            {
               if (write (fileno (f), buf, eol) < 0)
                  errx (1, "write error");
            } else if (var && var + eol < MAX)
               memmove (ev + var, buf, eol), var += eol;
         } else
         {                      /* headers */
            if (eol == 2 && pos >= 4)
            {                   /* start of file */
               eol = 4;         /* take up both lines and start content */
               if (dofile)
               {                /* file */
                  if (files < MAXF && strlen (name) + strlen (filename) + sizeof (fname[0]) + 2 < MAX)
                  {
                     strcpy (fname[files], "/tmp/envcgi.XXXXXX");
                     f = fdopen (mkstemp (fname[files]), "wb");
                     if (f)
                     {
                        sprintf (ev, "%s=%s", name, fname[files]);
                        if (dofile == 2)
                        {       // To word (old style)
                           char *p;
                           for (p = filename; *p; p++)
                              if (*p <= ' ')
                                 *p = '_';      // sanities so second word cleanly
                           sprintf (ev + strlen (ev), "\t%s", filename);
                        }
                        store (ev);
                        if (dofile == 1 && *filename)
                        {       // new way of doing it separate keywords so no need to sanitise
                           sprintf (ev, "%s_FILENAME=%s", name, filename);
                           store (ev);
                        }
                        files++;
                     }
                  }
               } else if (strlen (name) + 2 < MAX)
               {                /* variable */
                  char *i = name,
                     *o = name;
                  while (*i)
                  {
                     if (*i == '.')
                        *o++ = '_';
                     else if (*i != '=' && *i > ' ')
                        *o++ = *i;
                     i++;
                  }
                  *o = 0;
                  strcpy (ev, name);
                  strcat (ev, "=");
                  var = strlen (ev);
               }
               *name = 0;
               *filename = 0;
               dofile = allfile;
            } else if (!strncasecmp (buf, "\r\nContent-Disposition: form-data; name=\"", 40))
            {                   /* extra name and possibly filename */
               size_t q = 40;
               size_t z = 0;
               *filename = 0;
               if (!strncasecmp (buf + q, "FILE:", 5))
                  dofile = 1, q += 5;
               while (q < pos && buf[q] != '"' && z < sizeof (name) - 1)
                  name[z++] = buf[q++];
               name[z] = 0;
               if (q + 13 < pos && !strncasecmp (buf + q, "\"; filename=\"", 13))
               {                /* filename */
                  q += 13;
                  z = 0;
                  while (q < pos && buf[q] && buf[q] != '"' && z < sizeof (filename) - 1)
                  {
                     filename[z] = buf[q];
                     z++;
                     q++;
                  }
                  filename[z] = 0;
                  if (z && !dofile)
                     dofile = 2;
               }
            }
         }
         if (eol < pos)
            memmove (buf, buf + eol, pos - eol);
         pos -= eol;
      }
   } else
   {                            /* normal POST/GET */
      if (!post)
         q = getenv ("QUERY_STRING");
      peek = qget ();
      // Parse the query
      while (peek)
      {
         char ev[MAX];
         size_t e = 0;
         // name
         while (peek && peek != '&' && peek != '=' && e < sizeof (ev) - 5)
         {
            ev[e] = qnext ();
            if (ev[e] == '.')
               ev[e++] = '_';
            else if (ev[e] != '=' && (unsigned char) ev[e] > ' ')
               e++;             // dont allow some chars in the name part
         }
         ev[e] = 0;
         if (e > 2 && ev[e - 1] == 'x' && ev[e - 2] == '_')
         {
            ev[e - 2] = '=';
            ev[e - 1] = 0;
            store (ev);
            ev[e - 2] = '_';
            ev[e - 1] = 'x';
         }
         int bin = 0;
         if (allfile && files < MAXF)
         {
            strcpy (fname[files], "/tmp/envcgi.XXXXXX");
            f = fdopen (mkstemp (fname[files]), "wb");
            if (f)
            {
               sprintf (ev + e, "=%s", fname[files]);
               store (ev);
               files++;
            }
            if (peek == '=')
            {
               qnext ();
               while (peek && peek != '&')
                  fputc (qnext (), f);
            }
            fclose (f);
         } else
         {
            // get value
            if (peek == '=')
            {
               ev[e++] = qnext ();
               // value
               while (peek && peek != '&' && e < sizeof (ev) - 1)
                  if ((unsigned char) (ev[e++] = qnext ()) < ' ')
                     bin = 1;
            } else
               ev[e++] = '=';   // no value
            // store
            ev[e] = 0;          // Null terminate
            store (ev);
            if (bin)
            {                   // Binary data as variable suffixed _hex
               size_t i = 0,
                  o = 0;
               char hex[MAX];
               while (ev[i] != '=' && o < MAX)
                  hex[o++] = ev[i++];
               if (o + 5 < MAX)
               {
                  hex[o++] = '_';
                  hex[o++] = 'h';
                  hex[o++] = 'e';
                  hex[o++] = 'x';
                  hex[o++] = ev[i++];
                  while (o + 3 < MAX && i < e)
                     o += sprintf (hex + o, "%02X", (unsigned char) ev[i++]);
                  hex[o] = 0;
                  store (hex);
               }
            }
         }
#ifdef DEBUG
         printf ("Env '%s'\n", ev);
#endif
         // next
         while (peek == '&')
            qnext ();
      }
   }
#ifdef	NOFORK
   if (files)
#endif
   {                            // Fork, for cleanup or logging
      void done (void)
      {
         while (files)
            unlink (fname[--files]);
      }
    errorwrap (done:done);
   }

   q = getenv ("HTTP_COOKIE");
   if (q)
   {                            // cookies
      while (*q)
      {
         char ev[MAX] = "COOKIE_";
         size_t e = strlen (ev);
         while (*q && *q != '=' && *q != ';' && !isspace (*q) && e < sizeof (ev) - 5)
         {
            ev[e] = *q++;
            if (ev[e] != '=' && ev[e] >= ' ')
               e++;             // dont allow some chars in the name part
         }
         if (*q == '=')
         {
            ev[e++] = *q++;
            while (*q && *q != ';' && e < sizeof (ev) - 1)
            {
               ev[e] = *q++;
               if (ev[e])
                  e++;
            }
         } else
            ev[e] = '=';        // not value
         // store
         ev[e] = 0;
         store (ev);
         if (*q == ';')
            q++;
         while (*q && isspace (*q))
            q++;
#ifdef DEBUG
         printf ("Env '%s'\n", ev);
#endif
      }
   }

#if 0
   if (!session && !nocookie && !getenv ("NOHEADERS"))
      session = password_cookie ("ENVCGI", PASSWORD_UUID, 365 * 86400, NULL);
#endif
   if (session)
      setenv ("HTTP_SESSION", session, 1);

   char *https = getenv ("HTTPS");
   {                            // Helpful environment variables
      char *host = getenv ("HTTP_HOST");
      char *uri = getenv ("SCRIPT_NAME");
      if (host && uri)
      {
         char *temp = malloc (strlen (host) + strlen (uri) + 100),
            *p = temp,
            *q;
         if (https)
            p += sprintf (p, "https://");
         else
            p += sprintf (p, "http://");
         p += sprintf (p, "%s/", host);
         setenv ("ENVCGI_SERVER", temp, 1);
         sprintf (p - 1, "%s", uri);
         q = p;
         while (*q && *q != '?')
            q++;
         if (*q == '?')
            *q-- = 0;
         setenv ("ENVCGI_SCRIPT", temp, 1);
         while (q > p && q[-1] != '/')
            q--;
         *q = 0;
         setenv ("ENVCGI_DIRECTORY", temp, 1);
         if (!post)
         {
            q = getenv ("QUERY_STRING");
            if (q)
               setenv ("ENVCGI_QUERY", q, 1);
         }
      }
   }

   putenv ("PATH=/projects/tools/bin:/usr/local/bin:/bin:/usr/bin:/usr/local/mysql/bin");

   while (e)
   {                            // Store environment
      struct e_s *n = e->next;
      setenv (e->name, e->value, 0);    // Don't overwrite existing entries
      free (e->name);
      free (e->value);
      free (e);
      e = n;
   }

#ifdef DEBUG
   fflush (stdout);
#endif
#ifdef PLUGIN
   if (!(PLUGIN (session)))
#endif
      if (argc > 1)
      {                         /* Execute the arguments */
         int a;
         char *cmd = argv[1];
         char *s = strchr (cmd, ' ');
         if (s)
         {
            *s++ = 0;
            argv[1] = s;
            argv[argc] = 0;
         } else
         {
            for (a = 1; a < argc - 1; a++)
               argv[a] = argv[a + 1];
            argv[argc - 1] = 0;
         }
         s = strrchr (cmd, '/');
         if (s)
            argv[0] = s + 1;
         else
            argv[0] = cmd;
         fflush (stdout);
         execvp (cmd, argv);
      }
   return 0;
}