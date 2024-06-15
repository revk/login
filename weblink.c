// Web link - make and check a web link
#define OPENSSL_API_COMPAT      0x10100000L

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/sha.h>
#include <err.h>
#include "redirect.h"
#include "base64.h"

#define Q(x) #x                 // Trick to quote defined fields
#define QUOTE(x) Q(x)

int
main (int argc, const char *argv[])
{
   const char *makelink = NULL;
   const char *hash = "$QUERY_STRING";
   int checklink = 0;
   int silent = 0;
   int redirect = 0;
   int hours = CONFIG_WEBLINK_AGE;
   poptContext optCon;          // context for parsing command-line options
   {                            // POPT
      const struct poptOption optionsTable[] = {
         {"make", 0, POPT_ARG_STRING, &makelink, 0, "Make a link", "value"},
         {"check", 0, POPT_ARG_NONE, &checklink, 0, "Check link", NULL},
         {"link", 0, POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT, &hash, 0, "Specify the link to check", "value"},
         {"hours", 0, POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &hours, 0, "Number of hours to allow", "N"},
         {"redirect", 'r', POPT_ARG_NONE, &redirect, 0, "Redirect home/login", NULL},
         {"silent", 'q', POPT_ARG_NONE, &silent, 0, "Don't output value", NULL},
         POPT_AUTOHELP {}
      };

      optCon = poptGetContext (NULL, argc, argv, optionsTable, 0);

      int c;
      if ((c = poptGetNextOpt (optCon)) < -1)
         errx (1, "%s: %s\n", poptBadOption (optCon, POPT_BADOPTION_NOALIAS), poptStrerror (c));

      if (poptPeekArg (optCon) || (!makelink && !checklink) || hours <= 0 || hours > 48)
      {
         poptPrintUsage (optCon, stderr, 0);
         return -1;
      }
   }

   // The link is base64 coding of an SHA1 hash followed by a value
   // The hash is made from the time (YYYY-MM-DDTHH) and value and the secret
   // Checking checks a number of hours
   char *makehash (int old, const char *value)
   {                            // Make a hash
      if (!value)
         errx (1, "value?");
      struct tm t;
      time_t now = time (0);
      gmtime_r (&now, &t);
      char *data;
      if (asprintf
          (&data, "%04d-%02d-%02dT%02d%s%s", t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour - old, value, QUOTE (SECRET)) < 0)
         errx (1, "malloc");
      int valuelen = strlen (value);
      unsigned char sha[SHA_DIGEST_LENGTH + valuelen];
      SHA_CTX c;
      SHA1_Init (&c);
      SHA1_Update (&c, data, strlen (data));
      SHA1_Final (sha, &c);
      free (data);
      memcpy (sha + SHA_DIGEST_LENGTH, value, valuelen);
      return base64e (sha, SHA_DIGEST_LENGTH + valuelen);
   }

   if (makelink)
   {                            // make a link and print the link
      if (*makelink == '$')
         makelink = getenv (makelink + 1);
      if (!makelink)
         errx (1, "No value");
      char *hash = makehash (0, makelink);
      if (silent)
         errx (1, "Why silent?");
      else
         printf ("%s", hash);
      free (hash);
      return 0;
   }

   if (checklink)
   {                            // Check a link and print the value
      if (*hash == '$')
      {
         hash = getenv (hash + 1);
         if (hash && *hash == '?')
            hash++;
      }
      if (!hash || !*hash)
         errx (1, "No link");
      unsigned char *block;
      size_t len = base64d (&block, hash);      // Note this adds a null to end so safe to assume a string
      if (len < SHA_DIGEST_LENGTH)
         errx (1, "hash to short");
      char *value = (void *) block + SHA_DIGEST_LENGTH;
      int h = 0;
      while (h < hours)
      {
         char *try = makehash (h, value);
         if (!strcmp (try, hash))
         {                      // Match
            free (try);
            break;
         }
         free (try);
         h++;
      }
      if (h < hours)
      {
         if (redirect)
            sendredirect (NULL, "Link is incorrect or expired, sorry");
         else if (!silent)
            printf ("%s", value);
      }
      free (block);
      if (h < hours)
         return 0;
      return 1;
   }

   poptFreeContext (optCon);
   return -1;
}
