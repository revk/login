// Password management tools
// (c) Copyright Adrian Kennard, Andrews & Arnold Ltd 2015-2021

#include "config.h"
#include <stdio.h>
#include <string.h>
#ifndef LIB
#include <popt.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <stdlib.h>
#include <err.h>
#include "password.h"
#include "xkcd936-wordlist.h"

#define	RANDOM	"/dev/urandom"

// Password generation system - creates malloc'd password
// Password is between min and max in length and at least
// specified number of bits of entropy. NULL if cannot
// generate a password (can be avoided by entropy <= max*5)
const char *
password (int min, int max, int entropy)
{
   int r = open (RANDOM, O_RDONLY, 0);
   if (r < 0)
      err (1, "Cannot open " RANDOM);
   char *password = malloc (max + 1);   // space for new password
   if (!password)
      errx (1, "malloc");

   float e;                     // entropy count
   int p;                       // position in new password
   int w;                       // word type (two word lists alternate)
   int attempts = 10;           // How many times to try and do this with words and digits
   // Note, technically we reduce entropy by repeatedly trying to find words that fit... So keep attempts small
   while (attempts--)
   {
      p = w = e = 0;
      while ((p < min || e < entropy) && p < max)
      {                         // lets add words as per XKCD936 (adjective/noun pairs)
         unsigned long long v = 0;
         if (read (r, &v, sizeof (v)) != sizeof (v))
            err (1, "Bad read " RANDOM);
         unsigned long long words = (w ? sizeof (w2) / sizeof (*w2) : sizeof (w1) / sizeof (*w1));
         v %= words;
         const char *word = (w ? w2 : w1)[v];
         int l = strlen (word);
         if (p + l < max)
         {                      // add the word
            e += log2f (words); // count the entropy
            w = 1 - w;
            memmove (password + p, word, l);
            p += l;
         } else
            break;
      }
      if (p < max && e < entropy)
      {                         // try full word list
         p = w = e = 0;
         while ((p < min || e < entropy) && p < max)
         {                      // lets add words as per XKCD936
            unsigned long long v = 0;
            if (read (r, &v, sizeof (v)) != sizeof (v))
               err (1, "Bad read " RANDOM);
            unsigned long long words = sizeof (w0) / sizeof (*w0);
            v %= words;
            const char *word = w0[v];
            int l = strlen (word);
            if (p + l < max)
            {                   // add the word
               e += log2f (words);      // count the entropy
               w = 1 - w;
               memmove (password + p, word, l);
               p += l;
            } else
               break;
         }
      }
      // If still short on entropy, add digits
      while (p < max && e < entropy)
      {                         // try adding digits to make up entropy
         unsigned long long v = 0;
         if (read (r, &v, sizeof (v)) != sizeof (v))
            err (1, "Bad read " RANDOM);
         v %= 10;
         password[p++] = '0' + v;
         e += log2f (10);
      }
      if (p >= min && e >= entropy)
         break;                 // managed it using words
   }
   if (e < entropy && entropy <= max * log2f (32))
   {                            // try again completely different style
      p = e = 0;
      while ((p < min || e < entropy) && p < max)
      {
         unsigned long long v = 0;
         if (read (r, &v, sizeof (v)) != sizeof (v))
            err (1, "Bad read " RANDOM);
         v %= 32;
         password[p++] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"[v]; // Not quite BASE32, this avoids I/O/1/0 clashes, as passwords may need reading and typing
         e += log2f (32);
      }
   }
   if (e < entropy && entropy <= max * log2f (64))
   {                            // try again completely different style
      p = e = 0;
      while ((p < min || e < entropy) && p < max)
      {
         unsigned long long v = 0;
         if (read (r, &v, sizeof (v)) != sizeof (v))
            err (1, "Bad read " RANDOM);
         v %= 64;
         password[p++] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[v]; // Base 64
         e += log2f (64);
      }
   }
   if (e < entropy && entropy <= max * log2f (94))
   {                            // try again completely different style
      p = e = 0;
      while ((p < min || e < entropy) && p < max)
      {
         unsigned long long v = 0;
         if (read (r, &v, sizeof (v)) != sizeof (v))
            err (1, "Bad read " RANDOM);
         v %= 94;
         password[p++] = '!' + v;
         e += log2f (94);
      }
   }
   password[p] = 0;
   close (r);
   if (e < entropy)
   {                            // Failed
      free (password);
      return NULL;
   }
   return password;
}

#ifndef	LIB                     // Command line
int
main (int argc, const char *argv[])
{
   int min = CONFIG_PASSWORD_MIN;
   int max = CONFIG_PASSWORD_MAX;
   int entropy = CONFIG_PASSWORD_ENTROPY;
   poptContext optCon;          // context for parsing command-line options
   {                            // POPT
      const struct poptOption optionsTable[] = {
         {"min", 'm', POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &min, 0, "Min password len", "characters"},
         {"max", 'x', POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &max, 0, "Max password len", "characters"},
         {"entropy", 'e', POPT_ARG_INT | POPT_ARGFLAG_SHOW_DEFAULT, &entropy, 0, "Min entropy", "bits"},
         POPT_AUTOHELP {}
      };

      optCon = poptGetContext (NULL, argc, argv, optionsTable, 0);

      int c;
      if ((c = poptGetNextOpt (optCon)) < -1)
         errx (1, "%s: %s\n", poptBadOption (optCon, POPT_BADOPTION_NOALIAS), poptStrerror (c));

      if (poptPeekArg (optCon))
      {
         poptPrintUsage (optCon, stderr, 0);
         return -1;
      }
   }

   const char *pass = password (min, max, entropy);
   printf ("%s", pass);
   free ((char *) pass);

   poptFreeContext (optCon);
   return 0;
}
#endif
