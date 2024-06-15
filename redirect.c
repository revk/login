// Some misc tools

#include "config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>

void
sendredirect (const char *page, const char *fail)
{
   static char havesentredirect = 0;
   if (havesentredirect)
      return;
   const char *v;
   const char *back = NULL;
#ifdef	CONFIG_ENV_BACK
   if (*CONFIG_ENV_BACK)
      back = getenv (CONFIG_ENV_BACK);
#endif
   if (!back && fail)
      back = getenv ("REQUEST_URI");
#ifdef	CONFIG_PAGE_LOGIN
   if (back && !strcmp (back, CONFIG_PAGE_LOGIN))
      back = NULL;
   if (!page)
      page = (fail ? CONFIG_PAGE_LOGIN : back ? : CONFIG_PAGE_HOME);
#endif
#ifdef CONFIG_DB_DEBUG
   warnx ("Redirect to %s er %s", page, fail);
#endif
   printf("Status: 303\r\nLocation: ");
   if (strncasecmp (page, "http://", 7) && strncasecmp (page, "https://", 8))
   {
      if (*CONFIG_ENVCGI_SERVER && (v = getenv (CONFIG_ENVCGI_SERVER)))
         printf ("%s", v);
      else
         printf ("/");
   }
#ifdef  CONFIG_ENV_DB_FROM_URL
   if (*CONFIG_ENV_DB && (v = getenv (CONFIG_ENV_DB)) && *v)
      printf ("%s/", v);
#endif
   v = page;
   if (*v == '/')
      v++;
   printf ("%s", v);
   void add (const char *tag, const char *val)
   {
      if (!tag || !*tag || !val || !*val)
         return;
      printf (v ? "?" : "&");
      v = NULL;
      printf ("%s=", tag);
      while (*val)
      {
         if (*val == ' ')
            putchar ('+');
         else if (*val < ' ' || strchr (";?:@^=+$,/", *val))
            printf ("%%%02X", *val);
         else
            putchar (*val);
         val++;
      }
   }
#ifdef	CONFIG_ENV_BACK
   add (CONFIG_ENV_BACK, back);
#endif
#ifdef	CONFIG_ENV_FAIL
   add (CONFIG_ENV_FAIL, fail);
#endi
   printf ("\r\n\r\n");
   havesentredirect = 1;
   fflush (stdout);
}

#ifndef LIB
int
main (int argc, const char *argv[])
{
   char *url = getenv (CONFIG_ENVCGI_SCRIPT) ? : "/";
   char *fail = NULL;
   if (argc > 1)
      url = (char *) argv[1];
   if (argc > 2)
      fail = (char *) argv[2];
   if (strncasecmp (url, "http://", 7) && strncasecmp (url, "https://", 8)
       && asprintf (&url, "%s%s", getenv (CONFIG_ENVCGI_SERVER) ? : "/", *url == '/' ? url + 1 : url) < 0)
      errx (1, "malloc");
   sendredirect (url, fail);
   return 0;
}
#endif
