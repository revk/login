// Do a logic

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <sqllib.h>
#include "envcgi.h"
#include "login.h"

const char *login(SQL * sqlp, const char *session, const char *username, const char *password, const char *otp)
{
   const char *v;
   if (!sqlp)
      return "No sql";
   if (otp)
      return "Not doing OTP yet";
   if (!username || !*username)
      return "No username";
   if (!password || !*password)
      return "No password";
   if (!session || !*session)
      return "No session";
#ifdef CONFIG_DB_DATABASE
   if (*CONFIG_DB_DATABASE)
      sql_safe_select_db(sqlp, CONFIG_DB_DATABASE);
#else
   if (*CONFIG_ENV_DB && !(v = getenv(CONFIG_ENV_DB)) || !*v)
      return "No database";
   sql_safe_select_db(sqlp, v);
#endif


   return "not yet";            // OK
}

#ifndef LIB
int main(int argc, const char *argv[])
{
   int silent = 0;
   int redirect = 0;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "redirect", 't', POPT_ARG_NONE, &redirect, 0, "Redirect home/login", NULL },
         { "debug", 'v', POPT_ARG_NONE, &sqldebug, 0, "Debug", NULL },
         POPT_AUTOHELP { }
      };

      optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);

      int c;
      if ((c = poptGetNextOpt(optCon)) < -1)
         errx(1, "%s: %s\n", poptBadOption(optCon, POPT_BADOPTION_NOALIAS), poptStrerror(c));

      if (poptPeekArg(optCon))
      {
         poptPrintUsage(optCon, stderr, 0);
         return -1;
      }
      poptFreeContext(optCon);
   }
   const char *session = NULL;
   if (*CONFIG_ENV_SESSION)
      session = getenv(CONFIG_ENV_SESSION);
   const char *username = NULL;
   if (*CONFIG_ENV_USERNAME)
      username = getenv(CONFIG_ENV_USERNAME);
   const char *password = NULL;
   if (*CONFIG_ENV_PASSWORD)
      password = getenv(CONFIG_ENV_PASSWORD);
   const char *otp = NULL;
#ifdef CONFIV_ENV_OTA
   if (*CONFIG_ENV_OTA)
      otp = getenv(CONFIG_ENV_OTA);
#endif
   const char *v;
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   const char *fail = login(&sql, session, username, password, otp);
   sql_close(&sql);
   if (redirect)sendredirect(NULL,fail);
   else if (fail)
      printf("%s", fail);
   if (fail)
      return 1;
   return 0;
}
#endif
