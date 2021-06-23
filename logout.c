// Logout

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
#include "logout.h"

const char *logout(SQL * sqlp, const char *session)
{
   const char *v;
   if (!sqlp)
      return "No sql";
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
   return NULL;
}

#ifndef LIB
int main(int argc, const char *argv[])
{
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         POPT_AUTOHELP { }
      };

      optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
      //poptSetOtherOptionHelp (optCon, "");

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

   return 0;
}
#endif
