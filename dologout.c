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
#include "dologout.h"

const char *dologout(SQL * sqlp, const char *session)
{
   if (!sqlp)
      return "No sql";
   if (!session || !*session)
      return "No session";
   if (!session || !*session)
      return "No session";
#ifdef CONFIG_DB_DATABASE
   if (*CONFIG_DB_DATABASE)
      sql_safe_select_db(sqlp, CONFIG_DB_DATABASE);
#else
   const char *v;
   if (*CONFIG_ENV_DB && !(v = getenv(CONFIG_ENV_DB)) || !*v)
      return "No database";
   sql_safe_select_db(sqlp, v);
#endif
#ifdef	DB_SEPARATE_SESSION
   sql_safe_query_free(sqlp, sql_printf("DELETE FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_SESSION_TABLE, CONFIG_DB_SESSION_FIELD, session));
#else
   sql_safe_query_free(sqlp, sql_printf("UPDATE `%#S` SET `%#S`=NULL WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_SESSION_FIELD, CONFIG_DB_SESSION_FIELD, session));
#endif
   if (!sql_affected_rows(sqlp))
      return "Was not logged in";
   return NULL;
}

#ifndef LIB
int main(int argc, const char *argv[])
{
#ifdef  CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
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
