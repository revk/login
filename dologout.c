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
#include "selectdb.h"
#include "envcgi.h"
#include "dologout.h"

const char *dologout(SQL * sqlp, const char *session)
{
   if (!sqlp)
      return "No sql";
   if (!session || !*session)
      return "No session";
   if (!session || !*session)
      return "No session";
   selectdb(sqlp);
#ifdef	CONFIG_DB_SEPARATE_SESSION
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
   int silent = 0;
   int redirect = 0;
   const char *session = NULL;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "redirect", 't', POPT_ARG_NONE, &redirect, 0, "Redirect home/login", NULL },
         { "session", 0, POPT_ARG_STRING, &session, 0, "Session", "session" },
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
   if (!session && *CONFIG_ENV_SESSION)
      session = getenv(CONFIG_ENV_SESSION);
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   const char *fail = dologout(&sql, session);
   sql_close(&sql);
   if (redirect)
      sendredirect(NULL, fail ? : "Logged out");
   else if (fail && !silent)
      printf("%s", fail);
   if (fail)
      return 1;
   return 0;
}
#endif
