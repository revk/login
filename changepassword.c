// Change password

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
#include "hashes.h"
#include "logincheck.h"
#include "changepassword.h"

const char *changepassword(SQL * sqlp, const char *session, const char *oldpassword, const char *newpassword)
{
   if (!sqlp)
      return "No sql";
   if (!session || !*session)
      return "No session";
   if (!oldpassword || !*oldpassword)
      return "No old password";
   if (!newpassword || !*newpassword)
      return "No new password";
#ifdef CONFIG_DB_DATABASE
   if (*CONFIG_DB_DATABASE)
      sql_safe_select_db(sqlp, CONFIG_DB_DATABASE);
#else
   const char *v;
   if (*CONFIG_ENV_DB && !(v = getenv(CONFIG_ENV_DB)) || !*v)
      return "No database";
   sql_safe_select_db(sqlp, v);
#endif
   SQL_RES *res = find_session(sqlp, session);
   if (!res)
      return "Not logged in";
   const char *hash = NULL;
   if (*CONFIG_DB_PASSWORD_FIELD)
      hash = sql_col(res, CONFIG_DB_PASSWORD_FIELD);
   char *newhash = password_check(hash, oldpassword);
   if (newhash && newhash != hash)
      free(newhash);            // Update, but we don't need to
   if (!newhash)
   {
      sql_free_result(res);
      return "Wrong password";
   }
   newhash = password_hash(newpassword);
   sql_safe_query_free(sqlp, sql_printf("UPDATE `%#S` SET `%#S`=%#s WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_PASSWORD_FIELD, newhash, CONFIG_DB_USERNAME_FIELD, sql_col(res, CONFIG_DB_USERNAME_FIELD)));
   free(newhash);
   sql_free_result(res);
   return NULL;
}

#ifndef LIB
int main(int argc, const char *argv[])
{
#ifdef  CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
   int silent = 0;
   const char *session = NULL;
   const char *oldpassword = NULL;
   const char *newpassword = NULL;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "session", 0, POPT_ARG_STRING, &session, 0, "Session", "session" },
         { "old-password", 0, POPT_ARG_STRING, &oldpassword, 0, "Old password", "password" },
         { "new-password", 0, POPT_ARG_STRING, &newpassword, 0, "New password", "password" },
         { "debug", 'v', POPT_ARG_NONE, &sqldebug, 0, "Debug", NULL },
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
   if (!session && *CONFIG_ENV_SESSION)
      session = getenv(CONFIG_ENV_SESSION);
   if (!oldpassword && *CONFIG_ENV_OLD_PASSWORD)
      oldpassword = getenv(CONFIG_ENV_OLD_PASSWORD);
   if (!newpassword && *CONFIG_ENV_NEW_PASSWORD)
      newpassword = getenv(CONFIG_ENV_NEW_PASSWORD);
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   const char *fail = changepassword(&sql, session, oldpassword, newpassword);
   if (fail && !silent)
      printf("%s", fail);
   sql_close(&sql);
   if (fail)
      return 1;
   return 0;
}
#endif
