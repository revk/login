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
#include "selectdb.h"
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
   selectdb(sqlp);
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
   const char *username = NULL;
   const char *oldpassword = NULL;
   const char *newpassword = NULL;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "session", 0, POPT_ARG_STRING, &session, 0, "Session", "session" },
         { "username", 0, POPT_ARG_STRING, &username, 0, "Username (use instead of session and old password)", "username" },
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
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   const char *fail = NULL;
   if (username)
   {                            // Fixed setting password
      if (session)
         errx(1, "Use --username to force a new password, not based on session");
      if (oldpassword)
         errx(1, "User --username to force a new password, not based on old password");
      if (!newpassword)
         errx(1, "Specify the --new-password to set");
      if (!*newpassword)
         fail = "Blank passwords are not supported";
      else
      {
         selectdb(&sql);
         char *newhash = password_hash(newpassword);
         sql_safe_query_free(&sql, sql_printf("UPDATE `%#S` SET `%#S`=%#s WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_PASSWORD_FIELD, newhash, CONFIG_DB_USERNAME_FIELD, username));
         free(newhash);
         if (!sql_affected_rows(&sql))
            fail = "User not found";
      }
   } else
   {                            // Change logged in user
      if (!session && *CONFIG_ENV_SESSION)
         session = getenv(CONFIG_ENV_SESSION);
      if (!oldpassword && *CONFIG_ENV_OLD_PASSWORD)
         oldpassword = getenv(CONFIG_ENV_OLD_PASSWORD);
      if (!newpassword && *CONFIG_ENV_NEW_PASSWORD)
         newpassword = getenv(CONFIG_ENV_NEW_PASSWORD);
      fail = changepassword(&sql, session, oldpassword, newpassword);
   }
   if (fail && !silent)
      printf("%s", fail);
   sql_close(&sql);
   if (fail)
      return 1;
   return 0;
}
#endif
