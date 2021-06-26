// Do a logic

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <popt.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <err.h>
#include <argon2.h>
#include <sqllib.h>
#include "selectdb.h"
#include "redirect.h"
#include "hashes.h"
#include "logincheck.h"
#include "dologin.h"

const char *forcelogin(SQL * sqlp, const char *session, const char *username, SQL_RES * res)
{
   if (!sqlp)
      return "No sql";
   if (!username || !*username)
      return "No username";
   if (!session || !*session)
      return "No session";
   selectdb(sqlp);
   sql_string_t s = { };
#ifdef	CONFIG_DB_SEPARATE_SESSION
   sql_sprintf(&s, "REPLACE INTO `%#S` SET ", CONFIG_DB_SESSION_TABLE);
   const char *uid = username;
   if (*CONFIG_DB_USER_ID_FIELD)
   {
      SQL_RES *r = res;
      if (!r && (!(r = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USERNAME_FIELD, username))) || !sql_fetch_row(r)))
         r = NULL;
      if (!r)
         return "User not found";
      uid = sql_col(r, CONFIG_DB_USER_ID_FIELD);
      if (!res && r)
         sql_free_result(r);
   }
   if (*CONFIG_DB_SESSION_USER_LINK)
      sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_USER_LINK, uid);
#ifdef CONFIG_DB_SESSION_EXPIRES
   if (*CONFIG_DB_SESSION_EXPIRES)
      sql_sprintf(&s, "`%#S`=%#T,", CONFIG_DB_SESSION_EXPIRES, time(0) + 3600 * CONFIG_SESSION_EXPIRY);
#endif
#else
   sql_sprintf(&s, "UPDATE `%#S` SET ", CONFIG_DB_USER_TABLE);
#endif
   if (*CONFIG_DB_SESSION_FIELD)
      sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_FIELD, session);
#ifdef CONFIG_DB_SESSION_TIME
   if (*CONFIG_DB_SESSION_TIME)
      sql_sprintf(&s, "`%#S`=NOW(),", CONFIG_DB_SESSION_TIME);
#endif
   if (sql_back_s(&s) == ',')
   {
#ifndef	CONFIG_DB_SEPARATE_SESSION
      sql_sprintf(&s, " WHERE `%#S`=%#s", CONFIG_DB_USERNAME_FIELD, username);
#endif
      sql_safe_query_s(sqlp, &s);
   } else
      sql_free_s(&s);
   if (!sql_affected_rows(sqlp))
      return "Login failed";
#ifdef  CONFIG_DB_SEPARATE_SESSION
   find_session(sqlp, session, 0);      // Updates fields
#endif
   return NULL;
}

const char *dologin(SQL * sqlp, const char *session, const char *username, const char *password, const char *otp)
{
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
   selectdb(sqlp);
   // Find the user
   SQL_RES *res = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USERNAME_FIELD, username));
   if (!sql_fetch_row(res))
   {
      sql_free_result(res);
      return "Login failed.";
   }
   const char *hash = NULL;
   if (*CONFIG_DB_PASSWORD_FIELD)
      hash = sql_col(res, CONFIG_DB_PASSWORD_FIELD);
   char *newhash = password_check(hash, password);
   if (newhash && newhash != hash)
   {                            // Login OK but hash needs updating
#ifdef CONFIG_PASSWORD_UPDATE
      warnx("Hash update for user %s", username);
      sql_safe_query_free(sqlp, sql_printf("UPDATE `%#S` SET `%#S`=%#s WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_PASSWORD_FIELD, newhash, CONFIG_DB_USERNAME_FIELD, username));
#endif
      free(newhash);
   }
   const char *fail = NULL;
   if (!newhash)
      fail = "Login failed";
   else
      fail = forcelogin(sqlp, session, username, res);
   sql_free_result(res);
   return fail;
}

#ifndef LIB
int main(int argc, const char *argv[])
{
#ifdef	CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
   int silent = 0;
   int redirect = 0;
   int force = 0;
   const char *session = NULL;
   const char *username = NULL;
   const char *password = NULL;
   const char *otp = NULL;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "force", 0, POPT_ARG_NONE, &force, 0, "Force login for username/session", NULL },
         { "redirect", 'r', POPT_ARG_NONE, &redirect, 0, "Redirect home/login", NULL },
         { "session", 0, POPT_ARG_STRING, &session, 0, "Session", "session" },
         { "username", 0, POPT_ARG_STRING, &username, 0, "Username", "username" },
         { "password", 0, POPT_ARG_STRING, &password, 0, "Password", "password" },
#ifdef CONFIV_ENV_OTA
         { "otp", 0, POPT_ARG_STRING, &otp, 0, "One time password", "otp" },
#endif
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
   const char *fail = NULL;
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   sql_transaction(&sql);
#ifdef CONFIV_ENV_OTA
   if (!otp && *CONFIG_ENV_OTA)
      otp = getenv(CONFIG_ENV_OTA);
#endif
   if (!session && *CONFIG_ENV_SESSION)
      session = getenv(CONFIG_ENV_SESSION);
   if (!username && *CONFIG_ENV_USERNAME)
      username = getenv(CONFIG_ENV_USERNAME);
   if (force)
   {                            // Force login
      if (password || otp)
         errx(1, "Force login should not have password");
      fail = forcelogin(&sql, session, username, NULL);
   } else
   {                            // Normal login
      if (!password && *CONFIG_ENV_PASSWORD)
         password = getenv(CONFIG_ENV_PASSWORD);
      fail = dologin(&sql, session, username, password, otp);
   }
   sql_safe_commit(&sql);
   sql_close(&sql);
   if (redirect)
      sendredirect(NULL, fail);
   else if (fail && !silent)
      printf("%s", fail);
   if (fail)
      return 1;
   return 0;
}
#endif
