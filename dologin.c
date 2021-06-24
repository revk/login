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
#include <sqllib.h>
#include <argon2.h>
#include "envcgi.h"
#include "hashes.h"
#include "dologin.h"

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
#ifdef CONFIG_DB_DATABASE
   if (*CONFIG_DB_DATABASE)
      sql_safe_select_db(sqlp, CONFIG_DB_DATABASE);
#else
   if (*CONFIG_ENV_DB && !(v = getenv(CONFIG_ENV_DB)) || !*v)
      return "No database";
   sql_safe_select_db(sqlp, v);
#endif

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
   if (newhash)
   {                            // Logged in - update/mask session
      sql_string_t s = { };
#ifdef	CONFIG_DB_SEPARATE_SESSION
      sql_sprintf(&s, "REPLACE INTO `%#S` SET ", CONFIG_DB_SESSION_TABLE);
      const char *uid = NULL;
      if (*CONFIG_DB_USER_ID_FIELD)
         uid = sql_col(res, CONFIG_DB_USER_ID_FIELD);
      else
         uid = username;
      if (*CONFIG_DB_SESSION_USER_LINK)
         sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_USER_LINK, uid);
#else
      sql_sprintf(&s, "UPDATE `%#S` SET ", CONFIG_DB_USER_TABLE);
#endif
      if (*CONFIG_DB_SESSION_FIELD)
         sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_FIELD, session);
#ifdef CONFIG_DB_SESSION_TIME
      if (*CONFIG_DB_SESSION_TIME)
         sql_sprintf(&s, "`%#S`=NOW(),", CONFIG_DB_SESSION_TIME);
#endif
#ifdef CONFIG_DB_SESSION_IP
      if (*CONFIG_DB_SESSION_IP)
         sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_IP, getenv("REMOTE_ADDR"));
#endif
      if (sql_back_s(&s) == ',')
      {
#ifndef	CONFIG_DB_SEPARATE_SESSION
         sql_sprintf(&s, " WHERE `%#S`=%#s", CONFIG_DB_USERNAME_FIELD, username);
#endif
         sql_safe_query_s(sqlp, &s);
      } else
         sql_free_s(&s);
   }


   sql_free_result(res);
   if (!newhash)
      return "Login failed";
   return NULL;                 // OK
}

#ifndef LIB
int main(int argc, const char *argv[])
{
#ifdef	CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
   int silent = 0;
   int redirect = 0;
   const char *session = NULL;
   const char *username = NULL;
   const char *password = NULL;
   {                            // POPT
      poptContext optCon;       // context for parsing command-line options
      const struct poptOption optionsTable[] = {
         { "silent", 'q', POPT_ARG_NONE, &silent, 0, "Silent", NULL },
         { "redirect", 't', POPT_ARG_NONE, &redirect, 0, "Redirect home/login", NULL },
         { "session", 0, POPT_ARG_STRING, &session, 0, "Session", "session" },
         { "username", 0, POPT_ARG_STRING, &username, 0, "Username", "username" },
         { "password", 0, POPT_ARG_STRING, &password, 0, "Password", "password" },
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
   if (!username && *CONFIG_ENV_USERNAME)
      username = getenv(CONFIG_ENV_USERNAME);
   if (!password && *CONFIG_ENV_PASSWORD)
      password = getenv(CONFIG_ENV_PASSWORD);
   const char *otp = NULL;
#ifdef CONFIV_ENV_OTA
   if (*CONFIG_ENV_OTA)
      otp = getenv(CONFIG_ENV_OTA);
#endif
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   const char *fail = dologin(&sql, session, username, password, otp);
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
