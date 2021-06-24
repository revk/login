// Logged in check

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
#include "dologin.h"
#include "hashes.h"
#include "logincheck.h"

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

SQL_RES *find_session(SQL * sqlp, const char *session)
{
   SQL_RES *found = NULL;
#ifdef CONFIG_DB_SEPARATE_SESSION
   SQL_RES *res = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_SESSION_TABLE, CONFIG_DB_SESSION_FIELD, session));
   if (sql_fetch_row(res))
   {
      const char *uid = sql_col(res, CONFIG_DB_SESSION_USER_LINK);
      if (uid)
      {
         sql_string_t s = { };
         sql_sprintf(&s, "SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USER_ID_FIELD, uid);
         sql_free_result(res);
         res = sql_safe_query_store_s(sqlp, &s);
         if (sql_fetch_row(res))
            found = res;
      }
   }
#else
   SQL_RES *res = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_SESSION_FIELD, session));
   if (sql_fetch_row(res))
      found = res;
#endif
   if (found)
      return found;
   sql_free_result(res);
   return NULL;
}

const char *logincheck(const char *session)
{                               // Do plugin checks after envcgi has set session and environment and so on - return 0 if OK
#ifdef  CONFIG_DB_DEBUG
   sqldebug = 1;
#endif
   // Clearing user ID
   if (*CONFIG_ENV_USER_ID)
      unsetenv(CONFIG_ENV_USER_ID);
   // Check login
   SQL sql;
   sql_cnf_connect(&sql, CONFIG_DB_CONF);
   selectdb(&sql);
   SQL_RES *res = find_session(&sql, session);
   loginenv(res);
   const char *fail = NULL;
   if (res)
      sql_free_result(res);
   else
      fail = "Not logged on";
   if (fail)
   {                            // Failed, check http auth (always done as envcgi controls if allowed or not)
      char *auth = getenv("HTTP_AUTHORIZATION");
      warnx("auth %s", auth);
      if (auth && !strncasecmp(auth, "Basic ", 6))
      {                         // We have basic auth, decode base64 for username and password
         auth += 6;
         while (*auth == ' ')
            auth++;
         if (!getenv("HTTPS"))
            fail = "Must use https - your password may now be compromised";
         else
         {
            auth = strdup(auth);
            size_t v = 0,
                b = 0,
                i = 0,
                o = 0;
            while (auth[i])
            {
               char *q = strchr(BASE64, auth[i] == ' ' ? '+' : auth[i]);        // Note that + changes to space if used raw in a URL
               if (!q)
                  break;
               i++;
               b += 6;
               v = (v << 6) + (q - BASE64);
               while (b >= 8)
               {
                  b -= 8;
                  auth[o++] = (v >> b);
               }
            }
            auth[o] = 0;
            char *pass = strchr(auth, ':');
            if (pass)
            {
               *pass++ = 0;
               warnx("user %s pass %s", auth, pass);
               // Find the user
               SQL_RES *res = sql_safe_query_store_free(&sql, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USERNAME_FIELD, auth));
               if (!sql_fetch_row(res))
                  fail = "Login failed.";
               else
               {
                  const char *hash = NULL;
                  if (*CONFIG_DB_PASSWORD_FIELD)
                     hash = sql_col(res, CONFIG_DB_PASSWORD_FIELD);
                  char *newhash = password_check(hash, pass);
                  if (newhash && newhash != hash)
                  {             // Login OK but hash needs updating
#ifdef CONFIG_PASSWORD_UPDATE
                     warnx("Hash update for user %s", auth);
                     sql_safe_query_free(&sql, sql_printf("UPDATE `%#S` SET `%#S`=%#s WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_PASSWORD_FIELD, newhash, CONFIG_DB_USERNAME_FIELD, auth));
#endif
                     free(newhash);
                  }
                  if (newhash)
                     fail = NULL;       // Yay...
                  else
                     fail = "Login failed";
               }
               sql_free_result(res);
            }
            free(auth);
         }
      }
   }
   sql_close(&sql);
   return fail;
}

void loginenv(SQL_RES * res)
{                               // Fill in login environment variables
   if (!res)
   {                            // Not logged in
      if (*CONFIG_ENV_USER_ID)
         unsetenv(CONFIG_ENV_USER_ID);
      return;
   }
   if (*CONFIG_ENV_USER_ID)
   {
      const char *uid = NULL;
      if (*CONFIG_DB_USER_ID_FIELD)
         uid = sql_col(res, CONFIG_DB_USER_ID_FIELD);
      else
         uid = sql_col(res, CONFIG_DB_USERNAME_FIELD);
      setenv(CONFIG_ENV_USER_ID, uid, 1);
   }



}
