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
#include "base64.h"
#include "logincheck.h"

#ifdef CONFIG_DB_SEPARATE_SESSION
void sessionenv(SQL_RES * res);
#endif

SQL_RES *find_session(SQL * sqlp, const char *session, int envstore)
{
   SQL_RES *found = NULL;
#ifdef CONFIG_DB_SEPARATE_SESSION
   SQL_RES *res = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_SESSION_TABLE, CONFIG_DB_SESSION_FIELD, session));
   if (sql_fetch_row(res))
   {
      const char *uid = sql_col(res, CONFIG_DB_SESSION_USER_LINK);
      // Update session
      sql_string_t s = { };
      sql_sprintf(&s, "UPDATE `%#S` SET ", CONFIG_DB_SESSION_TABLE);
#ifdef CONFIG_DB_SESSION_EXPIRES
      if (*CONFIG_DB_SESSION_EXPIRES)
      {
         time_t now = time(0);
         time_t expires = sql_time(sql_colz(res, CONFIG_DB_SESSION_EXPIRES));
         if (expires < now)
         {
            warnx("Session for %s expired", uid);
            found = NULL;
            uid = NULL;
         } else
         {
            time_t end = now + 3600 * CONFIG_SESSION_EXPIRY;
            if (expires < end - 1800)
            {

               sql_sprintf(&s, "`%#S`=%#T,", CONFIG_DB_SESSION_EXPIRES, end);
#ifdef CONFIG_DB_CLEANUP_SESSION
               sql_safe_query_free(sqlp, sql_printf("DELETE FROM `%#S` WHERE `%#S`<%#T", CONFIG_DB_SESSION_TABLE, CONFIG_DB_SESSION_EXPIRES, now - 86400));     // cleanup
#endif
            }
         }
      }
#endif
      const char *a = NULL,
          *b = NULL;
#ifdef CONFIG_DB_SESSION_IP
      if (*CONFIG_DB_SESSION_IP && (a = getenv("REMOTE_ADDR")) && (b = sql_colz(res, CONFIG_DB_SESSION_IP)) && strcmp(a, b))
         sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_IP, a);
#endif
#ifdef CONFIG_DB_SESSION_AGENT
      if (*CONFIG_DB_SESSION_AGENT && (a = getenv("HTTP_USER_AGENT")) && (b = sql_colz(res, CONFIG_DB_SESSION_AGENT)) && strcmp(a, b))
         sql_sprintf(&s, "`%#S`=%#s,", CONFIG_DB_SESSION_AGENT, a);
#endif
      if (uid && sql_back_s(&s) == ',')
      {
         sql_sprintf(&s, " WHERE `%#S`=%#s", CONFIG_DB_SESSION_FIELD, session);
         sql_safe_query_s(sqlp, &s);
      } else
         sql_free_s(&s);
      if (envstore)
         sessionenv(res);       // Store session data in environment (before update, but the fields we update are not included
      if (uid)
      {                         // Valid, get user...
         sql_string_t s = { };
         sql_sprintf(&s, "SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_USER_ID_FIELD, uid);
         sql_free_result(res);
         res = sql_safe_query_store_s(sqlp, &s);
         if (sql_fetch_row(res))
            found = res;
      } else
         sql_free_result(res);
   }
#else
   SQL_RES *res = sql_safe_query_store_free(sqlp, sql_printf("SELECT * FROM `%#S` WHERE `%#S`=%#s", CONFIG_DB_USER_TABLE, CONFIG_DB_SESSION_FIELD, session));
   if (sql_fetch_row(res))
      found = res;
#endif
   if (found)
   {
      if (envstore)
         loginenv(found);
      return found;
   }
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
   SQL_RES *res = find_session(&sql, session, 1);
   char nopass = 0;
   const char *fail = NULL;
   if (res)
   {
      if (*CONFIG_DB_PASSWORD_FIELD && !sql_col(res, CONFIG_DB_PASSWORD_FIELD))
         nopass = 1;
      sql_free_result(res);
   } else
      fail = "Not logged on";
   if (fail)
   {                            // Failed, check http auth (always done as envcgi controls if allowed or not)
      char *auth = getenv("HTTP_AUTHORIZATION");
      if (auth && !strncasecmp(auth, "Basic ", 6))
      {                         // We have basic auth, decode base64 for username and password
         auth += 6;
         while (*auth == ' ')
            auth++;
         if (!getenv("HTTPS"))
            fail = "Must use https - your password may now be compromised";
         else
         {
            base64d(&auth, auth);
            char *pass = strchr(auth, ':');
            if (pass)
            {
               *pass++ = 0;
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
                  {
                     fail = NULL;       // Yay...
                     loginenv(res);
                  } else
                     fail = "Login failed";
               }
               sql_free_result(res);
            }
            free(auth);
         }
      }
   }
   sql_close(&sql);
   if (!fail && nopass)
   {
      if (*CONFIG_PAGE_PASSWORD)
      {
         char *url = getenv("SCRIPT_NAME");
         if (strstr(url, CONFIG_PAGE_PASSWORD))
            return NULL;        // This is the password page, so no error
         return CONFIG_PAGE_PASSWORD;   // Go to password page (start with / to do redirect)
      }
      fail = "User has no password";
   }
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
   // load fields
   void load(const char *list, int exclude) {
      for (size_t n = 0; n < res->field_count; n++)
      {                         // Check fields
         const char *name = res->fields[n].name;
         if (*CONFIG_DB_USERNAME_FIELD && !strcasecmp(name, CONFIG_DB_USERNAME_FIELD))
            continue;           // ID field already done
         if (*CONFIG_DB_PASSWORD_FIELD && !strcasecmp(name, CONFIG_DB_PASSWORD_FIELD))
            continue;           // Never password field
         const char *value = res->current_row[n];
         int len = strlen(name);
         const char *l = list;
         while (*l)
         {
            if (!strncasecmp(l, name, len) && (!l[len] || l[len] == ','))
               break;
            while (*l && *l != ',')
               l++;
            while (*l == ',' || *l == ' ')
               l++;
         }
         if (!exclude && !*l)
            continue;
         if (exclude && *l)
            continue;
         char *var;
         if (asprintf(&var, "%s%s", CONFIG_ENV_USER_PREFIX, name) < 0)
            errx(1, "malloc");
#ifdef CONFIG_ENV_USER_UPPER_CASE
         for (char *v = var; *v; v++)
            if (isalpha(*v))
               *v = toupper(*v);
#endif
         if (!value)
            unsetenv(var);
         else
            setenv(var, value, 1);
         free(var);
      }
   }
#ifdef	CONFIG_ENV_USER_LOAD
   load(CONFIG_ENV_USER_FIELD_EXCLUDE, 1);
#else
   load(CONFIG_ENV_USER_FIELD_LIST, 0);
#endif
}

#ifdef CONFIG_DB_SEPARATE_SESSION
void sessionenv(SQL_RES * res)
{                               // Fill in session environment variables
   // load fields
   void load(const char *list, int exclude) {
      for (size_t n = 0; n < res->field_count; n++)
      {                         // Check fields
         const char *name = res->fields[n].name;
         // Check excluded fields
         if (*CONFIG_DB_SESSION_USER_LINK && !strcasecmp(name, CONFIG_DB_SESSION_USER_LINK))
            continue;
         if (*CONFIG_DB_SESSION_IP && !strcasecmp(name, CONFIG_DB_SESSION_IP))
            continue;
         if (*CONFIG_DB_SESSION_AGENT && !strcasecmp(name, CONFIG_DB_SESSION_AGENT))
            continue;
         if (*CONFIG_DB_SESSION_FIELD && !strcasecmp(name, CONFIG_DB_SESSION_FIELD))
            continue;
         if (*CONFIG_DB_SESSION_EXPIRES && !strcasecmp(name, CONFIG_DB_SESSION_EXPIRES))
            continue;
         const char *value = res->current_row[n];
         int len = strlen(name);
         const char *l = list;
         while (*l)
         {
            if (!strncasecmp(l, name, len) && (!l[len] || l[len] == ','))
               break;
            while (*l && *l != ',')
               l++;
            while (*l == ',' || *l == ' ')
               l++;
         }
         if (!exclude && !*l)
            continue;
         if (exclude && *l)
            continue;
         char *var;
         if (asprintf(&var, "%s%s", CONFIG_ENV_SESSION_PREFIX, name) < 0)
            errx(1, "malloc");
#ifdef CONFIG_ENV_SESSION_UPPER_CASE
         for (char *v = var; *v; v++)
            if (isalpha(*v))
               *v = toupper(*v);
#endif
         if (!value)
            unsetenv(var);
         else
            setenv(var, value, 1);
         free(var);
      }
   }
#ifdef	CONFIG_ENV_SESSION_LOAD
   load(CONFIG_ENV_SESSION_FIELD_EXCLUDE, 1);
#else
   load(CONFIG_ENV_SESSION_FIELD_LIST, 0);
#endif
}
#endif
