// Hash handling
#define OPENSSL_API_COMPAT      0x10100000L

#include "config.h"
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/file.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <argon2.h>
#include "hashes.h"

#define RANDOM  "/dev/urandom"
#define ARGON2_ENC      "$argon2i$v=19$m=12,t=3,p=1$"
#define ARGON2_SET_T    3       // Time cost
#define ARGON2_SET_M    12      // Memory cost
#define ARGON2_SET_P    1       // Parallelism
#define ARGON2_SET_H    32      // Hash len
#define ARGON2_SET_S    15      // Salt len

// Internal password checking functions
#ifdef CONFIG_PASSWORD_SHA256
static char *
password_check_sha256 (const char *hashtext, const char *password)
{                               // Hash assumed to be hex representing 32 SHA256 and arbitrary number of additional bytes of salt
   const char *hash = hashtext;
   if (!strncmp (hash, "SHA256#", 7))
      hash += 7;
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hash[l]))
      l++;
   if ((l & 1) || l < SHA256_DIGEST_LENGTH * 2 || hash[l])
      return NULL;              // Not exact number of bytes, or not all hex, or too few bytes
   // Convert hex to binary
   unsigned char *bin = alloca (l / 2);
   l = 0;
   while (hash[l])
   {
      bin[l / 2] = (((hash[l] & 0xF) + (isalpha (hash[l]) ? 9 : 0)) << 4) + (hash[l + 1] & 0xF) + (isalpha (hash[l + 1]) ? 9 : 0);
      l += 2;
   }
   l /= 2;                      // Count of actual bytes
   // Generate hash to match
   unsigned char check[SHA256_DIGEST_LENGTH];
   SHA256_CTX c;
   SHA256_Init (&c);
   SHA256_Update (&c, password, strlen (password));
   if (l > sizeof (check))
      SHA256_Update (&c, bin + sizeof (check), l - sizeof (check));     // Salt suffix
   SHA256_Final (check, &c);
   // Check it
   if (memcmp (check, bin, sizeof (check)))
      return NULL;              // failed
   return (char *) hashtext;    // OK
}
#endif

#ifdef CONFIG_PASSWORD_SHA1
static char *
password_check_sha1 (const char *hashtext, const char *password)
{                               // Hash assumed to be hex representing 20 SHA1 and arbitrary number of additional bytes of salt
   const char *hash = hashtext;
   if (!strncmp (hash, "SHA1#", 5))
      hash += 5;
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hash[l]))
      l++;
   if ((l & 1) || l < SHA_DIGEST_LENGTH * 2 || hash[l])
      return NULL;              // Not exact number of bytes, or not all hex, or too few bytes
   // Convert hex to binary
   unsigned char *bin = alloca (l / 2);
   l = 0;
   while (hash[l])
   {
      bin[l / 2] = (((hash[l] & 0xF) + (isalpha (hash[l]) ? 9 : 0)) << 4) + (hash[l + 1] & 0xF) + (isalpha (hash[l + 1]) ? 9 : 0);
      l += 2;
   }
   l /= 2;                      // Count of actual bytes
   // Generate hash to match
   unsigned char check[SHA_DIGEST_LENGTH];
   SHA_CTX c;
   SHA1_Init (&c);
   SHA1_Update (&c, password, strlen (password));
   if (l > sizeof (check))
      SHA1_Update (&c, bin + sizeof (check), l - sizeof (check));       // Salt suffix
   SHA1_Final (check, &c);
   // Check it
   if (memcmp (check, bin, sizeof (check)))
      return NULL;              // failed
   return (char *) hashtext;    // OK
}
#endif

#ifdef	CONFIG_PASSWORD_MD5
static char *
password_check_md5 (const char *hashtext, const char *password)
{                               // Hash assumed to be hex representing 16 MD5 and arbitrary number of additional bytes of salt
   const char *hash = hashtext;
   if (!strncmp (hash, "MD5#", 4))
      hash += 4;
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hash[l]))
      l++;
   if ((l & 1) || l < MD5_DIGEST_LENGTH * 2 || hash[l])
      return NULL;              // Not exact number of bytes, or not all hex, or too few bytes
   // Convert hex to binary
   unsigned char *bin = alloca (l / 2);
   l = 0;
   while (hash[l])
   {
      bin[l / 2] = (((hash[l] & 0xF) + (isalpha (hash[l]) ? 9 : 0)) << 4) + (hash[l + 1] & 0xF) + (isalpha (hash[l + 1]) ? 9 : 0);
      l += 2;
   }
   l /= 2;                      // Count of actual bytes
   // Generate hash to match
   unsigned char check[MD5_DIGEST_LENGTH];
   MD5_CTX c;
   MD5_Init (&c);
   MD5_Update (&c, password, strlen (password));
   if (l > sizeof (check))
      MD5_Update (&c, bin + sizeof (check), l - sizeof (check));        // Salt suffix
   MD5_Final (check, &c);
   // Check it
   if (memcmp (check, bin, sizeof (check)))
      return NULL;              // failed
   return (char *) hashtext;    // OK
}
#endif

#ifdef	CONFIG_PASSWORD_MD5
static char *
password_check_md5p (const char *hashtext, const char *password)
{                               // Hash assumed to be hex representing 16 MD5 and arbitrary text prefixing password as salt
   const char *hash = hashtext;
   if (!strncmp (hash, "MD5P#", 5))
      hash += 5;
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hash[l]) && l < MD5_DIGEST_LENGTH * 2)
      l++;
   if ((l & 1) || l < MD5_DIGEST_LENGTH * 2)
      return NULL;              // Not exact number of bytes, or not all hex, or too few bytes
   // Convert hex to binary
   unsigned char *bin = alloca (l / 2);
   l = 0;
   while (hash[l] && l < MD5_DIGEST_LENGTH * 2)
   {
      bin[l / 2] = (((hash[l] & 0xF) + (isalpha (hash[l]) ? 9 : 0)) << 4) + (hash[l + 1] & 0xF) + (isalpha (hash[l + 1]) ? 9 : 0);
      l += 2;
   }
   // Generate hash to match
   unsigned char check[MD5_DIGEST_LENGTH];
   MD5_CTX c;
   MD5_Init (&c);
   if (hash[l])
      MD5_Update (&c, hash + l, strlen (hash + l));     // Prefix salt
   MD5_Update (&c, password, strlen (password));
   MD5_Final (check, &c);
   // Check it
   if (memcmp (check, bin, sizeof (check)))
      return NULL;              // failed
   return (char *) hashtext;    // OK
}
#endif

#ifdef CONFIG_PASSWORD_MYSQL
// New mysql password hash (* and 40 hex)
static char *
password_check_mysql_password (const char *hashtext, const char *password)
{
   const char *hash = hashtext;
   if (*hash++ != '*')
      return NULL;              // Starts *
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hash[l]))
      l++;
   if ((l & 1) || l != SHA_DIGEST_LENGTH * 2 || hash[l])
      return NULL;              // Not exact number of bytes, or not all hex, or too few bytes
   // Convert hex to binary
   unsigned char *bin = alloca (l / 2);
   l = 0;
   while (hash[l])
   {
      bin[l / 2] = (((hash[l] & 0xF) + (isalpha (hash[l]) ? 9 : 0)) << 4) + (hash[l + 1] & 0xF) + (isalpha (hash[l + 1]) ? 9 : 0);
      l += 2;
   }
   l /= 2;                      // Count of actual bytes
   // Generate hash mysql way
   unsigned char check[SHA_DIGEST_LENGTH];
   SHA_CTX c;
   SHA1_Init (&c);
   SHA1_Update (&c, password, strlen (password));
   SHA1_Final (check, &c);
   SHA1_Init (&c);
   SHA1_Update (&c, check, SHA_DIGEST_LENGTH);
   SHA1_Final (check, &c);
   // Check it
   if (memcmp (check, bin, sizeof (check)))
      return NULL;              // failed
   return (char *) hashtext;    // OK
}
#endif

#ifdef CONFIG_PASSWORD_OLDMYSQL
// Old mysql password hash (horrid)
static char *
password_check_mysql_old_password (const char *hashtext, const char *password)
{
   // Check it looks right
   size_t l = 0;
   while (isxdigit (hashtext[l]))
      l++;
   if (l != 16 || hashtext[l])
      return NULL;
   // from my_make_scrambled_password_323
   unsigned long nr = 1345345333L,
      add = 7,
      nr2 = 0x12345671L,
      tmp;
   for (; *password; password++)
   {
      if (*password == ' ' || *password == '\t')
         continue;              /* skip space in password */
      tmp = *(unsigned char *) password;
      nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
      nr2 += (nr2 << 8) ^ nr;
      add += tmp;
   }
   unsigned long long res = ((((unsigned long long) nr & 0x7FFFFFFF) << 32L) | (nr2 & 0x7FFFFFFF));
   unsigned long long pw = strtoull (hashtext, NULL, 16);
   fprintf (stderr, "pw  %016llx\nres %016llx\n", pw, res);
   if (pw != res)
      return NULL;
   return (char *) hashtext;
}
#endif

#ifdef CONFIG_PASSWORD_ARGON2
static char *
password_check_argon2i (const char *hashtext, const char *password)
{
   int e;
   e = argon2i_verify (hashtext, password, strlen (password));
   if (e == ARGON2_VERIFY_MISMATCH)
      return NULL;
   if (e)
      errx (1, "Argon2 error %s", argon2_error_message (e));
   return (char *) hashtext;
}

static char *
password_check_argon2d (const char *hashtext, const char *password)
{
   int e;
   e = argon2d_verify (hashtext, password, strlen (password));
   if (e == ARGON2_VERIFY_MISMATCH)
      return NULL;
   if (e)
      errx (1, "Argon2 error %s", argon2_error_message (e));
   return (char *) hashtext;
}
#endif

static void
delay (int s)
{                               // Forced delay, e.g. bad passwords
#ifdef	CONFIG_PASSWORD_DELAY
   int f = open ("/var/lock/password", O_CREAT, 0444);
   if (f < 0)
      err (1, "Failed to open password mutex /tmp/.password");
   if (flock (f, LOCK_EX) < 0)
      err (1, "Failed to open password mutex /tmp/.password");
   sleep (s);
   if (flock (f, LOCK_UN) < 0)
      err (1, "Failed to unlock password mutex /tmp/.password");
   close (f);
#else
   s = s;
#endif
}

// Password check, returns :-
// NULL         Check failed
// hash         Check passed, hash was fine
// other        Check passed, new hash returned (malloc'd)
char *
password_check (const char *hash, const char *password)
{
   if (!hash || !*hash || !password || !*password)
   {
      delay (2);                // Look the same as bad password
      return NULL;              // not sensible.
   }
   size_t l = strlen (hash);
   // Check current hash
#ifdef ARGON2_FLAG_CLEAR_MEMORY // Bodge as this is present in one version of argon2 and not the other
   size_t argon2_len = argon2_encodedlen (ARGON2_SET_T, ARGON2_SET_M, ARGON2_SET_P, ARGON2_SET_S, ARGON2_SET_H);        // inc null
#else
   size_t argon2_len = argon2_encodedlen (ARGON2_SET_T, ARGON2_SET_M, ARGON2_SET_P, ARGON2_SET_S, ARGON2_SET_H, Argon2_i);      // inc null
#endif

   if (l + 1 == argon2_len && !strncmp (hash, ARGON2_ENC, strlen (ARGON2_ENC)))
   {
      char *ok = password_check_argon2i (hash, password);
      if (!ok)
         delay (2);             // Delay
      return ok;
   }
   // Check for older supported hash functions
   while (1)                    // Just to make exit when found easier
   {
#ifdef CONFIG_PASSWORD_ARGON2
      if (l >= 9 && !strncmp (hash, "$argon2i$", 9) && password_check_argon2i (hash, password)) // Argon 2i
         break;
      if (l >= 9 && !strncmp (hash, "$argon2d$", 9) && password_check_argon2d (hash, password)) // Argon 2d
         break;
#endif
#ifdef CONFIG_PASSWORD_SHA256
      if (l >= SHA256_DIGEST_LENGTH * 2 + 7 && !strncmp (hash, "SHA256#", 7) && password_check_sha256 (hash, password)) // SHA256 (optionally with salt)
         break;
#endif
#ifdef CONFIG_PASSWORD_SHA1
      if (l >= SHA_DIGEST_LENGTH * 2 + 5 && !strncmp (hash, "SHA1#", 5) && password_check_sha1 (hash, password))        // SHA1 (optionally with salt)
         break;
      if (l == SHA_DIGEST_LENGTH * 2 && password_check_sha1 (hash, password))   // older unsalted SHA1 as simple hex
         break;
#endif
#ifdef	CONFIG_PASSWORD_MD5
      if (l >= MD5_DIGEST_LENGTH * 2 + 4 && !strncmp (hash, "MD5#", 4) && password_check_md5 (hash, password))  // MD5 (optionally with salt)
         break;
      if (l >= MD5_DIGEST_LENGTH * 2 + 5 && !strncmp (hash, "MD5P#", 5) && password_check_md5p (hash, password))        // MD5 (optionally with prefixed text salt)
         break;
      if (l == MD5_DIGEST_LENGTH * 2 && password_check_md5 (hash, password))    // older unsalted MD5 as simple hex
         break;
#endif
#ifdef	CONFIG_PASSWORD_MYSQL
      if (l == 41 && password_check_mysql_password (hash, password))    // Newer mysql password()
         break;
#endif
#ifdef	CONFIG_PASSWORD_OLDMYSQL
      if (l == 16 && password_check_mysql_old_password (hash, password))        // Old mysql old_password();
         break;
#endif
      delay (10);               // Delay (longer as still on old password)
      return NULL;              // Not a supported hash function
   }
   // break one of the matching older generators, but needs to be new hash function...
   return password_hash (password);
}

int
password_ishash (const char *hash)
{                               // Check if looks like a hash
   if (!hash || !*hash)
      return 0;                 // Nope
   size_t l = strlen (hash);
   int ishex (const char *p, int l)
   {                            // is it hex?
      while (l && *p && isxdigit (*p))
      {
         p++;
         l--;
      };
      return !l;
   }
#ifdef CONFIG_PASSWORD_ARGON2
   if (l >= 9 && !strncmp (hash, "$argon2i$", 9))
      return 2;                 // Looks like an argon2
#endif
#ifdef CONFIG_PASSWORD_SHA256
   if (l >= SHA256_DIGEST_LENGTH * 2 + 7 && !strncmp (hash, "SHA256#", 7) && ishex (hash + 7, l - 7))
      return 256;
#endif
#ifdef CONFIG_PASSWORD_SHA1
   if (l >= SHA_DIGEST_LENGTH * 2 + 5 && !strncmp (hash, "SHA1#", 5) && ishex (hash + 5, l - 5))
      return 1;
   if (l == SHA_DIGEST_LENGTH * 2 && ishex (hash, l))
      return 1;
#endif
#ifdef CONFIG_PASSWORD_MD5
   if (l >= MD5_DIGEST_LENGTH * 2 + 4 && !strncmp (hash, "MD5#", 4) && ishex (hash + 4, MD5_DIGEST_LENGTH * 2))
      return 5;
   if (l >= MD5_DIGEST_LENGTH * 2 + 5 && !strncmp (hash, "MD5P#", 5)
       && ishex (hash + l - MD5_DIGEST_LENGTH * 2, MD5_DIGEST_LENGTH * 2))
      return 5;
   if (l == MD5_DIGEST_LENGTH * 2 && ishex (hash, l))
      return 5;
#endif
#ifdef CONFIG_PASSWORD_MYSQL
   if (l == 41 && *hash == '*' && ishex (hash + 1, l - 1))
      return 41;
#endif
#ifdef CONFIG_PASSWORD_OLD_MYSQL
   if (l == 16 && ishex (hash, l))
      return 16;
#endif
   return 0;
}

// Generate new password hash using current preferred hash algorithm
// Return NULL is password is not acceptable
// Return malloc'd hash string otherwise
char *
password_hash (const char *password)
{
   if (!password || !*password)
      return NULL;              // Unacceptable
   // Get some salt
   unsigned char salt[ARGON2_SET_S];
   if (sizeof (salt))
   {
      int r = open (RANDOM, O_RDONLY, 0);
      if (r < 0)
         err (1, "Cannot open " RANDOM);
      if (read (r, salt, sizeof (salt)) != sizeof (salt))
         err (1, "Bad read " RANDOM);
      close (r);
   }
#ifndef CONFIG_PASSWORD_ARGON2
#error	Latest is Argon2, so allow it plesae
#endif
   // Generate hash (has own prefix)
#ifdef ARGON2_FLAG_CLEAR_MEMORY // Bodge as this is present in one version of argon2 and not the other
   size_t l = argon2_encodedlen (ARGON2_SET_T, ARGON2_SET_M, ARGON2_SET_P, ARGON2_SET_S, ARGON2_SET_H); // inc null
#else
   size_t l = argon2_encodedlen (ARGON2_SET_T, ARGON2_SET_M, ARGON2_SET_P, ARGON2_SET_S, ARGON2_SET_H, Argon2_i);       // inc null
#endif
   char *hash = malloc (l);
   if (!hash)
      errx (1, "malloc");
   int e = argon2i_hash_encoded (ARGON2_SET_T, ARGON2_SET_M, ARGON2_SET_P, password, strlen (password), salt, ARGON2_SET_S,
                                 ARGON2_SET_H, hash, l);
   if (e)
      errx (1, "Argon2 error %s", argon2_error_message (e));
   return hash;
}
