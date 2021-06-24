// Base 64 coding

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char BASE64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64e(const void *src, size_t len)
{                               // Encodes to base64, malloc'd response
   const unsigned char *hash = src;
   char *dst = NULL;
   size_t outlen = 0;
   FILE *f = open_memstream(&dst, &outlen);
   size_t v = 0,
       b = 0,
       i = 0,
       o = 0;
   while (i < len)
   {
      b += 8;
      v = (v << 8) + hash[i++];
      while (b >= 6)
      {
         b -= 6;
         fputc(BASE64[(v >> b) & 0x3F], f);
      }
   }
   if (b)
   {
      b += 8;
      v <<= 8;
      b -= 6;
      fputc(BASE64[(v >> b) & 0x3F], f);
      while (b)
      {
         while (b >= 6)
         {
            b -= 6;
            fputc('=', f);
         }
         if (b)
            b += 8;
      }
   }
   fputc(0, f);
   fclose(f);
   return dst;
}

size_t base64d(unsigned char **dstp, const char *src)
{                               // Decodes to base64, malloed and stored to dst, returns len
   char *dst = NULL;
   size_t len = 0;
   FILE *f = open_memstream(&dst, &len);
   size_t v = 0,
       b = 0,
       o = 0;
   while (*src)
   {
      char *q = strchr(BASE64, *src == ' ' ? '+' : *src);       // Note that + changes to space if used raw in a URL
      if (!q)
         break;
      src++;
      b += 6;
      v = (v << 6) + (q - BASE64);
      while (b >= 8)
      {
         b -= 8;
         fputc((v >> b), f);
      }
   }
   fputc(0, f);                 // Add null anyway
   fclose(f);
   if (dstp)
      *dstp = dst;
   else if (dst)
      free(dst);
   return len - 1;              // without the null
}
