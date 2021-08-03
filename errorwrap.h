// Simple error reporting block output with timestamp, intended for use from apache/cgi

typedef struct {
   const char *name;            // Script name, default is $SCRIPT_NAME
   const char *ip;              // IP, default is $REMOTE_ADDR
   void (*done)(void);          // Function to run when done
   unsigned char exitzero:1;    // Require clean exit code 0
   unsigned char timestamp:1;	// Timestamps
} errorwrap_t;
void errorwrap_opts(errorwrap_t);
#define	errorwrap(...)	errorwrap_opts((errorwrap_t){__VA_ARGS__})
