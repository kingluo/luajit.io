local ffi = require("ffi")

ffi.cdef[[
void openlog(const char *ident, int option, int facility);
void syslog(int priority, const char *format, ...);
void closelog(void);

static const int LOG_PID         = 0x01;    /* log the pid with each message */
static const int LOG_CONS        = 0x02;    /* log on the console if errors in sending */
static const int LOG_ODELAY      = 0x04;    /* delay open until first syslog() (default) */
static const int LOG_NDELAY      = 0x08;    /* don't delay open */
static const int LOG_NOWAIT      = 0x10;    /* don't wait for console forks: DEPRECATED */
static const int LOG_PERROR      = 0x20;    /* log to stderr as well */

static const int LOG_KERN        = (0<<3);  /* kernel messages */
static const int LOG_USER        = (1<<3);  /* random user-level messages */
static const int LOG_MAIL        = (2<<3);  /* mail system */
static const int LOG_DAEMON      = (3<<3);  /* system daemons */
static const int LOG_AUTH        = (4<<3);  /* security/authorization messages */
static const int LOG_SYSLOG      = (5<<3);  /* messages generated internally by syslogd */
static const int LOG_LPR         = (6<<3);  /* line printer subsystem */
static const int LOG_NEWS        = (7<<3);  /* network news subsystem */
static const int LOG_UUCP        = (8<<3);  /* UUCP subsystem */
static const int LOG_CRON        = (9<<3);  /* clock daemon */
static const int LOG_AUTHPRIV    = (10<<3); /* security/authorization messages (private) */
static const int LOG_FTP         = (11<<3); /* ftp daemon */

static const int LOG_EMERG       = 0;       /* system is unusable */
static const int LOG_ALERT       = 1;       /* action must be taken immediately */
static const int LOG_CRIT        = 2;       /* critical conditions */
static const int LOG_ERR         = 3;       /* error conditions */
static const int LOG_WARNING     = 4;       /* warning conditions */
static const int LOG_NOTICE      = 5;       /* normal but significant condition */
static const int LOG_INFO        = 6;       /* informational */
static const int LOG_DEBUG       = 7;       /* debug-level messages */
]]
