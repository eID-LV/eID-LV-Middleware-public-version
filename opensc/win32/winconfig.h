#ifndef _OPENSC_WINCONFIG_H
#define _OPENSC_WINCONFIG_H

#include <stdio.h>
#include <windows.h>
#include <winscard.h>
#include <sys/timeb.h>
#include <sys/stat.h>

#ifndef strcasecmp
#define strcasecmp stricmp
#endif

#ifndef strncasecmp
#define strncasecmp strnicmp
#endif

#ifndef snprintf
#define snprintf _snprintf
#endif

#ifndef vsnprintf
#define vsnprintf _vsnprintf
#endif

#ifndef isatty
#define isatty _isatty
#endif

#ifndef strnicmp
#define strnicmp _strnicmp
#endif

#ifndef stricmp
#define stricmp _stricmp
#endif

#ifndef strdup
#define strdup _strdup
#endif

#ifndef fileno
#define fileno _fileno
#endif

#ifndef mkdir
#define mkdir _mkdir
#endif

#ifndef access
#define access _access
#endif

#ifndef unlink
#define unlink _unlink
#endif

#ifndef putenv
#define putenv _putenv
#endif

#ifndef R_OK
#define R_OK  4		/* test whether readable.  */
#define W_OK  2		/* test whether writable.  */
#define X_OK  1		/* test whether execubale. */
#define F_OK  0		/* test whether exist.  */
#endif

#ifndef S_IRUSR
#define S_IRUSR S_IREAD
#endif

#ifndef S_IWUSR
#define S_IWUSR S_IWRITE
#endif

#define HAVE_IO_H
#define ENABLE_PCSC
#define HAVE_WINSCARD_H
#define DEFAULT_PCSC_PROVIDER "winscard.dll"

#define PKCS11_THREAD_LOCKING

#define SC_PKCS15_PROFILE_DIRECTORY "C:\\Program Files\\Latvia\\profiles"

#define PATH_MAX FILENAME_MAX

#ifndef PACKAGE_VERSION
#define PACKAGE_VERSION "2.1.2"
#endif

#ifndef VERSION
#define VERSION PACKAGE_VERSION
#endif

#ifndef PACKAGE_NAME
#define PACKAGE_NAME "latvia-eid"
#endif

#ifndef OPENSC_FEATURES
#define OPENSC_FEATURES "N/A"
#endif

#ifndef OPENSC_VERSION_MAJOR
#define OPENSC_VERSION_MAJOR 2
#endif

#ifndef OPENSC_VERSION_MINOR
#define OPENSC_VERSION_MINOR 1
#endif

#ifndef OPENSC_VS_FF_COMPANY_NAME
#define OPENSC_VS_FF_COMPANY_NAME  "Latvia eID"
#endif

#ifndef OPENSC_VS_FF_PRODUCT_NAME
#define OPENSC_VS_FF_PRODUCT_NAME  "Latvia eID"
#endif

#ifndef DEFAULT_PKCS11_PROVIDER
#define DEFAULT_PKCS11_PROVIDER "eidlv-pkcs11.dll"
#endif

#ifndef OPENSC_SCM_REVISION
#define OPENSC_SCM_REVISION "No Git revision info available"
#endif

#endif
