/*
 * minidriver.c: OpenSC minidriver
 *
 * Copyright (C) 2009,2010 francois.leblanc@cev-sa.com
 * Copyright (C) 2015 vincent.letoux@mysmartlogon.com
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

 /*
  * This module requires "cardmod.h" from CNG SDK or platform SDK to build.
  */

#include "config.h"
#ifdef ENABLE_MINIDRIVER

#ifdef _MANAGED
#pragma managed(push, off)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <windows.h>
#include <WtsApi32.h>
#include <Commctrl.h>
#include <timeapi.h>
#include "cardmod.h"
#include "resource.h"

#include "common/compat_strlcpy.h"
#include "libopensc/asn1.h"
#include "libopensc/cardctl.h"
#include "libopensc/opensc.h"
#include "libopensc/pkcs15.h"
#include "libopensc/log.h"
#include "libopensc/internal.h"
#include "libopensc/aux-data.h"
#include "ui/notify.h"
#include "ui/strings.h"
#include "ui/wchar_from_char_str.h"
#include "pkcs15init/pkcs15-init.h"

#ifdef ENABLE_OPENSSL
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/pem.h>
#endif
#endif

#if defined(__MINGW32__)
#include "cardmod-mingw-compat.h"
#endif

#include "cardmod.h"

  /* store the instance given at DllMain when attached to access internal resources */
HINSTANCE g_inst;

#define MD_MINIMUM_VERSION_SUPPORTED 6
#define MD_CURRENT_VERSION_SUPPORTED 7

#define NULLSTR(a) (a == NULL ? "<NULL>" : a)
#define NULLWSTR(a) (a == NULL ? L"<NULL>" : a)

#define MD_MAX_KEY_CONTAINERS 12
#define MD_CARDID_SIZE 16

#define MD_ROLE_USER_SIGN (ROLE_ADMIN + 1)
/*
 * must be higher than MD_ROLE_USER_SIGN and
 * less than or equal MAX_PINS
 */
#define MD_MAX_PINS MAX_PINS

#define MD_CARDCF_LENGTH	(sizeof(CARD_CACHE_FILE_FORMAT))

#define MD_KEY_USAGE_KEYEXCHANGE		\
	SC_PKCS15INIT_X509_KEY_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DATA_ENCIPHERMENT	| \
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE
#define MD_KEY_USAGE_KEYEXCHANGE_ECC		\
	SC_PKCS15INIT_X509_KEY_AGREEMENT| \
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE
#define MD_KEY_USAGE_SIGNATURE			\
	SC_PKCS15INIT_X509_DIGITAL_SIGNATURE	| \
	SC_PKCS15INIT_X509_KEY_CERT_SIGN	| \
	SC_PKCS15INIT_X509_CRL_SIGN
#define MD_KEY_ACCESS				\
	SC_PKCS15_PRKEY_ACCESS_SENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_ALWAYSSENSITIVE	| \
	SC_PKCS15_PRKEY_ACCESS_NEVEREXTRACTABLE	| \
	SC_PKCS15_PRKEY_ACCESS_LOCAL

 /* copied from pkcs15-cardos.c */
#define USAGE_ANY_SIGN		(SC_PKCS15_PRKEY_USAGE_SIGN | SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_ANY_DECIPHER	(SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP)
#define USAGE_ANY_AGREEMENT (SC_PKCS15_PRKEY_USAGE_DERIVE)

/* if use of internal-winscard.h */
#ifndef SCARD_E_INVALID_PARAMETER
#define SCARD_E_INVALID_PARAMETER	0x80100004L
#define SCARD_E_UNSUPPORTED_FEATURE	0x80100022L
#define SCARD_E_NO_MEMORY		0x80100006L
#define SCARD_W_WRONG_CHV		0x8010006BL
#define SCARD_E_FILE_NOT_FOUND		0x80100024L
#define SCARD_E_UNKNOWN_CARD		0x8010000DL
#define SCARD_F_UNKNOWN_ERROR		0x80100014L
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256                 12
#endif

#ifndef ALG_SID_SHA_384
#define ALG_SID_SHA_384                 13
#endif

#ifndef ALG_SID_SHA_512
#define ALG_SID_SHA_512                 14
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef CALG_SHA_384
#define CALG_SHA_384            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_384)
#endif

#ifndef CALG_SHA_512
#define CALG_SHA_512            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_512)
#endif

 /* defined twice: in versioninfo-minidriver.rc.in and in minidriver.c */
#define IDI_SMARTCARD   102

#define SUBKEY_ENABLE_CANCEL "Software\\Latvia eID\\OpenSC\\md_pinpad_dlg_enable_cancel"

/* magic to determine previous pinpad authentication */
#define MAGIC_SESSION_PIN "eidLvMinidriver"

#define TLS1_0_PROTOCOL_VERSION 0x0301
#define TLS1_1_PROTOCOL_VERSION 0x0302
#define TLS1_2_PROTOCOL_VERSION 0x0303
#define TLS_DERIVE_KEY_SIZE 48

struct md_directory {
	unsigned char name[9];

	CARD_DIRECTORY_ACCESS_CONDITION acl;

	struct md_file *files;
	struct md_directory *subdirs;

	struct md_directory *next;
};

struct md_file {
	unsigned char name[9];

	CARD_FILE_ACCESS_CONDITION acl;

	unsigned char *blob;
	size_t size;

	struct md_file *next;
};

struct md_pkcs15_container {
	int index;
	struct sc_pkcs15_id id;
	struct sc_pkcs15_card *p15card;
	char guid[MAX_CONTAINER_NAME_LEN + 1];
	unsigned char flags;
	size_t size_key_exchange, size_sign;

	struct sc_pkcs15_object *cert_obj, *prkey_obj, *pubkey_obj;
	// BOOL guid_overwrite;
	BOOL non_repudiation;
	BOOL key_derivation;
};

struct md_dh_agreement {
	DWORD dwSize;
	PBYTE pbAgreement;
};

struct md_guid_conversion {
	CHAR szOpenSCGuid[MAX_CONTAINER_NAME_LEN + 1];
	CHAR szWindowsGuid[MAX_CONTAINER_NAME_LEN + 1];
};

#define MD_MAX_CONVERSIONS 50
struct md_guid_conversion md_static_conversions[MD_MAX_CONVERSIONS] = { 0 };

typedef struct
{
	struct sc_pkcs15_card *p15card;	
} md_fw_data;

typedef struct _VENDOR_SPECIFIC
{
	BOOL initialized;


	struct sc_context *ctx;
	struct sc_reader *reader;
	struct sc_card *card;
	struct sc_pkcs15_object *pin_objs[MD_MAX_PINS];
	struct md_pkcs15_container p15_containers[MD_MAX_KEY_CONTAINERS];
	md_fw_data* fws_data[4];

	struct md_directory root;

	SCARDCONTEXT hSCardCtx;
	SCARDHANDLE hScard;

	ULONGLONG lastChecked;

	DWORD dwEventsCounter; /* this is the highest 16-bit value of SCARD_READERSTATE.dwEventState
									* that indicated the number removal/insertion that occured since reader
									* is connected to the system */

	/* These will be used in CardAuthenticateEx to display a dialog box when doing
	 * external PIN verification.
	 */
	HWND hwndParent;
	LPWSTR wszPinContext;
	/* these will be used to store intermediate dh agreements results */
	struct md_dh_agreement* dh_agreements;
	BYTE allocatedAgreements;

	CRITICAL_SECTION hScard_lock;
} VENDOR_SPECIFIC;

static DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror,
	DWORD dwDefaulCode);
static DWORD associate_card(PCARD_DATA pCardData);
static void disassociate_card(PCARD_DATA pCardData);
static DWORD md_pkcs15_delete_object(PCARD_DATA pCardData, struct sc_pkcs15_object *obj);
static DWORD md_fs_init(PCARD_DATA pCardData);
static void md_fs_finalize(PCARD_DATA pCardData);

typedef LONG (WINAPI *SCardGetAttribFn)(
    __in    SCARDHANDLE hCard,
    __in    DWORD dwAttrId,
    __out_bcount_opt(*pcbAttrLen) LPBYTE pbAttr,
    __inout LPDWORD pcbAttrLen);

typedef LONG (WINAPI *SCardGetStatusChangeFn)(
    __in    SCARDCONTEXT hContext,
    __in    DWORD dwTimeout,
    __inout LPSCARD_READERSTATEA rgReaderStates,
    __in    DWORD cReaders);

typedef LONG (WINAPI *SCardDisconnectFn)(
    __in    SCARDHANDLE hCard,
    __in    DWORD dwDisposition);

typedef LONG(WINAPI *SCardBeginTransactionFn)(
	_In_    SCARDHANDLE hCard);

typedef LONG(WINAPI *SCardEndTransactionFn)(
	_In_    SCARDHANDLE hCard,
	_In_    DWORD dwDisposition);

static SCardGetAttribFn SCardGetAttribPtr = NULL;
static SCardGetStatusChangeFn SCardGetStatusChangePtr = NULL;
static SCardDisconnectFn SCardDisconnectPtr = NULL;
static SCardBeginTransactionFn SCardBeginTransactionPtr = NULL;
static SCardEndTransactionFn SCardEndTransactionPtr = NULL;

static char exefilePath[MAX_PATH] = {0};
static char logfilePath[MAX_PATH] = {0};
static BOOL g_bDllDetached = FALSE;
static BOOL g_bLogEnabled = FALSE;

#ifdef _DEBUG
LONG WINAPI SCardBeginTransactionDummy(
	_In_    SCARDHANDLE hCard)
{
	return SCARD_S_SUCCESS;
}

LONG WINAPI SCardEndTransactionDummy(
	_In_    SCARDHANDLE hCard,
	_In_    DWORD dwDisposition)
{
	return SCARD_S_SUCCESS;
}
#endif


#if defined(__GNUC__)
static void logprintf(PCARD_DATA pCardData, int level, const char* format, ...)
__attribute__((format(SC_PRINTF_FORMAT, 3, 4)));
#endif

static void logprintf(PCARD_DATA pCardData, int level, _Printf_format_string_ const char* format, ...)
{
	va_list arg;
	if (logfilePath[0])
	{
		FILE* f = fopen(logfilePath,"a+");
		if (f != NULL) {
			va_start(arg, format);
			vfprintf(f, format, arg);
			va_end(arg);
			//fflush(f);
			fclose(f);
		}
	}
}


static void loghex(PCARD_DATA pCardData, int level, PBYTE data, size_t len)
{
	char line[74];
	char *c;
	unsigned int i, a;
	unsigned char * p;

   if (!g_bLogEnabled)
      return;

	logprintf(pCardData, level, "--- %p:%d\n", data, len);

	if (data == NULL || len <= 0) return;

	p = data;
	c = line;
	i = 0;
	a = 0;
	memset(line, 0, sizeof(line));

	while(i < len) {
		sprintf_s(c, sizeof(line)-(size_t)(c-line),"%02X", *p);
		p++;
		c += 2;
		i++;
		if (i%32 == 0) {
			logprintf(pCardData, level, " %04X  %s\n", a, line);
			a +=32;
			memset(line, 0, sizeof(line));
			c = line;
		} else {
			if (i%4 == 0) *(c++) = ' ', *c = 0;
			if (i%16 == 0) *(c++) = ' ', *c = 0;
		}
	}
	if (i%32 != 0)
		logprintf(pCardData, level, " %04X  %s\n", a, line);
}

static void print_werror(PCARD_DATA pCardData, PSTR str)
{
	void *buf;
   if (!g_bLogEnabled)
      return;
	FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, GetLastError(), 0, (LPSTR) &buf, 0, NULL);

	logprintf(pCardData, 0, "%s%s\n", str, (PSTR) buf);
	LocalFree(buf);
}

void trace (const char* format, ...)
{
	va_list arg;
	if (logfilePath[0])
	{
		FILE* f = fopen(logfilePath,"a+");
		if (f != NULL) {
			va_start(arg, format);
			vfprintf(f, format, arg);
			va_end(arg);
			fflush(f);
			fclose(f);
		}
	}
}

void traceHex ( unsigned char* data, size_t len)
{
   loghex(NULL, 0, data, len);
}

typedef struct _CARD_CONTEXT
{
   char szReaderName[MAX_PATH];
   BYTE rgbAtr[36];
   DWORD cbAtr;
   VENDOR_SPECIFIC* pVs;
   LONG counter;
} CARD_CONTEXT;

CARD_CONTEXT g_cardContexts[1024] = {0};
CRITICAL_SECTION g_cs;

BOOL IsLocalService ()
{
   static BOOL g_bChecked = FALSE;
   static BOOL g_bIsLocalService = FALSE;
   if (!g_bChecked)
   {
      DWORD dwSessionID = 0, dwProcessID = GetCurrentProcessId();
      ProcessIdToSessionId(dwProcessID, &dwSessionID);
      g_bIsLocalService = (dwSessionID == 0)? TRUE : FALSE;
      g_bChecked = TRUE;
   }

   return g_bIsLocalService;
}


VENDOR_SPECIFIC* GetContext (PCARD_DATA pCardData, const char* szName, LPBYTE rgbAtr, DWORD cbAtr, BOOL* pbNew)
{
   int i;
   VENDOR_SPECIFIC* pRet = NULL;

   if (IsLocalService ())
      return NULL;

   EnterCriticalSection (&g_cs);
   for (i = 0; i < ARRAYSIZE (g_cardContexts); i++)
   {
      if (g_cardContexts[i].pVs && (0 == _stricmp (szName, g_cardContexts[i].szReaderName))
         && (cbAtr == g_cardContexts[i].cbAtr)
         && (0 == memcmp (rgbAtr, g_cardContexts[i].rgbAtr, cbAtr))
         )
      {
         *pbNew = FALSE;
         pRet = g_cardContexts[i].pVs;
         g_cardContexts[i].counter++;
         break;
      }
   }

   if (!pRet)
   {
      for (i = 0; i < ARRAYSIZE (g_cardContexts); i++)
      {
         if (g_cardContexts[i].pVs == NULL)
         {
            strcpy (g_cardContexts[i].szReaderName, szName);
            g_cardContexts[i].cbAtr = cbAtr;
            memcpy (g_cardContexts[i].rgbAtr, rgbAtr, cbAtr);
	         /* VENDOR SPECIFIC */
            g_cardContexts[i].pVs = (VENDOR_SPECIFIC*) pCardData->pfnCspAlloc(sizeof(VENDOR_SPECIFIC));
	         memset(g_cardContexts[i].pVs, 0, sizeof(VENDOR_SPECIFIC));
            g_cardContexts[i].counter = 2;
            pRet = g_cardContexts[i].pVs;
            *pbNew = TRUE;
            break;
         }
      }
   }

   LeaveCriticalSection (&g_cs);
   return pRet;
}


static DWORD md_create_context(PCARD_DATA pCardData, VENDOR_SPECIFIC *vs);

void freeContext (PCARD_DATA pCardData)
{
   VENDOR_SPECIFIC* vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

   disassociate_card(pCardData);

   if(vs->ctx)   {
	   logprintf(pCardData, 6, "release context\n");
	   sc_release_context(vs->ctx);
	   vs->ctx = NULL;
   }

   logprintf(pCardData, 1, "**********************************************************************\n");

   md_fs_finalize(pCardData);
   pCardData->pfnCspFree(pCardData->pvVendorSpecific);
   pCardData->pvVendorSpecific = NULL;
}

void DeleteContext (PCARD_DATA pCardData, BOOL bForce)
{
   int i;
   VENDOR_SPECIFIC* pVs = (VENDOR_SPECIFIC*) pCardData->pvVendorSpecific;
   if (!pVs)
      return;
   if (IsLocalService ())
      freeContext (pCardData);
   else
   {
      BOOL bFound = FALSE;
      EnterCriticalSection (&g_cs);
      for (i = 0; i < ARRAYSIZE (g_cardContexts); i++)
      {
         if (g_cardContexts[i].pVs == pVs)
         {
            bFound = TRUE;
            g_cardContexts[i].counter--;
            if (g_cardContexts[i].counter <= 0 || (bForce && g_cardContexts[i].counter == 1))
            {               
               freeContext (pCardData);
               memset (&g_cardContexts[i], 0, sizeof (CARD_CONTEXT));
            }
            break;
         }
      }
      if (!bFound)
         freeContext (pCardData);
      LeaveCriticalSection (&g_cs);
   }
}

/*
 * check if the card has been removed, or the
 * caller has changed the handles.
 * if so, then free up all previous card info
 * and reestablish
 */
static int
check_reader_status(PCARD_DATA pCardData)
{
	int r = SCARD_S_SUCCESS;
	VENDOR_SPECIFIC *vs = NULL;
	BOOL bNew = FALSE;

	logprintf(pCardData, 4, "check_reader_status\n");
	if(!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 7, "pCardData->hSCardCtx:0x%08X pCardData->hScard:0x%08X\n",
			pCardData->hSCardCtx, pCardData->hScard);

	if (pCardData->hSCardCtx != vs->hSCardCtx || pCardData->hScard != vs->hScard) {
      char szReaderName[MAX_PATH];
      DWORD cbReaderName = MAX_PATH;
      BYTE rgbAtr[38];
      DWORD cbAtr = sizeof (rgbAtr);
		
		DWORD dwEventCounter = 0;
		SCARD_READERSTATE_A readerState = {0};

		logprintf (pCardData, 1, "HANDLES CHANGED from hSCardCtx:0x%08X hScard:0x%08X\n", vs->hSCardCtx, vs->hScard);

		r = SCardGetAttribPtr(pCardData->hScard, SCARD_ATTR_DEVICE_SYSTEM_NAME, (LPBYTE)szReaderName, &cbReaderName);
		if (r != SCARD_S_SUCCESS)
		{
			logprintf(pCardData, 1, "SCardGetAttrib(SCARD_ATTR_DEVICE_SYSTEM_NAME) failed with error 0x%.8X\n", r);
			return r;
		}

		readerState.szReader = szReaderName;

		r = SCardGetStatusChangePtr (pCardData->hSCardCtx, 0, &readerState, 1);
		if (r != SCARD_S_SUCCESS)
		{
			logprintf(pCardData, 1, "SCardGetStatusChange failed with error 0x%.8X\n", r);
			return r;
		}

		dwEventCounter = (readerState.dwEventState >> 16) & 0x0000FFFF;
		cbAtr = readerState.cbAtr;
		memcpy (rgbAtr, readerState.rgbAtr, cbAtr);

      /* verify reader name and ATR */
      if (  vs->reader
         && (0 == _stricmp (szReaderName, vs->reader->name))
         && (cbAtr == vs->reader->atr.len)
         && (0 == memcmp (rgbAtr, vs->reader->atr.value, cbAtr))
         )
      {					
			if (dwEventCounter == vs->dwEventsCounter)
			{
				logprintf (pCardData, 1, "reader instance = 0x%p\n", vs->reader);
			}
			else
			{
				logprintf (pCardData, 1, "New card has been inserted. Updating our internal instance.\n");
				disassociate_card(pCardData);
				if(vs->ctx)   {
					sc_release_context(vs->ctx);
				}
				md_fs_finalize(pCardData);

				memset(vs, 0, sizeof(VENDOR_SPECIFIC));
				bNew = TRUE;

            r = md_create_context(pCardData, vs);
	         if (r != SCARD_S_SUCCESS) {
		         DeleteContext(pCardData, TRUE);
		         return r;
	         }
			}
      }
      else
      {         
         VENDOR_SPECIFIC* localVs = GetContext (pCardData, szReaderName, rgbAtr, cbAtr, &bNew);
         logprintf (pCardData, 1, "something changed. Updating our internal instance.\n");
         if (localVs)
         {
            DeleteContext (pCardData, TRUE);
            pCardData->pvVendorSpecific = localVs;
            if (bNew)
            {
               r = md_create_context(pCardData, localVs);
	            if (r != SCARD_S_SUCCESS) {
		            DeleteContext(pCardData, TRUE);
		            return r;
	            }
            }
         }
         else
         {
            bNew = TRUE;
            localVs = vs;
            disassociate_card(pCardData);
		      logprintf(pCardData, 1, "disassociate_card r = 0x%08X\n", r);
         }

	      localVs->hSCardCtx = pCardData->hSCardCtx;
	      localVs->hScard = pCardData->hScard;
		}

      if (bNew)
      {
		   /* Basically a mini AcquireContext */
		   r = associate_card(pCardData); /* need to check return codes */
		   if (r != SCARD_S_SUCCESS) 
			   return r;
		   logprintf(pCardData, 1, "associate_card r = 0x%08X\n", r);
		   /* Rebuild 'soft' fs - in case changed */
		   r = md_fs_init(pCardData);
		   logprintf(pCardData, 1, "md_fs_init r = 0x%08X\n", r);

			vs->dwEventsCounter = dwEventCounter;
      }
	}
	else if (vs->reader) {
		/* This should always work, as BaseCSP should be checking for removal too */
		/*r = sc_detect_card_presence(vs->reader);
		logprintf(pCardData, 2, "check_reader_status r=%d flags 0x%08X\n", r, vs->reader->flags);*/
	}

    vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
    vs->hSCardCtx = pCardData->hSCardCtx;
    vs->hScard = pCardData->hScard;
    sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard);

	if (!bNew && (GetTickCount64() - vs->lastChecked) >= 500)
	{
		sc_pkcs15_get_pin_info(vs->pin_objs[ROLE_USER]->p15card, vs->pin_objs[ROLE_USER]);
		vs->lastChecked = GetTickCount64();
	}

	return r;
}

static int md_select_key_file(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_prkey_info *prkey)
{
	sc_context_t *ctx = p15card->card->ctx;
	sc_path_t path, file_id;
	int r;

	memset(&path, 0, sizeof(sc_path_t));
	memset(&file_id, 0, sizeof(sc_path_t));

	/* TODO: Why file_app may be NULL -- at least 3F00 has to be present?
	 * Check validity of the following assumption. */
	/* For pkcs15-emulated cards, the file_app may be NULL,
	 * in that case we allways assume an absolute path */
	if (!prkey->path.len && prkey->path.aid.len) {
		/* Private key is a SDO allocated in application DF */
		path = prkey->path;
	}
	else if (prkey->path.len == 2 && p15card->file_app != NULL) {
		/* Path is relative to app. DF */
		path = p15card->file_app->path;
		file_id = prkey->path;
		sc_append_path(&path, &file_id);
	}
	else if (prkey->path.len > 2) {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
		file_id.type = SC_PATH_TYPE_FILE_ID;
	}
	else {
		return SC_ERROR_INVALID_ARGUMENTS;
	}

	r = sc_select_file(p15card->card, &path, NULL);

	return r;
}

static BOOL lock(PCARD_DATA pCardData)
{
	if (pCardData) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if (vs) {
			EnterCriticalSection(&vs->hScard_lock);
			return TRUE;
		}
	}

	return FALSE;
}

static void unlock(PCARD_DATA pCardData)
{
	if (pCardData) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if (vs) {
			LeaveCriticalSection(&vs->hScard_lock);
		}
	}
}


struct sc_pkcs15_object *
	md_get_auth_object_by_role(struct sc_pkcs15_card *p15card, PIN_ID role)
{
	struct sc_pkcs15_object *ret_obj = NULL;
	int rv = SC_ERROR_OBJECT_NOT_FOUND;

	/* please keep me in sync with _get_auth_object_by_name() in pkcs11/framework-pkcs15.c */
	if (role == ROLE_USER) {
		/* Get 'global' User PIN; if no, get the 'local' one */
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
			SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
	}
	else if (role == MD_ROLE_USER_SIGN) {
		int idx = 0;

		/* Get the 'global' user PIN */
		rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_GLOBAL,
			SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
		if (!rv) {
			/* Global (user) PIN exists, get the local one -- sign PIN */
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
		}
		else {
			/* No global PIN, try to get first local one -- user PIN */
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, &ret_obj);
			if (!rv) {
				/* User PIN is local, try to get the second local if any -- sign PIN */
				struct sc_pkcs15_object *second_pin = NULL;
				idx++;
				if (SC_SUCCESS == sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PIN_LOCAL,
					SC_PKCS15_PIN_TYPE_FLAGS_MASK, &idx, &second_pin))
				{
					ret_obj = second_pin;
				}
			}
		}
	}
	else if (role == ROLE_ADMIN) {
		/* Get SO PIN; if no, get the 'global' PUK; if no get the 'local' one  */
		rv = sc_pkcs15_find_so_pin(p15card, &ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_GLOBAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
		if (rv)
			rv = sc_pkcs15_find_pin_by_flags(p15card, SC_PKCS15_PIN_TYPE_FLAGS_PUK_LOCAL,
				SC_PKCS15_PIN_TYPE_FLAGS_MASK, NULL, &ret_obj);
	}

	return rv ? NULL : ret_obj;
}

static int md_get_objects(VENDOR_SPECIFIC* vs, unsigned int type,
	struct sc_pkcs15_object **enum_objs, int ret_count)
{
	int rv, ii, obj_num = 0;
	for (ii = 0; ii < 4 && (obj_num < ret_count); ii++)
	{
		if (!vs->fws_data[ii])
			break;
		rv = sc_pkcs15_get_objects(vs->fws_data[ii]->p15card, type, enum_objs + obj_num, ret_count - obj_num);
		if (rv < 0) {
			return rv;
		}
		obj_num += rv;
	}

	return obj_num;
}

int md_get_pin_obj(VENDOR_SPECIFIC* vs, PIN_ID role, struct sc_pkcs15_object **out)
{
	md_fw_data *fw_data = NULL;
	int idx;

	for (idx = 0; idx < 4; idx++)
	{
		if (!vs->fws_data[idx])
			break;

		fw_data = vs->fws_data[idx];

		*out = md_get_auth_object_by_role(fw_data->p15card, role);

		if (*out)
			break;
	}

	return (*out)? SC_SUCCESS : SC_ERROR_ASN1_OBJECT_NOT_FOUND;
}

static DWORD
md_get_pin_by_role(PCARD_DATA pCardData, PIN_ID role, struct sc_pkcs15_object **ret_obj)
{
	VENDOR_SPECIFIC *vs;
	int rv;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!ret_obj)
		return SCARD_E_INVALID_PARAMETER;

	/* please keep me in sync with _get_auth_object_by_name() in pkcs11/framework-pkcs15.c */
	if (role == ROLE_USER || role == MD_ROLE_USER_SIGN || role == ROLE_ADMIN) {
		rv = md_get_pin_obj(vs, role, ret_obj);
	}
	else {
		logprintf(pCardData, 2,
			"cannot get PIN object: unsupported role %u\n",
			(unsigned int)role);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	if (rv)
		return SCARD_E_UNSUPPORTED_FEATURE;

	if (*ret_obj)
		logprintf(pCardData, 7, "Returning PIN '%.*s' for role %u\n",
		(int) sizeof(*ret_obj)->label, (*ret_obj)->label,
			(unsigned int)role);

	return SCARD_S_SUCCESS;
}

static const char *
md_get_config_str(PCARD_DATA pCardData, enum ui_str id)
{
	VENDOR_SPECIFIC *vs;
	const char *ret = NULL;

	if (!pCardData)
		return ret;

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader) {
		const char *preferred_language = NULL;
		struct sc_atr atr;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		ret = ui_get_str(vs->ctx, &atr, vs->fws_data[0]->p15card , id);
	}

	return ret;
}


static HICON
md_get_config_icon(PCARD_DATA pCardData, char *flag_name, HICON ret_default)
{
	VENDOR_SPECIFIC *vs;
	HICON ret = ret_default;

	if (!pCardData)
		return ret;

	logprintf(pCardData, 2, "Get '%s' option\n", flag_name);

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader) {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock) {
			const char *filename = scconf_get_str(atrblock, flag_name, NULL);
			if (filename) {
				ret = (HICON)LoadImage(g_inst, filename, IMAGE_ICON, 0, 0,
					LR_LOADFROMFILE | LR_DEFAULTSIZE | LR_SHARED);
			}
			if (!ret)
				ret = ret_default;
		}
	}


	return ret;
}


static HICON
md_get_pinpad_dlg_icon(PCARD_DATA pCardData)
{
	return md_get_config_icon(pCardData, "md_pinpad_dlg_icon", NULL);
}


static int
md_get_config_int(PCARD_DATA pCardData, char *flag_name, int ret_default)
{
	VENDOR_SPECIFIC *vs;
	int ret = ret_default;

	if (!pCardData)
		return ret;

	logprintf(pCardData, 2, "Get '%s' option\n", flag_name);

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (vs->ctx && vs->reader) {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock)
			ret = scconf_get_int(atrblock, flag_name, ret_default);
	}

	return ret;
}


static int
md_get_pinpad_dlg_timeout(PCARD_DATA pCardData)
{
	return md_get_config_int(pCardData, "md_pinpad_dlg_timeout", 30);
}


static BOOL
md_get_config_bool(PCARD_DATA pCardData, char *flag_name, BOOL ret_default)
{
	VENDOR_SPECIFIC *vs;
	BOOL ret = ret_default;

	if (!pCardData)
		return ret;

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (!vs)
		return ret;

	if (vs->ctx && vs->reader) {
		struct sc_atr atr;
		scconf_block *atrblock;
		atr.len = pCardData->cbAtr;
		memcpy(atr.value, pCardData->pbAtr, atr.len);
		atrblock = _sc_match_atr_block(vs->ctx, NULL, &atr);
		logprintf(pCardData, 2, "Match ATR:\n");
		loghex(pCardData, 3, atr.value, atr.len);

		if (atrblock)
			ret = scconf_get_bool(atrblock, flag_name, ret_default) ? TRUE : FALSE;
	}

	return ret;
}


/* 'cancellation' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_pinpad_dlg_enable_cancel(PCARD_DATA pCardData)
{
	TCHAR path[MAX_PATH] = { 0 };

	logprintf(pCardData, 2, "Is cancelling the PIN pad dialog enabled?\n");

	if (GetModuleFileName(NULL, path, ARRAYSIZE(path))) {
		DWORD enable_cancel;
		size_t sz = sizeof enable_cancel;

		if (SC_SUCCESS == sc_ctx_win32_get_config_value(NULL, path,
			SUBKEY_ENABLE_CANCEL,
			(char *)(&enable_cancel), &sz)) {
			switch (enable_cancel) {
			case 0:
				return FALSE;
			case 1:
				return TRUE;
			}
		}
	}

	return md_get_config_bool(pCardData, "md_pinpad_dlg_enable_cancel", FALSE);
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_read_only(PCARD_DATA pCardData)
{
	BOOL ret = TRUE;

	logprintf(pCardData, 2, "Is read-only?\n");

	if (pCardData && pCardData->pvVendorSpecific) {
		VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
		if (vs->fws_data[0] && vs->fws_data[0]->p15card && vs->fws_data[0]->p15card->tokeninfo) {
			if (vs->fws_data[0]->p15card->tokeninfo->flags & SC_PKCS15_TOKEN_READONLY) {
				ret = TRUE;
			}
			else {
				ret = FALSE;
			}
		}
	}

	return md_get_config_bool(pCardData, "read_only", ret);
}

static BOOL
md_has_ecdh_key(PCARD_DATA pCardData)
{
    if (pCardData && pCardData->pvVendorSpecific)
    {
        int ii;
        VENDOR_SPECIFIC *vs = (VENDOR_SPECIFIC *) pCardData->pvVendorSpecific;
        for (ii=0; ii<MD_MAX_KEY_CONTAINERS; ii++)   {
            if (    (vs->p15_containers[ii].flags & CONTAINER_MAP_VALID_CONTAINER)
                &&  vs->p15_containers[ii].prkey_obj 
                &&  (vs->p15_containers[ii].prkey_obj->type == SC_PKCS15_TYPE_PRKEY_EC)
					 &&  (vs->p15_containers[ii].key_derivation)
					 )
		        return TRUE;
        }
    }
	return FALSE;
}


/* 'Write' mode can be enabled from the OpenSC configuration file*/
static BOOL
md_is_supports_X509_enrollment(PCARD_DATA pCardData)
{
	BOOL defaultvalue = !md_is_read_only(pCardData);
	logprintf(pCardData, 2, "Is supports X509 enrollment?\n");
	return md_get_config_bool(pCardData, "md_supports_X509_enrollment", defaultvalue);
}


/* Get know if the GUID has to used as ID of crypto objects */
static BOOL
md_is_guid_as_id(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as ID of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_id", FALSE);
}


/* Get know if the GUID has to used as label of crypto objects */
static BOOL
md_is_guid_as_label(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is GUID has to be used as label of crypto objects?\n");
	return md_get_config_bool(pCardData, "md_guid_as_label", FALSE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_GEN mechanism */
static BOOL
md_is_supports_container_key_gen(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key generation' create_container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_gen", TRUE);
}


/* Get know if disabled CARD_CREATE_CONTAINER_KEY_IMPORT mechanism */
static BOOL
md_is_supports_container_key_import(PCARD_DATA pCardData)
{
	logprintf(pCardData, 2, "Is supports 'key import' create container mechanism?\n");
	return md_get_config_bool(pCardData, "md_supports_container_key_import", TRUE);
}

/* generate unique key label (GUID)*/
static VOID md_generate_guid(__in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szGuid) {
	RPC_CSTR szRPCGuid = NULL;
	GUID Label = { 0 };
	UuidCreate(&Label);
	if (UuidToStringA(&Label, &szRPCGuid) == RPC_S_OK && szRPCGuid) {
		strlcpy(szGuid, (PSTR)szRPCGuid, MAX_CONTAINER_NAME_LEN + 1);
		RpcStringFreeA(&szRPCGuid);
	}
	else
		szGuid[0] = 0;
}

static DWORD
md_contguid_get_guid_from_card(PCARD_DATA pCardData, struct sc_pkcs15_object *prkey, __in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szGuid)
{
	int rv;
	VENDOR_SPECIFIC *vs;
	size_t guid_len = MAX_CONTAINER_NAME_LEN + 1;

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	rv = sc_pkcs15_get_object_guid(prkey->p15card, prkey, 1, (unsigned char*)szGuid, &guid_len);
	if (rv) {
		logprintf(pCardData, 2, "md_contguid_get_guid_from_card(): error %d\n", rv);
		return SCARD_F_INTERNAL_ERROR;
	}

	return SCARD_S_SUCCESS;
}

/* add a new entry in the guid conversion table */
static DWORD
md_contguid_add_conversion(PCARD_DATA pCardData, struct sc_pkcs15_object *prkey,
	__in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szWindowsGuid)
{
	DWORD ret;
	int i;
	CHAR szOpenSCGuid[MAX_CONTAINER_NAME_LEN + 1] = "";

	ret = md_contguid_get_guid_from_card(pCardData, prkey, szOpenSCGuid);
	if (ret != SCARD_S_SUCCESS)
		return ret;

	if (strcmp(szOpenSCGuid, szWindowsGuid) == 0)
		return ret;

	for (i = 0; i < MD_MAX_CONVERSIONS; i++) {
		if (md_static_conversions[i].szWindowsGuid[0] == 0) {
			strlcpy(md_static_conversions[i].szWindowsGuid,
				szWindowsGuid, MAX_CONTAINER_NAME_LEN + 1);
			strlcpy(md_static_conversions[i].szOpenSCGuid,
				szOpenSCGuid, MAX_CONTAINER_NAME_LEN + 1);
			logprintf(pCardData, 0, "md_contguid_add_conversion(): Registering conversion '%s' '%s'\n", szWindowsGuid, szOpenSCGuid);
			return SCARD_S_SUCCESS;;
		}
	}
	logprintf(pCardData, 0, "md_contguid_add_conversion(): Unable to add a new conversion with guid %s.\n", szWindowsGuid);
	return SCARD_F_INTERNAL_ERROR;;
}

/* remove an entry in the guid conversion table*/
static VOID
md_contguid_delete_conversion(PCARD_DATA pCardData, __in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szWindowsGuid)
{
	int i;
	for (i = 0; i < MD_MAX_CONVERSIONS; i++) {
		if (strcmp(md_static_conversions[i].szWindowsGuid, szWindowsGuid) == 0) {
			memset(md_static_conversions + i, 0, sizeof(struct md_guid_conversion));
		}
	}
}

/* build key args from the minidriver guid */
static VOID
md_contguid_build_key_args_from_cont_guid(PCARD_DATA pCardData, __in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szGuid,
	struct sc_pkcs15init_prkeyargs *prkey_args)
{
	/* strlen(szGuid) <= MAX_CONTAINER_NAME */
	logprintf(pCardData, 3, "Using the guid '%s'\n", szGuid);
	if (szGuid[0] != 0) {
		prkey_args->guid = (unsigned char*)szGuid;
		prkey_args->guid_len = strlen(szGuid);
	}

	if (md_is_guid_as_id(pCardData)) {
		memcpy(prkey_args->id.value, szGuid, strlen(szGuid));
		prkey_args->id.len = strlen(szGuid);
	}
	if (md_is_guid_as_label(pCardData)) {
		prkey_args->label = szGuid;
	}
}

/* build minidriver guid from the key */
static DWORD
md_contguid_build_cont_guid_from_key(PCARD_DATA pCardData, struct sc_pkcs15_object *key_obj, __in_ecount(MAX_CONTAINER_NAME_LEN + 1) PSTR szGuid)
{
	struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
	DWORD dwret = SCARD_S_SUCCESS;

	szGuid[0] = '\0';
	/* prioritize the use of the key id over the key label as a container name */
	if (md_is_guid_as_id(pCardData) && prkey_info->id.len > 0 && prkey_info->id.len <= MAX_CONTAINER_NAME_LEN) {
		memcpy(szGuid, prkey_info->id.value, prkey_info->id.len);
		szGuid[prkey_info->id.len] = 0;
	}
	else if (md_is_guid_as_label(pCardData) && key_obj->label[0] != 0) {
		strlcpy(szGuid, key_obj->label, MAX_CONTAINER_NAME_LEN + 1);
	}
	else {
		dwret = md_contguid_get_guid_from_card(pCardData, key_obj, szGuid);
	}

	return dwret;
}


static DWORD
md_cont_flags_from_key(PCARD_DATA pCardData, struct sc_pkcs15_object *key_obj, unsigned char *cont_flags)
{
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	VENDOR_SPECIFIC *vs;
	int rv;

	vs = (VENDOR_SPECIFIC*)pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;

	*cont_flags = CONTAINER_MAP_VALID_CONTAINER;
	if (prkey_info->aux_data) {
		rv = sc_aux_data_get_md_flags(vs->ctx, prkey_info->aux_data, cont_flags);
		if (rv != SC_ERROR_NOT_SUPPORTED && rv != SC_SUCCESS)
			return SCARD_F_INTERNAL_ERROR;
	}

	return SCARD_S_SUCCESS;
}


/* Search directory by name and optionally by name of it's parent */
static DWORD
md_fs_find_directory(PCARD_DATA pCardData, struct md_directory *parent, char *name, struct md_directory **out)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;

	if (out)
		*out = NULL;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (!parent)
		parent = &vs->root;

	if (!name) {
		dir = parent;
	}
	else {
		dir = parent->subdirs;
		while (dir) {
			if (strlen(name) > sizeof dir->name
				|| !strnicmp((char *)dir->name, name, sizeof dir->name))
				break;
			dir = dir->next;
		}
	}

	if (!dir)
		return SCARD_E_DIR_NOT_FOUND;

	if (out)
		*out = dir;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' directory\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_directory(PCARD_DATA pCardData, struct md_directory **head, char *name,
	CARD_FILE_ACCESS_CONDITION acl,
	struct md_directory **out)
{
	struct md_directory *new_dir = NULL;

	if (!pCardData || !head || !name)
		return SCARD_E_INVALID_PARAMETER;

	new_dir = pCardData->pfnCspAlloc(sizeof(struct md_directory));
	if (!new_dir)
		return SCARD_E_NO_MEMORY;
	memset(new_dir, 0, sizeof(struct md_directory));

	strlcpy((char *)new_dir->name, name, sizeof(new_dir->name));
	new_dir->acl = acl;

	if (*head == NULL) {
		*head = new_dir;
	}
	else {
		struct md_directory *last = *head;
		while (last->next)
			last = last->next;
		last->next = new_dir;
	}

	if (out)
		*out = new_dir;

	logprintf(pCardData, 3, "MD virtual file system: directory '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_find_file(PCARD_DATA pCardData, char *parent, char *name, struct md_file **out)
{
	struct md_file *file = NULL;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (out)
		*out = NULL;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir) {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}

	for (file = dir->files; file != NULL;) {
		if (sizeof file->name < strlen(name)
			|| !strnicmp((char *)file->name, name, sizeof file->name))
			break;
		file = file->next;
	}
	if (!file)
		return SCARD_E_FILE_NOT_FOUND;

	if (out)
		*out = file;

	logprintf(pCardData, 3, "MD virtual file system: found '%s' file\n", name);
	return SCARD_S_SUCCESS;
}


static DWORD
md_fs_add_file(PCARD_DATA pCardData, struct md_file **head, char *name, CARD_FILE_ACCESS_CONDITION acl,
	unsigned char *blob, size_t size, struct md_file **out)
{
	struct md_file *new_file = NULL;

	if (!pCardData || !head || !name)
		return SCARD_E_INVALID_PARAMETER;

	new_file = pCardData->pfnCspAlloc(sizeof(struct md_file));
	if (!new_file)
		return SCARD_E_NO_MEMORY;
	memset(new_file, 0, sizeof(struct md_file));

	strlcpy((char *)new_file->name, name, sizeof(new_file->name));
	new_file->size = size;
	new_file->acl = acl;

	if (size) {
		new_file->blob = pCardData->pfnCspAlloc(size);
		if (!new_file->blob) {
			pCardData->pfnCspFree(new_file);
			return SCARD_E_NO_MEMORY;
		}

		if (blob)
			CopyMemory(new_file->blob, blob, size);
		else
			memset(new_file->blob, 0, size);
	}

	if (*head == NULL) {
		*head = new_file;
	}
	else {
		struct md_file *last = *head;
		while (last->next)
			last = last->next;
		last->next = new_file;
	}

	if (out)
		*out = new_file;

	logprintf(pCardData, 3, "MD virtual file system: file '%s' added\n", name);
	return SCARD_S_SUCCESS;
}


static void
md_fs_free_file(PCARD_DATA pCardData, struct md_file *file)
{
	if (!file)
		return;
	if (file->blob)
		pCardData->pfnCspFree(file->blob);
	file->blob = NULL;
	file->size = 0;
	pCardData->pfnCspFree(file);
}


static DWORD
md_fs_delete_file(PCARD_DATA pCardData, char *parent, char *name)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL, *file_to_rm = NULL;
	struct md_directory *dir = NULL;
	int deleted = 0;
	DWORD dwret;

	if (!pCardData || !name)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir) {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_INVALID_PARAMETER;
	}
	else if (!dir->files) {
		logprintf(pCardData, 2, "no files in '%s' directory\n", parent ? parent : "<null>");
		return SCARD_E_FILE_NOT_FOUND;
	}

	if (sizeof dir->files->name < strlen(name)
		|| !strnicmp((char *)dir->files->name, name, sizeof dir->files->name)) {
		file_to_rm = dir->files;
		dir->files = dir->files->next;
		md_fs_free_file(pCardData, file_to_rm);
		dwret = SCARD_S_SUCCESS;
	}
	else {
		for (file = dir->files; file != NULL; file = file->next) {
			if (!file->next)
				break;
			if (sizeof file->next->name < strlen(name)
				|| !strnicmp((char *)file->next->name, name, sizeof file->next->name)) {
				file_to_rm = file->next;
				file->next = file->next->next;
				md_fs_free_file(pCardData, file_to_rm);
				deleted = 1;
				break;
			}
		}
		dwret = deleted ? SCARD_S_SUCCESS : SCARD_E_FILE_NOT_FOUND;
	}

	if (!stricmp(parent, "mscp")) {
		int idx = -1;

		if (sscanf(name, "ksc%d", &idx) > 0) {
		}
		else if (sscanf(name, "kxc%d", &idx) > 0) {
		}

		if (idx >= 0 && idx < MD_MAX_KEY_CONTAINERS) {
			dwret = md_pkcs15_delete_object(pCardData, vs->p15_containers[idx].cert_obj);
			vs->p15_containers[idx].cert_obj = NULL;
			if (dwret != SCARD_S_SUCCESS)
				logprintf(pCardData, 2,
					"Cannot delete certificate PKCS#15 object #%i: dwret 0x%lX\n",
					idx, (unsigned long)dwret);
		}
	}

	return dwret;
}

static void
md_fs_finalize(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	struct md_file *file = NULL, *file_to_rm;
	struct md_directory *dir = NULL, *dir_to_rm;

	if (!pCardData)
		return;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return;

	file = vs->root.files;
	while (file != NULL) {
		file_to_rm = file;
		file = file->next;
		md_fs_free_file(pCardData, file_to_rm);
	}
	vs->root.files = NULL;

	dir = vs->root.subdirs;
	while (dir) {
		file = dir->files;
		while (file != NULL) {
			file_to_rm = file;
			file = file->next;
			md_fs_free_file(pCardData, file_to_rm);
		}
		dir_to_rm = dir;
		dir = dir->next;
		pCardData->pfnCspFree(dir_to_rm);
	}
	vs->root.subdirs = NULL;
}

/*
 * Update 'soft' containers.
 * Called each time when 'WriteFile' is called for 'cmapfile'.
 */
static DWORD
md_pkcs15_update_containers(PCARD_DATA pCardData, unsigned char *blob, size_t size)
{
	VENDOR_SPECIFIC *vs;
	CONTAINER_MAP_RECORD *pp;
	int nn_records, idx;

	if (!pCardData || !blob || size < sizeof(CONTAINER_MAP_RECORD))
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	nn_records = (int)size / sizeof(CONTAINER_MAP_RECORD);
	if (nn_records > MD_MAX_KEY_CONTAINERS)
		nn_records = MD_MAX_KEY_CONTAINERS;

	for (idx = 0, pp = (CONTAINER_MAP_RECORD *)blob; idx < nn_records; idx++, pp++) {
		struct md_pkcs15_container *cont = &(vs->p15_containers[idx]);
		size_t count;
		CHAR szGuid[MAX_CONTAINER_NAME_LEN + 1] = "";

		count = wcstombs(szGuid, pp->wszGuid, sizeof(cont->guid));
		if (!count) {
			if (cont->guid[0] != 0) {
				md_contguid_delete_conversion(pCardData, cont->guid);
			}
			memset(cont, 0, sizeof(CONTAINER_MAP_RECORD));
		}
		else {
			strlcpy(cont->guid, szGuid, MAX_CONTAINER_NAME_LEN + 1);
			cont->index = idx;
			cont->flags = pp->bFlags;
			cont->size_sign = pp->wSigKeySizeBits;
			cont->size_key_exchange = pp->wKeyExchangeKeySizeBits;
			logprintf(pCardData, 3, "update P15 containers: touch container (idx:%i,id:%s,guid:%.*s,flags:%X)\n",
				idx, sc_pkcs15_print_id(&cont->id),
				(int)sizeof cont->guid, cont->guid, cont->flags);
		}
	}

	return SCARD_S_SUCCESS;
}

static DWORD
md_pkcs15_delete_object(PCARD_DATA pCardData, struct sc_pkcs15_object *obj)
{
	VENDOR_SPECIFIC *vs;
	struct sc_profile *profile = NULL;
	struct sc_card *card = NULL;
	struct sc_app_info *app_info = NULL;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	int rv;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;
	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	card = obj->p15card->card;

	if (!obj)
		return SCARD_S_SUCCESS;
	logprintf(pCardData, 3, "MdDeleteObject('%.*s',type:0x%X) called\n", (int) sizeof obj->label, obj->label, obj->type);

	rv = sc_lock(card);
	if (rv) {
		logprintf(pCardData, 3, "MdDeleteObject(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = obj->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdDeleteObject(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdDeleteObject(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, obj->p15card);

	rv = sc_pkcs15init_delete_object(obj->p15card, profile, obj);
	if (rv) {
		logprintf(pCardData, 2, "MdDeleteObject(): pkcs15init delete object failed %d\n", rv);
		goto done;
	}

	dwret = SCARD_S_SUCCESS;
	logprintf(pCardData, 3, "MdDeleteObject() returns OK\n");
done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}


/* Set 'soft' file contents,
 * and update data associated to  'cardcf' and 'cmapfile'.
 */
static DWORD
md_fs_set_content(PCARD_DATA pCardData, struct md_file *file, unsigned char *blob, size_t size)
{
	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	if (file->blob)
		pCardData->pfnCspFree(file->blob);

	file->blob = pCardData->pfnCspAlloc(size);
	if (!file->blob)
		return SCARD_E_NO_MEMORY;
	CopyMemory(file->blob, blob, size);
	file->size = size;

    if (!md_is_read_only (pCardData) && !_stricmp(file->name, "cmapfile"))
		return md_pkcs15_update_containers(pCardData, blob, size);

	return SCARD_S_SUCCESS;
}

/*
 * Set 'cardid' from the 'serialNumber' attribute of the 'tokenInfo'
 */
static DWORD
md_set_cardid(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	sc_pkcs15_tokeninfo_t *tokeninfo;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs || !vs->fws_data[0] || !vs->fws_data[0]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	tokeninfo = vs->fws_data[0]->p15card->tokeninfo;

	if (tokeninfo && tokeninfo->serial_number) {
		unsigned char sn_bin[SC_MAX_SERIALNR];
		unsigned char cardid_bin[MD_CARDID_SIZE];
		size_t offs, wr, sn_len = sizeof(sn_bin);
		int rv;

		rv = sc_hex_to_bin(tokeninfo->serial_number, sn_bin, &sn_len);
		if (rv) {
			sn_len = strlen(tokeninfo->serial_number);
			if (sn_len > SC_MAX_SERIALNR) {
				sn_len = SC_MAX_SERIALNR;
			}
			memcpy(sn_bin, tokeninfo->serial_number, sn_len);
		}

		if (sn_len > 0) {
			for (offs = 0; offs < MD_CARDID_SIZE; ) {
				wr = MD_CARDID_SIZE - offs;
				if (wr > sn_len)
					wr = sn_len;
				memcpy(cardid_bin + offs, sn_bin, wr);
				offs += wr;
			}
		}
		else {
			memset(cardid_bin, 0, MD_CARDID_SIZE);
		}

		dwret = md_fs_set_content(pCardData, file, cardid_bin, MD_CARDID_SIZE);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;
	}

	logprintf(pCardData, 3, "cardid(%"SC_FORMAT_LEN_SIZE_T"u)\n",
		file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

static int
md_pkcs15_read_certificate(struct sc_pkcs15_card *p15card, struct sc_pkcs15_cert_info *info,
	struct sc_pkcs15_cert **cert_out)
{
	int rv;

	rv = sc_pkcs15_read_certificate(p15card, info, cert_out);
	if (rv >= 0 && (!info->value.value || !info->value.len))
	{
		struct sc_pkcs15_cert* p15_cert = *cert_out;
		/* save certificate value to avoid send APDU when reading certificate next time */
		info->value.value = malloc(p15_cert->data.len);
		if (info->value.value)
		{
			memcpy(info->value.value, p15_cert->data.value, p15_cert->data.len);
			info->value.len = p15_cert->data.len;
		}
	}

	return rv;

}

/* fill the msroots file from root certificates */
static DWORD
md_fs_read_msroots_file(PCARD_DATA pCardData, struct md_file *file)
{
	CERT_BLOB dbStore = { 0 };
	HCERTSTORE hCertStore;
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	DWORD dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	hCertStore = CertOpenStore(CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING, (HCRYPTPROV_LEGACY)NULL, 0, NULL);
	if (!hCertStore)
		goto Ret;


	rv = md_get_objects(vs, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0) {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
		dwret = md_translate_OpenSC_to_Windows_error(rv, dwret);
		goto Ret;
	}
	cert_num = rv;

	for (ii = 0; ii < cert_num; ii++) {
		struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) prkey_objs[ii]->data;
		struct sc_pkcs15_cert *cert = NULL;
		PCCERT_CONTEXT wincert = NULL;
		if (cert_info->authority) {
			rv = md_pkcs15_read_certificate(prkey_objs[ii]->p15card, cert_info, &cert);
			if (rv) {
				logprintf(pCardData, 2, "Cannot read certificate idx:%i: sc-error %d\n", ii, rv);
				continue;
			}
			wincert = CertCreateCertificateContext(X509_ASN_ENCODING, cert->data.value, (DWORD)cert->data.len);
			if (wincert) {
				CertAddCertificateContextToStore(hCertStore, wincert, CERT_STORE_ADD_REPLACE_EXISTING, NULL);
				CertFreeCertificateContext(wincert);
			}
			else {
				logprintf(pCardData, 2,
					"unable to load the certificate from Windows 0x%08X\n",
					(unsigned int)GetLastError());
			}
			sc_pkcs15_free_certificate(cert);
		}
	}
	if (FALSE == CertSaveStore(hCertStore,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		CERT_STORE_SAVE_AS_PKCS7,
		CERT_STORE_SAVE_TO_MEMORY,
		&dbStore,
		0)) {
		goto Ret;
	}

	dbStore.pbData = (PBYTE)pCardData->pfnCspAlloc(dbStore.cbData);

	if (NULL == dbStore.pbData) {
		dwret = SCARD_E_NO_MEMORY;
		goto Ret;
	}

	if (FALSE == CertSaveStore(hCertStore,
		PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
		CERT_STORE_SAVE_AS_PKCS7,
		CERT_STORE_SAVE_TO_MEMORY,
		&dbStore,
		0))
	{
		dwret = GetLastError();
		goto Ret;
	}
	file->size = dbStore.cbData;
	file->blob = dbStore.pbData;
	dbStore.pbData = NULL;
	dwret = SCARD_S_SUCCESS;

Ret:
	if (dbStore.pbData)
		pCardData->pfnCspFree(dbStore.pbData);
	if (hCertStore)
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_FORCE_FLAG);

	return dwret;
}

/*
 * Return content of the 'soft' file.
 */
static DWORD
md_fs_read_content(PCARD_DATA pCardData, char *parent, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	DWORD dwret;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs || !vs->fws_data[0] || !vs->fws_data[0]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_find_directory(pCardData, NULL, parent, &dir);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "find directory '%s' error: %lX\n",
			parent ? parent : "<null>", (unsigned long)dwret);
		return dwret;
	}
	else if (!dir) {
		logprintf(pCardData, 2, "directory '%s' not found\n", parent ? parent : "<null>");
		return SCARD_E_DIR_NOT_FOUND;
	}

	if (!stricmp((char *)dir->name, "mscp")) {
		int idx, rv;

		if (sscanf_s((char *)file->name, "ksc%d", &idx) > 0) {
		}
		else if (sscanf_s((char *)file->name, "kxc%d", &idx) > 0) {
		}
		else {
			idx = -1;
		}

		if (idx >= 0 && idx < MD_MAX_KEY_CONTAINERS && vs->p15_containers[idx].cert_obj) {
			struct sc_pkcs15_cert *cert = NULL;
			struct sc_pkcs15_object *cert_obj = vs->p15_containers[idx].cert_obj;
			struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *)cert_obj->data;

			rv = md_pkcs15_read_certificate(cert_obj->p15card, cert_info, &cert);
			if (rv) {
				logprintf(pCardData, 2, "Cannot read certificate idx:%i: sc-error %d\n", idx, rv);
				logprintf(pCardData, 2, "set cardcf from 'DATA' pkcs#15 object\n");
				return md_translate_OpenSC_to_Windows_error(rv,
					SCARD_F_INTERNAL_ERROR);
			}

			file->blob = pCardData->pfnCspAlloc(cert->data.len);
			if (file->blob) {
				CopyMemory(file->blob, cert->data.value, cert->data.len);
				file->size = cert->data.len;
				dwret = SCARD_S_SUCCESS;
			}
			else
				dwret = SCARD_E_NO_MEMORY;

			sc_pkcs15_free_certificate(cert);

			return dwret;
		}
		else if (!_stricmp((char *)file->name, "msroots"))
			return md_fs_read_msroots_file(pCardData, file);
	}

	return SCARD_E_FILE_NOT_FOUND;
}

static const unsigned char LatviaV2_ADF_QSCD[] = {
		0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61,
		0x74, 0x69, 0x6F, 0x6E
};

static const unsigned char LatviaV2_ADF_AWP[] = {
	0xE8, 0x28, 0xBD, 0x08, 0x0F, 0xF2, 0x50, 0x4F, 0x54, 0x20, 0x41, 0x57,
	0x50
};


static int latvia_select_ADF(struct sc_card *card, const unsigned char* pbAID, size_t cbAID)
{
	struct sc_path path;

	memset(&path, 0, sizeof(path));
	path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(path.value, pbAID, cbAID);
	path.len = cbAID;
	
	return sc_select_file(card, &path, NULL);
}

static int latvia_read_file(struct sc_card *card, unsigned short efid, unsigned char** ppbData, size_t *pcbData)
{
	struct sc_path path;
	struct sc_file *file = NULL;
	char szEfid[5];
	int r;

	sprintf(szEfid, "%.4X", efid);
	sc_format_path(szEfid, &path);

	r = sc_select_file(card, &path, &file);
	if (r >= 0)
	{
		*ppbData = (unsigned char*)malloc(file->size);
		r = sc_read_binary(card, 0, *ppbData, file->size, 0);
		if (r < 0)
		{
			free(*ppbData);
			*ppbData = NULL;
			*pcbData = 0;
		}
		else
			*pcbData = file->size;
	}
	else
	{
		*ppbData = NULL;
		*pcbData = 0;
	}

	sc_file_free(file);
	return r;
}

/*
 * Set content of 'cardcf',
 * for that look for the possible source in the following order:
 * - data from the dedicated PKCS#15 'DATA' object;
 * - 'lastUpdate' attribute of tokenInfo;
 * - random data.
 */
static DWORD
md_set_cardcf(PCARD_DATA pCardData, struct md_file *file)
{
	VENDOR_SPECIFIC *vs;
	CARD_CACHE_FILE_FORMAT empty = { 0 };
	DWORD dwret;
	const DWORD g_CardCfHashVersion = 0x30112018; // enables changing CardCF if something changes in mapping of content
	unsigned char hash[20];
	SHA_CTX ctx;
	int ii;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs || !vs->fws_data[0] || !vs->fws_data[0]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_set_content(pCardData, file, (unsigned char *)(&empty), MD_CARDCF_LENGTH);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	SHA1_Init(&ctx);

	for (ii = 0; ii < 4; ii++)
	{
		char* last_update;
		sc_pkcs15_tokeninfo_t *tokeninfo;

		if (!vs->fws_data[ii])
			break;
		tokeninfo = vs->fws_data[ii]->p15card->tokeninfo;
		last_update = tokeninfo->last_update.gtime;		
		if (last_update)
			SHA1_Update(&ctx, last_update, strlen(last_update));	

		// 
		// V1 cards don't have CKF_WRITE_PROTECTED flag set and maximum PIN length is set to 64
		// so V2 cards are those without these characteristics
		if ((tokeninfo->flags & SC_PKCS15_TOKEN_READONLY))
		{
			// select 
			struct sc_card *card = vs->fws_data[ii]->p15card->card;
			WORD lastUpdateEfid = 0x5040;

			int r = latvia_select_ADF(card, LatviaV2_ADF_AWP, sizeof(LatviaV2_ADF_AWP));
			if (r == SCARD_S_SUCCESS)
			{
				unsigned char* pbData = NULL;
				size_t cbData = 0;
				r = latvia_read_file(card, lastUpdateEfid, &pbData, &cbData);
				if (r >= 0)
				{
					SHA1_Update(&ctx, pbData, cbData);
					free(pbData);

					// read second EF only if reading the first succeeded
					r = latvia_select_ADF(card, LatviaV2_ADF_QSCD, sizeof(LatviaV2_ADF_QSCD));
					if (r == SCARD_S_SUCCESS)
					{
						pbData = NULL;
						cbData = 0;
						r = latvia_read_file(card, lastUpdateEfid, &pbData, &cbData);
						if (r >= 0)
						{
							SHA1_Update(&ctx, pbData, cbData);
							free(pbData);
						}
					}
				}
			}
		}
	}

	SHA1_Update(&ctx, &g_CardCfHashVersion, sizeof(g_CardCfHashVersion));
	SHA1_Final(hash, &ctx);
	memcpy(file->blob + 2, hash, 4);

	logprintf(pCardData, 3, "'cardcf' content(%"SC_FORMAT_LEN_SIZE_T"u)\n",
		file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/*
 * Return content of the 'soft' 'cardcf' file
 */
static DWORD
md_get_cardcf(PCARD_DATA pCardData, CARD_CACHE_FILE_FORMAT **out)
{
	struct md_file *file = NULL;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	md_fs_find_file(pCardData, NULL, "cardcf", &file);
	if (!file)   {
		logprintf(pCardData, 2, "file 'cardcf' not found\n");
		return SCARD_E_FILE_NOT_FOUND;
	}
	if (!file->blob || file->size < MD_CARDCF_LENGTH)
		return SCARD_E_INVALID_VALUE;
	if (out)
		*out = (CARD_CACHE_FILE_FORMAT *)file->blob;

	return SCARD_S_SUCCESS;
}


static DWORD
md_set_cardapps(PCARD_DATA pCardData, struct md_file *file)
{
	DWORD dwret;
	unsigned char mscp[8] = { 'm','s','c','p',0,0,0,0 };

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_set_content(pCardData, file, mscp, sizeof(mscp));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "mscp(%"SC_FORMAT_LEN_SIZE_T"u)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/* check if the card has root certificates. If yes, notify the base csp by creating the msroots file */
static DWORD
md_fs_add_msroots(PCARD_DATA pCardData, struct md_file **head)
{
	VENDOR_SPECIFIC *vs;
	int rv, ii, cert_num;
	DWORD dwret;
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	if (!pCardData || !head)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC *)pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	rv = md_get_objects(vs, SC_PKCS15_TYPE_CERT_X509, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0) {
		logprintf(pCardData, 0, "certificate enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_S_SUCCESS;
	}
	cert_num = rv;
	for (ii = 0; ii < cert_num; ii++) {
		struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) prkey_objs[ii]->data;
		if (cert_info->authority) {
			dwret = md_fs_add_file(pCardData, head, "msroots", EveryoneReadUserWriteAc, NULL, 0, NULL);
			if (dwret != SCARD_S_SUCCESS)
				return dwret;
			return SCARD_S_SUCCESS;
		}
	}
	return SCARD_S_SUCCESS;
}

/*
 * Set the content of the 'soft' 'cmapfile':
 * 1. Initialize internal p15_contaniers with the existing private keys PKCS#15 objects;
 * 2. Try to read the content of the PKCS#15 'DATA' object 'CSP':'cmapfile',
 *		If some record from the 'DATA' object references an existing key:
 *    2a. Update the non-pkcs#15 attributes of the corresponding internal p15_container;
 *    2b. Change the index of internal p15_container according to the index from 'DATA' file.
 *	  Records from 'DATA' file are ignored is they do not have
 *		the corresponding PKCS#15 private key object.
 * 3. Initialize the content of the 'soft' 'cmapfile' from the internal p15-containers.
 */
static DWORD
md_set_cmapfile(PCARD_DATA pCardData, struct md_file *file)
{
	typedef enum {
		SCF_NONE,
		SCF_NONDEFAULT_SIGN_PIN,
		SCF_NONDEFAULT_OTHER_PIN,
		SCF_NONDEFAULT_USER_PIN,
		SCF_DEFAULT_SIGN_PIN,
		SCF_DEFAULT_OTHER_PIN,
		SCF_DEFAULT_USER_PIN
	} pin_mode_t;
	VENDOR_SPECIFIC *vs;
	PCONTAINER_MAP_RECORD p;
	sc_pkcs15_pubkey_t *pubkey = NULL;
	struct sc_pkcs15_cert *cert = NULL;
	unsigned char *cmap_buf = NULL;
	size_t cmap_len;
	DWORD dwret;
	int ii, jj, rv, prkey_num, conts_num, found_default = 0;
	/* struct sc_pkcs15_data *data_object; */
	struct sc_pkcs15_object *prkey_objs[MD_MAX_KEY_CONTAINERS];
	struct md_pkcs15_container tmp_container;
	pin_mode_t pin_mode = SCF_NONE;
	int pin_cont_idx = -1;

	if (!pCardData || !file)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 2, "set 'cmapfile'\n");
	vs = pCardData->pvVendorSpecific;
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_get_pin_by_role(pCardData, ROLE_USER, &vs->pin_objs[ROLE_USER]);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		return dwret;
	}

	dwret = md_get_pin_by_role(pCardData, MD_ROLE_USER_SIGN, &vs->pin_objs[MD_ROLE_USER_SIGN]);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "Cannot get Sign PIN object -- ignored");
		vs->pin_objs[MD_ROLE_USER_SIGN] = NULL;
	}

	dwret = md_get_pin_by_role(pCardData, ROLE_ADMIN, &vs->pin_objs[ROLE_ADMIN]);
	if (dwret != SCARD_S_SUCCESS) {
		logprintf(pCardData, 2, "Cannot get Admin PIN object -- ignored");
		vs->pin_objs[ROLE_ADMIN] = NULL;
	}

	cmap_len = MD_MAX_KEY_CONTAINERS * sizeof(CONTAINER_MAP_RECORD);
	cmap_buf = pCardData->pfnCspAlloc(cmap_len);
	if (!cmap_buf)
		return SCARD_E_NO_MEMORY;
	memset(cmap_buf, 0, cmap_len);

	rv = md_get_objects(vs, SC_PKCS15_TYPE_PRKEY, prkey_objs, MD_MAX_KEY_CONTAINERS);
	if (rv < 0) {
		logprintf(pCardData, 0, "Private key enumeration failed: %s\n", sc_strerror(rv));
		return SCARD_F_UNKNOWN_ERROR;
	}

	prkey_num = rv;
	conts_num = 0;

	logprintf(pCardData, 2, "Found %d private key(s) in the card.\n", conts_num);

	/* Initialize the P15 container array with the existing keys */
	for (ii = 0; ii < prkey_num; ii++) {
		struct sc_pkcs15_object *key_obj = prkey_objs[ii];
		struct sc_pkcs15_prkey_info *prkey_info = (struct sc_pkcs15_prkey_info *)key_obj->data;
		struct md_pkcs15_container *cont = &vs->p15_containers[ii];
		struct sc_pkcs15_der pubkey_der;
		struct sc_pkcs15_der cert_pubkey_der;

		pubkey_der.value = NULL;
		pubkey_der.len = 0;
		cert_pubkey_der.value = NULL;
		cert_pubkey_der.len = 0;

		if (key_obj->type != SC_PKCS15_TYPE_PRKEY_RSA && key_obj->type != SC_PKCS15_TYPE_PRKEY_EC) {
			logprintf(pCardData, 7, "Non 'RSA' 'EC' key (type:%X) are ignored\n", key_obj->type);
			continue;
		}

		dwret = md_contguid_build_cont_guid_from_key(pCardData, key_obj, cont->guid);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;

		/* replace the OpenSC guid by a Windows Guid if needed
		Typically used in the certificate enrollment process.
		Windows create a new container with a Windows guid, close the context, then create a new context and look for the previous container.
		If we return our guid, it fails because the Windows guid can't be found.
		The overwrite is present to avoid this conversion been replaced by md_pkcs15_update_container_from_do*/
		// cont->guid_overwrite = md_contguid_find_conversion(pCardData, cont->guid);

		// cont->flags = CONTAINER_MAP_VALID_CONTAINER;
		dwret = md_cont_flags_from_key(pCardData, key_obj, &cont->flags);
		if (dwret != SCARD_S_SUCCESS)
			return dwret;

		logprintf(pCardData, 7, "Container[%i] is '%.*s' guid=%.*s\n", ii,
			(int) sizeof key_obj->label, key_obj->label,
			(int) sizeof cont->guid, cont->guid);

		if (cont->flags & CONTAINER_MAP_VALID_CONTAINER &&
			key_obj->auth_id.len > 0) {
			struct sc_pkcs15_object *keypin_obj;
			struct sc_pkcs15_auth_info *userpin_info =
				(struct sc_pkcs15_auth_info *)vs->pin_objs[ROLE_USER]->data;
			struct sc_pkcs15_auth_info *signpin_info =
				vs->pin_objs[MD_ROLE_USER_SIGN] ?
				(struct sc_pkcs15_auth_info *)vs->pin_objs[MD_ROLE_USER_SIGN]->data :
				NULL;
			struct sc_pkcs15_auth_info *adminpin_info =
				vs->pin_objs[ROLE_ADMIN] ?
				(struct sc_pkcs15_auth_info *)vs->pin_objs[ROLE_ADMIN]->data :
				NULL;

			if (sc_pkcs15_find_pin_by_auth_id(key_obj->p15card, &key_obj->auth_id, &keypin_obj))
				logprintf(pCardData, 2,
					"Container[%i] has an unknown auth id, might not work properly\n",
					ii);
			else {
				size_t pinidx;
				size_t pinidxempty = MD_MAX_PINS;
				for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
					struct sc_pkcs15_auth_info *pin_info;

					if (!vs->pin_objs[pinidx]) {
						if (pinidxempty >= MD_MAX_PINS)
							pinidxempty = pinidx;

						continue;
					}

					pin_info =
						(struct sc_pkcs15_auth_info *)vs->pin_objs[pinidx]->data;

					if (sc_pkcs15_compare_id(&key_obj->auth_id,
						&pin_info->auth_id))
						break;
				}

				if (pinidx >= MD_MAX_PINS) {
					if (pinidxempty >= MD_MAX_PINS)
						logprintf(pCardData, 2,
							"no free slot for container[%i] auth id, might not work properly\n",
							ii);
					else
						vs->pin_objs[pinidxempty] = keypin_obj;
				}

				if (sc_pkcs15_compare_id(&key_obj->auth_id, &userpin_info->auth_id)) {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_USER_PIN : SCF_NONDEFAULT_USER_PIN;

					logprintf(pCardData, 7,
						"Container[%i]%s is secured by User PIN\n",
						ii,
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						" (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				}
				else if (signpin_info != NULL &&
					sc_pkcs15_compare_id(&key_obj->auth_id, &signpin_info->auth_id)) {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_SIGN_PIN : SCF_NONDEFAULT_SIGN_PIN;

					logprintf(pCardData, 7,
						"Container[%i]%s is secured by Sign PIN\n",
						ii,
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						" (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				}
				else if (adminpin_info != NULL &&
					sc_pkcs15_compare_id(&key_obj->auth_id, &adminpin_info->auth_id)) {
					logprintf(pCardData, 2,
						"Container[%i] is secured by Admin PIN, might not work properly\n",
						ii);
				}
				else {
					pin_mode_t pin_mode_n =
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						SCF_DEFAULT_OTHER_PIN : SCF_NONDEFAULT_OTHER_PIN;

					logprintf(pCardData, 7,
						"Container[%i]%s is secured by other PIN\n",
						ii,
						cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER ?
						" (default)" : "");

					if (pin_mode < pin_mode_n) {
						pin_mode = pin_mode_n;
						pin_cont_idx = ii;
					}
				}
			}
		}

		if (cont->flags & CONTAINER_MAP_VALID_CONTAINER &&
			cont->flags & CONTAINER_MAP_DEFAULT_CONTAINER)
			found_default = 1;

		/* AT_KEYEXCHANGE is more general key usage,
		 *	it allows 'decryption' as well as 'signature' key usage.
		 * AT_SIGNATURE allows only 'signature' usage.
		 */
		cont->size_key_exchange = cont->size_sign = 0;
		if (key_obj->type == SC_PKCS15_TYPE_PRKEY_RSA) {
			if (prkey_info->usage & USAGE_ANY_DECIPHER)
				cont->size_key_exchange = prkey_info->modulus_length;
			else if (prkey_info->usage & USAGE_ANY_SIGN)
				cont->size_sign = prkey_info->modulus_length;
			else
				cont->size_key_exchange = prkey_info->modulus_length;
		}
		else if (key_obj->type == SC_PKCS15_TYPE_PRKEY_EC) {
			if (prkey_info->usage & USAGE_ANY_AGREEMENT)
				cont->size_key_exchange = prkey_info->field_length;
			else if (prkey_info->usage & USAGE_ANY_SIGN)
				cont->size_sign = prkey_info->field_length;
			else
				cont->size_key_exchange = prkey_info->field_length;
		}

		logprintf(pCardData, 7,
			"Container[%i]'s key-exchange:%"SC_FORMAT_LEN_SIZE_T"u, sign:%"SC_FORMAT_LEN_SIZE_T"u\n",
			ii, cont->size_key_exchange, cont->size_sign);

		cont->id = prkey_info->id;
		cont->prkey_obj = prkey_objs[ii];
		cont->non_repudiation = (SC_PKCS15_PRKEY_USAGE_NONREPUDIATION & prkey_info->usage)? TRUE: FALSE;
		cont->key_derivation = (SC_PKCS15_PRKEY_USAGE_DERIVE & prkey_info->usage)? TRUE: FALSE;
		cont->p15card = cont->prkey_obj->p15card;

		/* Try to find the friend objects: certificate and public key */
		if (!sc_pkcs15_find_cert_by_id(cont->p15card, &cont->id, &cont->cert_obj))
			logprintf(pCardData, 2, "found certificate friend '%.*s'\n", (int) sizeof cont->cert_obj->label, cont->cert_obj->label);

		if (!sc_pkcs15_find_pubkey_by_id(cont->p15card, &cont->id, &cont->pubkey_obj))
			logprintf(pCardData, 2, "found public key friend '%.*s'\n", (int) sizeof cont->pubkey_obj->label, cont->pubkey_obj->label);

		if (sc_pkcs15_read_pubkey(cont->p15card, cont->pubkey_obj, &pubkey))
		{
			cont->pubkey_obj = NULL;
		}
		else
		{
			size_t minPubKeyLen = (key_obj->type == SC_PKCS15_TYPE_PRKEY_RSA) ? (prkey_info->modulus_length + 7) / 8 : (prkey_info->field_length + 7) / 8;
			if (sc_pkcs15_encode_pubkey(vs->ctx, pubkey, &pubkey_der.value, &pubkey_der.len))
				cont->pubkey_obj = NULL;
			/* check public key DER coherance*/
			if (pubkey_der.len <= minPubKeyLen)
			{
				cont->pubkey_obj = NULL;
			}
			sc_pkcs15_free_pubkey(pubkey);
			pubkey = NULL;
		}

		if (cont->cert_obj)
		{
			if (md_pkcs15_read_certificate(cont->p15card, (struct sc_pkcs15_cert_info *)(cont->cert_obj->data), &cert))
			{
				cont->cert_obj = NULL;
			}
			else
			{
				size_t minPubKeyLen = (key_obj->type == SC_PKCS15_TYPE_PRKEY_RSA) ? (prkey_info->modulus_length + 7) / 8 : (prkey_info->field_length + 7) / 8;
				if (sc_pkcs15_encode_pubkey(vs->ctx, cert->key, &cert_pubkey_der.value, &cert_pubkey_der.len))
					cont->cert_obj = NULL;
				/* check public key DER coherance*/
				if (cert_pubkey_der.len <= minPubKeyLen)
				{
					cont->cert_obj = NULL;
				}
				sc_pkcs15_free_certificate(cert);
				cert = NULL;
			}
		}

		if (cont->pubkey_obj || cont->cert_obj)
		{
			conts_num++;
			if (!cont->prkey_obj->content.value)
			{
				sc_der_copy(&cont->prkey_obj->content, cert_pubkey_der.value? &cert_pubkey_der : &pubkey_der);
			}
		}
		else
		{
			memset (cont, 0, sizeof (struct md_pkcs15_container));
		}

		if (cert_pubkey_der.value)
			free (cert_pubkey_der.value);
		if (pubkey_der.value)
			free (pubkey_der.value);
	}

	if (conts_num) {
		/* Read 'CMAPFILE' (Gemalto style) and update the attributes of P15 containers */

        /* put exchange keys first */
        for (ii=0; ii<conts_num; ii++)   {
            if (vs->p15_containers[ii].size_sign && ((ii+1) < conts_num))
            {
                for (jj = (conts_num-1); jj > ii; jj--) {
                    if (vs->p15_containers[jj].size_key_exchange) {
                        tmp_container = vs->p15_containers[ii];
                        vs->p15_containers[ii] = vs->p15_containers[jj];
                        vs->p15_containers[jj] = tmp_container;

						if (pin_cont_idx >= 0 && (pin_cont_idx == ii || pin_cont_idx == jj))
						{
							if (pin_cont_idx == ii)
								pin_cont_idx = jj;
							else
								pin_cont_idx = ii;
						}
                        break;
                    }
                }

                if (jj == ii)
                    break;
            }
        }

        /* put non repudiation keys last */
        for (ii=0; ii<conts_num; ii++)   {
            if (vs->p15_containers[ii].non_repudiation && ((ii+1) < conts_num))
            {
                for (jj = (conts_num-1); jj > ii; jj--) {
                    if (!vs->p15_containers[jj].non_repudiation) {
                        tmp_container = vs->p15_containers[ii];
                        vs->p15_containers[ii] = vs->p15_containers[jj];
                        vs->p15_containers[jj] = tmp_container;
						if (pin_cont_idx >= 0 && (pin_cont_idx == ii || pin_cont_idx == jj))
						{
							if (pin_cont_idx == ii)
								pin_cont_idx = jj;
							else
								pin_cont_idx = ii;
						}
                        break;
                    }
                }

                if (jj == ii)
                    break;
            }
		}


		/* if no default container was found promote the best one (PIN-wise) to default */
		if (!found_default && (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
			pin_mode == SCF_NONDEFAULT_OTHER_PIN ||
			pin_mode == SCF_NONDEFAULT_USER_PIN)) {
			struct md_pkcs15_container *cont =
				&vs->p15_containers[pin_cont_idx];
			cont->flags |= CONTAINER_MAP_DEFAULT_CONTAINER;

			found_default = 1;

			logprintf(pCardData, 7,
				"Container[%i] promoted to default\n",
				pin_cont_idx);

			if (pin_mode == SCF_NONDEFAULT_SIGN_PIN)
				pin_mode = SCF_DEFAULT_SIGN_PIN;
			else if (pin_mode == SCF_NONDEFAULT_OTHER_PIN)
				pin_mode = SCF_DEFAULT_OTHER_PIN;
			else
				pin_mode = SCF_DEFAULT_USER_PIN;
		}

		/* if all containers use non-user PINs we need to make the best container PIN the user (primary) one */
		if (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
			pin_mode == SCF_DEFAULT_SIGN_PIN ||
			pin_mode == SCF_NONDEFAULT_OTHER_PIN ||
			pin_mode == SCF_DEFAULT_OTHER_PIN) {
			struct sc_pkcs15_object *user_pin_old =
				vs->pin_objs[ROLE_USER];
			struct sc_pkcs15_object *user_pin_new =
				NULL;

			if (pin_mode == SCF_NONDEFAULT_SIGN_PIN ||
				pin_mode == SCF_DEFAULT_SIGN_PIN) {
				user_pin_new = vs->pin_objs[MD_ROLE_USER_SIGN];
				vs->pin_objs[MD_ROLE_USER_SIGN] = NULL;

				logprintf(pCardData, 7,
					"Sign PIN%s promoted to user one\n",
					pin_mode == SCF_DEFAULT_SIGN_PIN ?
					" (from default container)" : "");
			}
			else {
				struct sc_pkcs15_object *key_obj =
					vs->p15_containers[pin_cont_idx].prkey_obj;
				struct sc_pkcs15_object *keypin_obj;

				if (sc_pkcs15_find_pin_by_auth_id(key_obj->p15card, &key_obj->auth_id, &keypin_obj))
					logprintf(pCardData, 2,
						"Cannot find container[%i] auth id again, might not work properly\n",
						pin_cont_idx);
				else {
					size_t pinidx;

					logprintf(pCardData, 7,
						"Container[%i]%s PIN will be made the user one\n",
						pin_cont_idx,
						pin_mode == SCF_DEFAULT_OTHER_PIN ?
						" (default)" : "");

					for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
						struct sc_pkcs15_auth_info *pin_info;

						if (!vs->pin_objs[pinidx])
							continue;

						pin_info =
							(struct sc_pkcs15_auth_info *)vs->pin_objs[pinidx]->data;

						if (sc_pkcs15_compare_id(&key_obj->auth_id,
							&pin_info->auth_id)) {
							vs->pin_objs[pinidx] = NULL;
							break;
						}
					}

					user_pin_new = keypin_obj;
				}
			}

			if (user_pin_new) {
				size_t pinidx;

				vs->pin_objs[ROLE_USER] = user_pin_new;

				for (pinidx = 0; pinidx < MD_MAX_PINS; pinidx++) {
					if (vs->pin_objs[pinidx])
						continue;

					vs->pin_objs[pinidx] = user_pin_old;
					break;
				}

				if (pinidx >= MD_MAX_PINS) {
					logprintf(pCardData, 2,
						"no free slot for previous User PIN, replacing last one\n");

					vs->pin_objs[MD_MAX_PINS - 1] = user_pin_old;
				}
			}
		}

		/* Initialize 'CMAPFILE' content from the P15 containers */
		p = (PCONTAINER_MAP_RECORD)cmap_buf;
		for (ii = 0; ii < MD_MAX_KEY_CONTAINERS; ii++) {
			if (!(vs->p15_containers[ii].flags & CONTAINER_MAP_VALID_CONTAINER))
				continue;

			if (!found_default) {
				vs->p15_containers[ii].flags |= CONTAINER_MAP_DEFAULT_CONTAINER;
				found_default = 1;
			}

			mbstowcs((p + ii)->wszGuid, vs->p15_containers[ii].guid, MAX_CONTAINER_NAME_LEN + 1);
			(p + ii)->bFlags = vs->p15_containers[ii].flags;
			(p + ii)->wSigKeySizeBits = (WORD)vs->p15_containers[ii].size_sign;
			(p + ii)->wKeyExchangeKeySizeBits = (WORD)vs->p15_containers[ii].size_key_exchange;

			if (vs->p15_containers[ii].cert_obj) {
				char k_name[6];
				struct sc_pkcs15_cert *cert = NULL;
				struct sc_pkcs15_object *cert_obj = vs->p15_containers[ii].cert_obj;
				struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *)cert_obj->data;

				rv = md_pkcs15_read_certificate(cert_obj->p15card, cert_info, &cert);
				if (!rv)
				{
					dwret = SCARD_S_SUCCESS;
					if (vs->p15_containers[ii].size_key_exchange) {
						snprintf(k_name, sizeof(k_name), "kxc%02i", ii);
						k_name[sizeof(k_name) - 1] = 0;
						dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, cert->data.value, cert->data.len, NULL);
					}

					if (vs->p15_containers[ii].size_sign) {
						snprintf(k_name, sizeof(k_name), "ksc%02i", ii);
						k_name[sizeof(k_name) - 1] = 0;
						dwret = md_fs_add_file(pCardData, &(file->next), k_name, file->acl, cert->data.value, cert->data.len, NULL);
					}

					sc_pkcs15_free_certificate(cert);

					if (dwret != SCARD_S_SUCCESS)
						return dwret;
				}
			}

			logprintf(pCardData, 7, "cmapfile entry(%d) '%s' ", ii, vs->p15_containers[ii].guid);
			loghex(pCardData, 7, (PBYTE)(p + ii), sizeof(CONTAINER_MAP_RECORD));
		}
	}

	dwret = md_fs_add_msroots(pCardData, &(file->next));
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	dwret = md_fs_set_content(pCardData, file, cmap_buf, cmap_len);
	pCardData->pfnCspFree(cmap_buf);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	logprintf(pCardData, 3, "cmap(%"SC_FORMAT_LEN_SIZE_T"u)\n", file->size);
	loghex(pCardData, 3, file->blob, file->size);
	return SCARD_S_SUCCESS;
}

/*
 * Initialize internal 'soft' file system
 */
static DWORD
md_fs_init(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	struct md_file *cardid, *cardcf, *cardapps, *cmapfile;
	struct md_directory *mscp;

	if (!pCardData || !pCardData->pvVendorSpecific)
		return SCARD_E_INVALID_PARAMETER;

	vs = pCardData->pvVendorSpecific;
	if (!vs || !vs->fws_data[0] || !vs->fws_data[0]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardid", EveryoneReadAdminWriteAc, NULL, 0, &cardid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;
	dwret = md_set_cardid(pCardData, cardid);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardcf", EveryoneReadUserWriteAc, NULL, 0, &cardcf);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cardcf(pCardData, cardcf);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(vs->root.files), "cardapps", EveryoneReadAdminWriteAc, NULL, 0, &cardapps);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cardapps(pCardData, cardapps);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_directory(pCardData, &(vs->root.subdirs), "mscp", UserCreateDeleteDirAc, &mscp);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

	dwret = md_fs_add_file(pCardData, &(mscp->files), "cmapfile", EveryoneReadUserWriteAc, NULL, 0, &cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;
	dwret = md_set_cmapfile(pCardData, cmapfile);
	if (dwret != SCARD_S_SUCCESS)
		goto ret_cleanup;

#ifdef OPENSSL_VERSION_NUMBER
	logprintf(pCardData, 3,
		"MD virtual file system initialized; OPENSSL_VERSION_NUMBER 0x%lX\n",
		OPENSSL_VERSION_NUMBER);
#else
	logprintf(pCardData, 3,
		"MD virtual file system initialized; Without OPENSSL\n");
#endif
	return SCARD_S_SUCCESS;

ret_cleanup:
	md_fs_finalize(pCardData);
	return dwret;
}

/* Create SC context */
static DWORD
md_create_context(PCARD_DATA pCardData, VENDOR_SPECIFIC *vs)
{
	sc_context_param_t ctx_param;
	int r;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 3, "create sc ccontext\n");
	vs->ctx = NULL;

	memset(&ctx_param, 0, sizeof(ctx_param));
	ctx_param.ver = 1;
	ctx_param.app_name = "cardmod";

	r = sc_context_create(&(vs->ctx), &ctx_param);
	if (r) {
		logprintf(pCardData, 0, "Failed to establish context: %s\n", sc_strerror(r));
		return SCARD_F_UNKNOWN_ERROR;
	}

	logprintf(pCardData, 3, "sc context created\n");
	return SCARD_S_SUCCESS;
}

static DWORD
md_card_capabilities(PCARD_DATA pCardData, PCARD_CAPABILITIES  pCardCapabilities)
{
	if (!pCardCapabilities)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardCapabilities->dwVersion != CARD_CAPABILITIES_CURRENT_VERSION && pCardCapabilities->dwVersion != 0)
		return ERROR_REVISION_MISMATCH;

	pCardCapabilities->dwVersion = CARD_CAPABILITIES_CURRENT_VERSION;
	pCardCapabilities->fCertificateCompression = TRUE;
	/* a read only card cannot generate new keys */
	pCardCapabilities->fKeyGen = !md_is_read_only(pCardData);

	return SCARD_S_SUCCESS;
}

static DWORD
md_free_space(PCARD_DATA pCardData, PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	int count, idx;

	if (!pCardData || !pCardFreeSpaceInfo)
		return SCARD_E_INVALID_PARAMETER;

	if (pCardFreeSpaceInfo->dwVersion > CARD_FREE_SPACE_INFO_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	/* Count free containers */
	for (idx = 0, count = 0; idx < MD_MAX_KEY_CONTAINERS; idx++)
		if (!vs->p15_containers[idx].prkey_obj)
			count++;

	pCardFreeSpaceInfo->dwVersion = CARD_FREE_SPACE_INFO_CURRENT_VERSION;
	pCardFreeSpaceInfo->dwBytesAvailable = CARD_DATA_VALUE_UNKNOWN;
	pCardFreeSpaceInfo->dwKeyContainersAvailable = count;
	pCardFreeSpaceInfo->dwMaxKeyContainers = MD_MAX_KEY_CONTAINERS;

	return SCARD_S_SUCCESS;
}

/* Check the new key to be created for the compatibility with card:
 * - for the key to be generated the card needs to support the mechanism and size;
 * - for the key to be imported checked also the validity of supplied key blob.
 */
static DWORD
md_check_key_compatibility(PCARD_DATA pCardData, struct sc_pkcs15_card *p15card,
	DWORD flags, DWORD key_type,
	DWORD key_size, BYTE *pbKeyData)
{
	VENDOR_SPECIFIC *vs;
	struct sc_algorithm_info *algo_info;
	unsigned int count, key_algo;

	if (!pCardData || p15card)
		return SCARD_E_INVALID_PARAMETER;

	switch (key_type) {
	case AT_SIGNATURE:
	case AT_KEYEXCHANGE:
		key_algo = SC_ALGORITHM_RSA;
		break;
	case AT_ECDHE_P256:
	case AT_ECDHE_P384:
	case AT_ECDHE_P521:
	case AT_ECDSA_P256:
	case AT_ECDSA_P384:
	case AT_ECDSA_P521:
		key_algo = SC_ALGORITHM_EC;
		break;
	default:
		logprintf(pCardData, 3, "Unsupported key type: 0x%lX\n",
			(unsigned long)key_type);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (flags & CARD_CREATE_CONTAINER_KEY_IMPORT) {
		if (key_algo == SC_ALGORITHM_RSA) {
			PUBLICKEYSTRUC *pub_struc = (PUBLICKEYSTRUC *)pbKeyData;
			RSAPUBKEY *pub_rsa = (RSAPUBKEY *)(pbKeyData + sizeof(PUBLICKEYSTRUC));

			if (!pub_struc) {
				logprintf(pCardData, 3, "No data for the key import operation\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if (pub_struc->bType != PRIVATEKEYBLOB) {
				logprintf(pCardData, 3, "Invalid blob data for the key import operation\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if ((key_type == AT_KEYEXCHANGE) && (pub_struc->aiKeyAlg != CALG_RSA_KEYX)) {
				logprintf(pCardData, 3, "Expected KEYEXCHANGE type of blob\n");
				return SCARD_E_INVALID_PARAMETER;
			}
			else if ((key_type == AT_SIGNATURE) && (pub_struc->aiKeyAlg != CALG_RSA_SIGN)) {
				logprintf(pCardData, 3, "Expected KEYSIGN type of blob\n");
				return SCARD_E_INVALID_PARAMETER;
			}

			if (pub_rsa->magic == BCRYPT_RSAPUBLIC_MAGIC || pub_rsa->magic == BCRYPT_RSAPRIVATE_MAGIC) {
				key_size = pub_rsa->bitlen;
			}
			else {
				logprintf(pCardData, 3, "'Magic' control failed\n");
				return SCARD_E_INVALID_PARAMETER;
			}

			logprintf(pCardData, 3, "Set key size to %lu\n",
				(unsigned long)key_size);
		}
		else if (key_algo == SC_ALGORITHM_EC) {
			BCRYPT_ECCKEY_BLOB *pub_ecc = (BCRYPT_ECCKEY_BLOB *)pbKeyData;
			switch (key_type) {
			case AT_ECDSA_P256:
				if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDSA_P256 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 256;
				break;
			case AT_ECDSA_P384:
				if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P384_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDSA_P384 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 384;
				break;
			case AT_ECDSA_P521:
				if (pub_ecc->dwMagic != BCRYPT_ECDSA_PRIVATE_P521_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDSA_P521 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 521;
				break;
			case AT_ECDHE_P256:
				if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P256_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDHE_P256 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 256;
				break;
			case AT_ECDHE_P384:
				if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P384_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDHE_P384 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 384;
				break;
			case AT_ECDHE_P521:
				if (pub_ecc->dwMagic != BCRYPT_ECDH_PRIVATE_P521_MAGIC) {
					logprintf(pCardData, 3, "Expected AT_ECDHE_P521 magic\n");
					return SCARD_E_INVALID_PARAMETER;
				}
				key_size = 521;
				break;
			}
		}
		logprintf(pCardData, 3, "Set key size to %lu\n",
			(unsigned long)key_size);
	}

	count = p15card->card->algorithm_count;
	for (algo_info = p15card->card->algorithms; count--; algo_info++) {
		if (algo_info->algorithm != key_algo || algo_info->key_length != key_size)
			continue;
		logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
		return SCARD_S_SUCCESS;
	}

	logprintf(pCardData, 3,
		"No card support for key(type:0x%lX,size:0x%lX)\n",
		(unsigned long)key_type, (unsigned long)key_size);
	return SCARD_E_UNSUPPORTED_FEATURE;
}


static DWORD
md_pkcs15_generate_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, DWORD key_size, PIN_ID PinId)
{
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
	struct sc_app_info *app_info = NULL;
	struct sc_pkcs15init_keygen_args keygen_args;
	struct sc_pkcs15init_pubkeyargs pub_args;
	struct md_pkcs15_container *cont = NULL;
	int rv;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	CHAR szGuid[MAX_CONTAINER_NAME_LEN + 1] = "Default key label";

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (PinId >= MD_MAX_PINS || !vs->pin_objs[PinId] || !vs->pin_objs[PinId]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	p15card = vs->pin_objs[PinId]->p15card;
	card = p15card->card;

	memset(&pub_args, 0, sizeof(pub_args));
	memset(&keygen_args, 0, sizeof(keygen_args));
	keygen_args.prkey_args.label = szGuid;
	keygen_args.pubkey_label = szGuid;

	if (key_type == AT_SIGNATURE) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if (key_type == AT_KEYEXCHANGE) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_RSA;
		pub_args.key.algorithm = SC_ALGORITHM_RSA;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
	}
	else if ((key_type == AT_ECDSA_P256) || (key_type == AT_ECDSA_P384) || (key_type == AT_ECDSA_P521)) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_EC;
		pub_args.key.algorithm = SC_ALGORITHM_EC;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if ((key_type == AT_ECDHE_P256) || (key_type == AT_ECDHE_P384) || (key_type == AT_ECDHE_P521)) {
		keygen_args.prkey_args.key.algorithm = SC_ALGORITHM_EC;
		pub_args.key.algorithm = SC_ALGORITHM_EC;
		keygen_args.prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE_ECC;
	}
	else {
		logprintf(pCardData, 3,
			"MdGenerateKey(): unsupported key type: 0x%lX\n",
			(unsigned long)key_type);
		return SCARD_E_UNSUPPORTED_FEATURE;
	}
	if (pub_args.key.algorithm == SC_ALGORITHM_EC) {
		keygen_args.prkey_args.key.u.ec.params.field_length = key_size;
		if ((key_type == AT_ECDSA_P256) || (key_type == AT_ECDHE_P256)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp256r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 10;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
		}
		else if ((key_type == AT_ECDSA_P384) || (key_type == AT_ECDHE_P384)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp384r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 7;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x05\x2B\x81\x04\x00\x22";
		}
		else if ((key_type == AT_ECDSA_P521) || (key_type == AT_ECDHE_P521)) {
			keygen_args.prkey_args.key.u.ec.params.named_curve = "secp521r1";
			keygen_args.prkey_args.key.u.ec.params.der.len = 7;
			keygen_args.prkey_args.key.u.ec.params.der.value = (unsigned char *)"\x06\x05\x2B\x81\x04\x00\x23";
		}
	}

	keygen_args.prkey_args.access_flags = MD_KEY_ACCESS;

	pin_obj = vs->pin_objs[PinId];
	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;
	keygen_args.prkey_args.auth_id = pub_args.auth_id = auth_info->auth_id;

	rv = sc_lock(card);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = pin_obj->p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdGenerateKey(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, p15card);
	cont = &(vs->p15_containers[idx]);

	/* use the Windows Guid as input to determine some characteristics of the key such as the label or the id */
	md_contguid_build_key_args_from_cont_guid(pCardData, cont->guid, &(keygen_args.prkey_args));

	if (keygen_args.prkey_args.label == NULL) {
		md_generate_guid(szGuid);
		keygen_args.prkey_args.label = szGuid;
	}
	keygen_args.pubkey_label = keygen_args.prkey_args.label;

	rv = sc_pkcs15init_generate_key(p15card, profile, &keygen_args, key_size, &cont->prkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdGenerateKey(): key generation failed: sc-error %i\n", rv);
		goto done;
	}

	dwret = md_contguid_add_conversion(pCardData, cont->prkey_obj, cont->guid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags = CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3,
		"MdGenerateKey(): generated key(idx:%lu,id:%s,guid:%.*s)\n",
		(unsigned long)idx, sc_pkcs15_print_id(&cont->id),
		(int) sizeof cont->guid, cont->guid);

done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}

static DWORD
md_pkcs15_store_key(PCARD_DATA pCardData, DWORD idx, DWORD key_type, BYTE *blob, DWORD blob_size, PIN_ID PinId)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	VENDOR_SPECIFIC *vs;
	struct sc_card *card = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_app_info *app_info = NULL;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15init_prkeyargs prkey_args;
	struct sc_pkcs15init_pubkeyargs pubkey_args;
	BYTE *ptr = blob;
	EVP_PKEY *pkey = NULL;
	int rv;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;
	CHAR szGuid[MAX_CONTAINER_NAME_LEN + 1] = "Default key label";

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	if (PinId >= MD_MAX_PINS || !vs->pin_objs[PinId] || !vs->pin_objs[PinId]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	p15card = vs->pin_objs[PinId]->p15card;
	card = p15card->card;

	pkey = b2i_PrivateKey((const unsigned char **)&ptr, blob_size);
	if (!pkey) {
		logprintf(pCardData, 1, "MdStoreKey() MSBLOB key parse error");
		return SCARD_E_INVALID_PARAMETER;
	}

	memset(&prkey_args, 0, sizeof(prkey_args));
	rv = sc_pkcs15_convert_prkey(&prkey_args.key, pkey);
	if (rv) {
		logprintf(pCardData, 1, "MdStoreKey() cannot convert private key");
		return SCARD_E_INVALID_PARAMETER;
	}

	memset(&pubkey_args, 0, sizeof(pubkey_args));
	rv = sc_pkcs15_convert_pubkey(&pubkey_args.key, pkey);
	if (rv) {
		logprintf(pCardData, 1, "MdStoreKey() cannot convert public key");
		return SCARD_E_INVALID_PARAMETER;
	}

	if (key_type == AT_SIGNATURE) {
		prkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
		pubkey_args.x509_usage = MD_KEY_USAGE_SIGNATURE;
	}
	else if (key_type == AT_KEYEXCHANGE) {
		prkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
		pubkey_args.x509_usage = MD_KEY_USAGE_KEYEXCHANGE;
	}
	else {
		logprintf(pCardData, 3,
			"MdStoreKey(): unsupported key type: 0x%lX\n",
			(unsigned long)key_type);
		return SCARD_E_INVALID_PARAMETER;
	}

	prkey_args.access_flags = MD_KEY_ACCESS;

	pin_obj = vs->pin_objs[PinId];
	prkey_args.auth_id = ((struct sc_pkcs15_auth_info *) pin_obj->data)->auth_id;

	rv = sc_lock(card);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreKey(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreKey(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreKey(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, p15card);
	cont = &(vs->p15_containers[idx]);

	prkey_args.label = szGuid;
	/* use the Windows Guid as input to determine some characteristics of the key such as the label or the id */
	md_contguid_build_key_args_from_cont_guid(pCardData, cont->guid, &prkey_args);

	memcpy(pubkey_args.id.value, prkey_args.id.value, prkey_args.id.len);
	pubkey_args.id.len = prkey_args.id.len;
	pubkey_args.label = prkey_args.label;

	if (prkey_args.label == szGuid) {
		md_generate_guid(szGuid);
	}
	pubkey_args.label = prkey_args.label;

	rv = sc_pkcs15init_store_private_key(p15card, profile, &prkey_args, &cont->prkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreKey(): private key store failed: sc-error %i\n", rv);
		goto done;
	}

	rv = sc_pkcs15init_store_public_key(p15card, profile, &pubkey_args, &cont->pubkey_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreKey(): public key store failed: sc-error %i\n", rv);
		goto done;
	}

	dwret = md_contguid_add_conversion(pCardData, cont->prkey_obj, cont->guid);
	if (dwret != SCARD_S_SUCCESS)
		return dwret;

	cont->id = ((struct sc_pkcs15_prkey_info *)cont->prkey_obj->data)->id;
	cont->index = idx;
	cont->flags |= CONTAINER_MAP_VALID_CONTAINER;

	logprintf(pCardData, 3,
		"MdStoreKey(): stored key(idx:%lu,id:%s,guid:%.*s)\n",
		(unsigned long)idx, sc_pkcs15_print_id(&cont->id),
		(int) sizeof cont->guid, cont->guid);

done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
#else
	logprintf(pCardData, 1, "MD store key not supported\n");
	return SCARD_E_UNSUPPORTED_FEATURE;
#endif
}


static DWORD
md_pkcs15_store_certificate(PCARD_DATA pCardData, char *file_name, unsigned char *blob, size_t len)
{
	VENDOR_SPECIFIC *vs;
	struct md_pkcs15_container *cont = NULL;
	struct sc_card *card = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_profile *profile = NULL;
	struct sc_app_info *app_info = NULL;
	struct sc_pkcs15_object *cert_obj;
	struct sc_pkcs15init_certargs args;
	int rv, idx;
	DWORD dwret = SCARD_F_INTERNAL_ERROR;

	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	logprintf(pCardData, 1, "MdStoreCert(): store certificate '%s'\n", file_name);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs || !vs->fws_data[0] || !vs->fws_data[0]->p15card)
		return SCARD_E_INVALID_PARAMETER;

	p15card = vs->fws_data[0]->p15card;
	card = p15card->card;

	memset(&args, 0, sizeof(args));
	args.der_encoded.value = blob;
	args.der_encoded.len = len;
	args.update = 1;

	/* use container's ID as ID of certificate to store */
	idx = -1;
	if(sscanf_s(file_name, "ksc%d", &idx) > 0)
		;
	else if(sscanf_s(file_name, "kxc%d", &idx) > 0)
		;

	if (idx >= 0 && idx < MD_MAX_KEY_CONTAINERS)   {
		cont = &(vs->p15_containers[idx]);
		args.id = cont->id;
		logprintf(pCardData, 3, "MdStoreCert(): store certificate(idx:%i,id:%s)\n", idx, sc_pkcs15_print_id(&cont->id));
	}

	rv = sc_lock(card);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot lock card\n");
		return SCARD_F_INTERNAL_ERROR;
	}

	app_info = p15card->app;
	rv = sc_pkcs15init_bind(card, "pkcs15", NULL, NULL, &profile);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): PKCS#15 bind failed\n");
		sc_unlock(card);
		return SCARD_F_INTERNAL_ERROR;
	}

	rv = sc_pkcs15init_finalize_profile(card, profile, app_info ? &app_info->aid : NULL);
	if (rv) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot finalize profile\n");
		goto done;
	}

	sc_pkcs15init_set_p15card(profile, p15card);

	rv = sc_pkcs15init_store_certificate(p15card, profile, &args, &cert_obj);
	if (rv < 0) {
		logprintf(pCardData, 3, "MdStoreCert(): cannot store certificate: sc-error %i\n", rv);
		goto done;
	}

	dwret = SCARD_S_SUCCESS;
done:
	sc_pkcs15init_unbind(profile);
	sc_unlock(card);
	return dwret;
}

static DWORD
md_query_key_sizes(PCARD_DATA pCardData, DWORD dwKeySpec, CARD_KEY_SIZES *pKeySizes)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct sc_pkcs15_card *p15card = NULL;
	struct sc_algorithm_info* algo_info;
	int count = 0, i, j, key_algo = 0, keysize = 0, flag;
	if (!pKeySizes)
		return SCARD_E_INVALID_PARAMETER;

	if (pKeySizes->dwVersion > CARD_KEY_SIZES_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;

	logprintf(pCardData, 1, "md_query_key_sizes: store dwKeySpec '%u'\n", dwKeySpec);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);	

	pKeySizes->dwVersion = CARD_KEY_SIZES_CURRENT_VERSION;
	pKeySizes->dwMinimumBitlen = 0;
	pKeySizes->dwDefaultBitlen = 0;
	pKeySizes->dwMaximumBitlen = 0;
	pKeySizes->dwIncrementalBitlen = 0;

	/* dwKeySpec=0 is a special value when the key size is queried without specifing the algorithm.
	Used on old minidriver version. In this case, it is RSA */
	if ((dwKeySpec == 0) || (dwKeySpec == AT_KEYEXCHANGE) || (dwKeySpec == AT_SIGNATURE)) {
		for (j = 0; j < 4; j++)
		{
			if (!vs->fws_data[j])
				break;
			p15card = vs->fws_data[j]->p15card;
			if (!p15card)
				break;
			count = p15card->card->algorithm_count;
			for (i = 0; i < count; i++) {
				algo_info = p15card->card->algorithms + i;
				if (algo_info->algorithm == SC_ALGORITHM_RSA) {

					if (pKeySizes->dwMinimumBitlen == 0 || pKeySizes->dwMinimumBitlen > algo_info->key_length) {
						pKeySizes->dwMinimumBitlen = algo_info->key_length;
					}
					if (pKeySizes->dwMaximumBitlen == 0 || pKeySizes->dwMaximumBitlen < algo_info->key_length) {
						pKeySizes->dwMaximumBitlen = algo_info->key_length;
					}
					if (algo_info->key_length == 2048) {
						pKeySizes->dwDefaultBitlen = algo_info->key_length;
					}
					if (algo_info->key_length == 1536) {
						pKeySizes->dwIncrementalBitlen = 512;
					}
				}
			}
		}
		if (pKeySizes->dwMinimumBitlen == 0) {
			logprintf(pCardData, 0, "No RSA key found\n");
			return SCARD_E_INVALID_PARAMETER;
		}
		if (pKeySizes->dwDefaultBitlen == 0) {
			logprintf(pCardData, 3, "No 2048 key found\n");
			pKeySizes->dwDefaultBitlen = pKeySizes->dwMaximumBitlen;
		}
		if (pKeySizes->dwIncrementalBitlen == 0) {
			pKeySizes->dwIncrementalBitlen = 1024;
		}
	}
	else if (dwKeySpec <= AT_ECDHE_P521) {
		keysize = 0;
		for (j = 0; j < 4; j++)
		{
			if (!vs->fws_data[j])
				break;
			p15card = vs->fws_data[j]->p15card;
			if (!p15card)
				break;
			count = p15card->card->algorithm_count;
			for (i = 0; i < count; i++) {
				algo_info = p15card->card->algorithms + i;
				if (algo_info->algorithm == SC_ALGORITHM_EC) {
					flag = SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_EXT_EC_NAMEDCURVE;
					/* ECDHE */
					if ((dwKeySpec == AT_ECDHE_P256) && (algo_info->key_length == 256) && (algo_info->flags & flag)) {
						keysize = 256;
						break;
					}
					if ((dwKeySpec == AT_ECDHE_P384) && (algo_info->key_length == 384) && (algo_info->flags & flag)) {
						keysize = 384;
						break;
					}
					if ((dwKeySpec == AT_ECDHE_P521) && (algo_info->key_length == 521) && (algo_info->flags & flag)) {
						keysize = 521;
						break;
					}
					/* ECDSA */
					flag = SC_ALGORITHM_ECDSA_HASH_NONE |
						SC_ALGORITHM_ECDSA_HASH_SHA1 |
						SC_ALGORITHM_ECDSA_HASH_SHA224 |
						SC_ALGORITHM_ECDSA_HASH_SHA256 |
						SC_ALGORITHM_EXT_EC_NAMEDCURVE;
					if ((dwKeySpec == AT_ECDSA_P256) && (algo_info->key_length == 256) && (algo_info->flags & flag)) {
						keysize = 256;
						break;
					}
					if ((dwKeySpec == AT_ECDSA_P384) && (algo_info->key_length == 384) && (algo_info->flags & flag)) {
						keysize = 384;
						break;
					}
					if ((dwKeySpec == AT_ECDSA_P521) && (algo_info->key_length == 521) && (algo_info->flags & flag)) {
						keysize = 521;
						break;
					}
				}
			}
		}

		if (keysize) {
			pKeySizes->dwMinimumBitlen = keysize;
			pKeySizes->dwDefaultBitlen = keysize;
			pKeySizes->dwMaximumBitlen = keysize;
			pKeySizes->dwIncrementalBitlen = 1;
		}
		else {
			logprintf(pCardData, 0, "No ECC key found (keyspec=%u)\n", dwKeySpec);
			return SCARD_E_UNSUPPORTED_FEATURE;
		}
	}
    else
    {
        logprintf(pCardData, 0, "Invalid keySpec specified (0x%.8X)\n", dwKeySpec);
        return SCARD_E_INVALID_PARAMETER;
    }
	
	logprintf(pCardData, 3, "Key compatible with the card capabilities\n");
	logprintf(pCardData, 3, " dwMinimumBitlen: %u\n", pKeySizes->dwMinimumBitlen);
	logprintf(pCardData, 3, " dwDefaultBitlen: %u\n", pKeySizes->dwDefaultBitlen);
	logprintf(pCardData, 3, " dwMaximumBitlen: %u\n", pKeySizes->dwMaximumBitlen);
	logprintf(pCardData, 3, " dwIncrementalBitlen: %u\n", pKeySizes->dwIncrementalBitlen);
	return SCARD_S_SUCCESS;
}

static HWND g_hPinPadDlg = NULL;

void SetForegroundWindowEx( HWND hWnd)
{
    HWND hLastActivePopupWnd = GetLastActivePopup( hWnd );
    HWND hForground = GetForegroundWindow();
    if (hForground && (hForground != hWnd)) {
        //Attach foreground window thread to our thread
        DWORD ForeGroundID = GetWindowThreadProcessId(GetForegroundWindow(), NULL);
        DWORD CurrentID   = GetCurrentThreadId();
        if (ForeGroundID != CurrentID) {
            AttachThreadInput ( ForeGroundID, CurrentID, TRUE );
            //Do our stuff here
            SetForegroundWindow( hLastActivePopupWnd );
            //Detach the attached thread
            AttachThreadInput ( ForeGroundID, CurrentID, FALSE );
            BringWindowToTop(hLastActivePopupWnd);
        } else {
            SetForegroundWindow( hLastActivePopupWnd );
        }
    } else {
        SetForegroundWindow( hLastActivePopupWnd );
    }
}

static BOOL CALLBACK PinPadDlgProc(HWND   hDlg,  UINT   msg,  WPARAM wParam,  LPARAM lParam)
{
   static DWORD g_dwCounter = 0;
   switch (msg)
   {     
      /* Initialize Dialog box                                                */
      case WM_INITDIALOG:
			{
				TCHAR szMsg[512];
				g_dwCounter = 0;
				SetForegroundWindow (hDlg);
				SetTimer(hDlg, 1, 1000, (TIMERPROC) NULL);
				if ((PIN_ID) lParam == ROLE_USER)
				{
					LoadString (g_inst, IDS_USER_PIN_PINPAD_PROMPT, szMsg, ARRAYSIZE(szMsg));
				}
				else
				{
					LoadString (g_inst, IDS_SIG_PIN_PINPAD_PROMPT, szMsg, ARRAYSIZE(szMsg));
				}

				SetDlgItemText (hDlg, IDC_PINPAD_MSG, szMsg);
			}
         return TRUE;

      case WM_DESTROY:
         KillTimer(hDlg, 1);
         break;

      case WM_TIMER:
        if (g_dwCounter >= 3) KillTimer(hDlg, 1);
        SetForegroundWindowEx(hDlg);
        SetActiveWindow(hDlg);
        break;

      default:
         return FALSE;
   }
   return FALSE;
}

static void DisplayPinPadDlg(HWND hParent, PIN_ID PinId)
{
   if (g_hPinPadDlg)
      return;

	g_hPinPadDlg = CreateDialogParam (g_inst, MAKEINTRESOURCE(IDD_PINPAD), hParent,  (DLGPROC) PinPadDlgProc, (LPARAM) PinId);
}
   
static void HidePinPadDlg()
{
   if (g_hPinPadDlg)
   {
      DestroyWindow(g_hPinPadDlg);
      g_hPinPadDlg = NULL;
   }
}


static int 
md_perform_pin_operation(PCARD_DATA pCardData, int operation, struct sc_pkcs15_card *p15card,
	    struct sc_pkcs15_object *puk_obj,
		struct sc_pkcs15_object *pin_obj,
		const u8 *pin1, size_t pin1len,
		const u8 *pin2, size_t pin2len)
{
	INT_PTR result = 0;
	HWND hWndDlg = 0;
	int rv = 0;
	VENDOR_SPECIFIC* pv = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	struct sc_pkcs15_auth_info *auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	/* the path in the pin object is optional */
	if ((auth_info->path.len > 0) || ((auth_info->path.aid.len > 0))) {
		rv = sc_select_file(p15card->card, &auth_info->path, NULL);
		if (rv)
			return rv;
	}

	switch (operation)
	{
	case SC_PIN_CMD_VERIFY:
		rv = sc_pkcs15_verify_pin(p15card, pin_obj, pin1, pin1len);
		break;
	case SC_PIN_CMD_CHANGE:
		rv = sc_pkcs15_change_pin(p15card, pin_obj, pin1, pin1len,pin2, pin2len);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = sc_pkcs15_unblock_pin(p15card, puk_obj, pin_obj, pin1, pin1len,pin2, pin2len);
		break;
	default:
		rv = (DWORD) ERROR_INVALID_PARAMETER;
		break;
	}

	return rv;
}

static DWORD md_translate_OpenSC_to_Windows_error(int OpenSCerror,
	DWORD dwDefaulCode)
{
	switch (OpenSCerror)
	{
		/* Errors related to reader operation */
	case SC_ERROR_READER:
		return SCARD_E_PROTO_MISMATCH;
	case SC_ERROR_NO_READERS_FOUND:
		return SCARD_E_NO_READERS_AVAILABLE;
	case SC_ERROR_CARD_NOT_PRESENT:
		return SCARD_E_NO_SMARTCARD;
	case SC_ERROR_TRANSMIT_FAILED:
		return SCARD_E_NOT_TRANSACTED;
	case SC_ERROR_CARD_REMOVED:
		return SCARD_W_REMOVED_CARD;
	case SC_ERROR_CARD_RESET:
		return SCARD_W_RESET_CARD;
	case SC_ERROR_KEYPAD_CANCELLED:
		return SCARD_W_CANCELLED_BY_USER;
	case SC_ERROR_KEYPAD_MSG_TOO_LONG:
		return SCARD_W_CARD_NOT_AUTHENTICATED;
	case SC_ERROR_KEYPAD_PIN_MISMATCH:
		return SCARD_E_INVALID_CHV;
	case SC_ERROR_KEYPAD_TIMEOUT:
		return ERROR_TIMEOUT;
	case SC_ERROR_EVENT_TIMEOUT:
		return SCARD_E_TIMEOUT;
	case SC_ERROR_CARD_UNRESPONSIVE:
		return SCARD_W_UNRESPONSIVE_CARD;
	case SC_ERROR_READER_LOCKED:
		return SCARD_E_SHARING_VIOLATION;

		/* Resulting from a card command or related to the card*/
	case SC_ERROR_INCORRECT_PARAMETERS:
		return SCARD_E_INVALID_PARAMETER;
	case SC_ERROR_MEMORY_FAILURE:
	case SC_ERROR_NOT_ENOUGH_MEMORY:
		return SCARD_E_NO_MEMORY;
	case SC_ERROR_NOT_ALLOWED:
		case SC_ERROR_SECURITY_STATUS_NOT_SATISFIED:
		return SCARD_W_SECURITY_VIOLATION;
	case SC_ERROR_AUTH_METHOD_BLOCKED:
		return SCARD_W_CHV_BLOCKED;
	case SC_ERROR_PIN_CODE_INCORRECT:
		return SCARD_W_WRONG_CHV;

		/* Returned by OpenSC library when called with invalid arguments */
	case SC_ERROR_INVALID_ARGUMENTS:
		return ERROR_INVALID_PARAMETER;
	case SC_ERROR_BUFFER_TOO_SMALL:
		return NTE_BUFFER_TOO_SMALL;

		/* Resulting from OpenSC internal operation */
	case SC_ERROR_INTERNAL:
		return ERROR_INTERNAL_ERROR;
	case SC_ERROR_NOT_SUPPORTED:
		return SCARD_E_UNSUPPORTED_FEATURE;
	case SC_ERROR_NOT_IMPLEMENTED:
		return ERROR_CALL_NOT_IMPLEMENTED;

	default:
		return dwDefaulCode;
	}
}


static void printTimestamp (char* buffer)
{
  time_t rawtime;
  struct tm * timeinfo;

  time (&rawtime);
  timeinfo = localtime (&rawtime);

  strftime (buffer,80,"%Y-%m-%d %H:%M:%S",timeinfo);
}

DWORD 
WINAPI 
InternalCardChangeAuthenticatorEx(
    __in                                    PCARD_DATA  pCardData,
    __in                                    DWORD       dwFlags,
	 __in												  BOOL		  bSilent,
    __in                                    PIN_ID      dwAuthenticatingPinId,
    __in_bcount(cbAuthenticatingPinData)    PBYTE       pbAuthenticatingPinData,
    __in                                    DWORD       cbAuthenticatingPinData,
    __in                                    PIN_ID      dwTargetPinId,
    __in_bcount(cbTargetData)               PBYTE       pbTargetData,
    __in                                    DWORD       cbTargetData,
    __in                                    DWORD       cRetryCount,
    __out_opt                               PDWORD      pcAttemptsRemaining);

BOOL APIENTRY DllMain( HINSTANCE hinstDLL,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			char buffer[80];
			HKEY hKey;
         HMODULE hDll;
			LSTATUS lRet = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Latvia eID\\Minidriver", 0, KEY_READ, &hKey);
			if (lRet != ERROR_SUCCESS)
				lRet = RegOpenKeyEx(HKEY_CURRENT_USER, "SOFTWARE\\Latvia eID\\Minidriver", 0, KEY_READ, &hKey);
			if (lRet == ERROR_SUCCESS)
			{
				DWORD dwType, cbData = MAX_PATH;
				lRet = RegQueryValueEx (hKey, "LogFile", NULL, &dwType, (LPBYTE) logfilePath, &cbData);
				if (lRet == ERROR_SUCCESS && logfilePath[0])
					g_bLogEnabled = TRUE;

				RegCloseKey (hKey);
			}

            GetModuleFileName (NULL, exefilePath, MAX_PATH);

			if (g_bLogEnabled)
			{				
				printTimestamp(buffer);
				logprintf(NULL, 0, "%s - Latvia-eID minidriver loaded by \"%s\"\n", buffer, exefilePath); 
			}
			g_inst = hinstDLL;
         InitializeCriticalSection (&g_cs);

         hDll = LoadLibrary ("winscard.dll");
         if (hDll)
         {
            SCardGetAttribPtr = (SCardGetAttribFn) GetProcAddress (hDll, "SCardGetAttrib");
			SCardDisconnectPtr= (SCardDisconnectFn) GetProcAddress (hDll, "SCardDisconnect");
			SCardGetStatusChangePtr = (SCardGetStatusChangeFn) GetProcAddress (hDll, "SCardGetStatusChangeA");
#ifdef _DEBUG
			SCardBeginTransactionPtr = SCardBeginTransactionDummy;
			SCardEndTransactionPtr = SCardEndTransactionDummy;
#else
			SCardBeginTransactionPtr = (SCardBeginTransactionFn)GetProcAddress(hDll, "SCardBeginTransaction");
			SCardEndTransactionPtr = (SCardEndTransactionFn)GetProcAddress(hDll, "SCardEndTransaction");
#endif
         }
		}
		break;
	case DLL_PROCESS_DETACH:
		{
			char buffer[80];
			int i;
			g_bDllDetached = TRUE;
			if (g_bLogEnabled)
			{
				printTimestamp(buffer);
				logprintf(NULL, 0, "%s - Latvia-eID minidriver unloaded from \"%s\"\n", buffer, exefilePath); 
			}

			/* disconnect any left open context to try to avoid card reset */
			EnterCriticalSection (&g_cs);
			for (i = 0; i < ARRAYSIZE (g_cardContexts); i++)
			{
				if (g_cardContexts[i].pVs)
				{
					VENDOR_SPECIFIC* vs = (VENDOR_SPECIFIC*)(g_cardContexts[i].pVs);

					SCardDisconnectPtr (vs->hScard, SCARD_LEAVE_CARD);
				}
			}
			LeaveCriticalSection (&g_cs);
         DeleteCriticalSection (&g_cs);
		}
		break;
	}
	return TRUE;
}

#define FUNCTION_BEGIN	\
								if (g_bLogEnabled) {	\
									char buffer[80]; \
									printTimestamp(buffer); \
                           logprintf (pCardData, 1, "\n===================================================================================================\n"); \
									logprintf (pCardData, 1, "%s (PID=%.8X, TID=%.8X) - BEGIN %s\n\tProcess: %s\npCardData = 0x%p, hContext = 0x%p, hCard = 0x%p\npvVendorSpecific = 0x%p\n\n", buffer, GetCurrentProcessId(), GetCurrentThreadId(), __FUNCTION__, exefilePath, pCardData, pCardData? (void*) pCardData->hSCardCtx : NULL, pCardData? (void*) pCardData->hScard: NULL, pCardData? pCardData->pvVendorSpecific : NULL ); \
								} \

#define FUNCTION_END(a)	{ \
									if (g_bLogEnabled) { \
                              DWORD dwLocalLastError = GetLastError (); \
										char buffer[80]; \
										printTimestamp(buffer); \
                              if (a == 0) \
                                 logprintf (pCardData, 1, "%s (PID=%.8X, TID=%.8X) - END %s. Returned SUCCESS\n", buffer, GetCurrentProcessId(), GetCurrentThreadId(), __FUNCTION__); \
                              else \
										   logprintf (pCardData, 1, "%s (PID=%.8X, TID=%.8X) - END %s. Returned ERROR 0x%.8X\n", buffer, GetCurrentProcessId(), GetCurrentThreadId(), __FUNCTION__, a); \
                              logprintf (pCardData, 1, "===================================================================================================\n\n"); \
                              SetLastError (dwLocalLastError); \
									} \
									return a; \
								}

#define GOTO_END(a) { dwret = (DWORD) a; goto end; }

DWORD WINAPI CardDeleteContext(__inout PCARD_DATA  pCardData)
{
	if (g_bDllDetached)
		return SCARD_E_UNEXPECTED;
	else
	{
		VENDOR_SPECIFIC *vs = NULL;

		FUNCTION_BEGIN;

		if(!pCardData)
			FUNCTION_END(SCARD_E_INVALID_PARAMETER);

		vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
		if(!vs)
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);

      DeleteContext(pCardData, FALSE);

		FUNCTION_END(SCARD_S_SUCCESS);
	}
}

DWORD WINAPI CardQueryCapabilities(__in PCARD_DATA pCardData,
	__inout PCARD_CAPABILITIES  pCardCapabilities)
{
	DWORD dwret;
	int rv;
	LONG lRet;
   
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardQueryCapabilities (pCardCapabilities=%p)\n", pCardCapabilities);

	if (!pCardData || !pCardData->hScard || !pCardCapabilities)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD)lRet);

	rv = check_reader_status(pCardData);
	if (rv != SCARD_S_SUCCESS)
		GOTO_END(rv);

	dwret = md_card_capabilities(pCardData, pCardCapabilities);
	if (dwret != SCARD_S_SUCCESS)
		GOTO_END(dwret);
	dwret = SCARD_S_SUCCESS;
end:
	SCardEndTransactionPtr(pCardData->hScard, SCARD_LEAVE_CARD);
	FUNCTION_END (dwret);
}

DWORD WINAPI CardDeleteContainer(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwReserved)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwret;
	struct md_pkcs15_container* cont;

   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardDeleteContainer(idx:%i)\n", bContainerIndex);

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

    if (md_is_read_only (pCardData))
    {
		logprintf(pCardData, 1, "card is read-only.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
    }

	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if (!md_is_supports_container_key_gen(pCardData))   {
		logprintf(pCardData, 1, "Denied 'deletion' mechanism to delete container.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if(!vs)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	cont = &(vs->p15_containers[bContainerIndex]);

	dwret = md_pkcs15_delete_object(pCardData, cont->prkey_obj);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "private key deletion failed\n");
		FUNCTION_END (dwret);
	}

	dwret = md_pkcs15_delete_object(pCardData, cont->pubkey_obj);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "public key deletion failed\n");
		FUNCTION_END (dwret);
	}

	ZeroMemory(cont, sizeof(struct md_pkcs15_container));

	logprintf(pCardData, 1, "key deleted\n");
	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardCreateContainerEx(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in DWORD dwFlags,
	__in DWORD dwKeySpec,
	__in DWORD dwKeySize,
	__in PBYTE pbKeyData,
	__in PIN_ID PinId)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dwret;

   FUNCTION_BEGIN;

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

   if (g_bLogEnabled)
	   logprintf(pCardData, 1, "CardCreateContainerEx(idx:%i,flags:%X,type:%X,size:%i,data:%p,PinId=%u)\n",
		   	bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData,(unsigned int) PinId);

	if (g_bLogEnabled && pbKeyData)   {
		logprintf(pCardData, 7, "Key data\n");
		loghex(pCardData, 7, pbKeyData, dwKeySize);
	}


	if (PinId == ROLE_ADMIN) {
		FUNCTION_END(SCARD_W_SECURITY_VIOLATION);
	}

	if (!vs || !vs->pin_objs[PinId])
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

    if (md_is_read_only (pCardData))
    {
		logprintf(pCardData, 1, "card is read-only.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
    }

	dwret = md_check_key_compatibility(pCardData, vs->pin_objs[PinId]->p15card, dwFlags, dwKeySpec, dwKeySize, pbKeyData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "check key compatibility failed\n");
		FUNCTION_END (dwret);
	}

	if (!md_is_supports_container_key_gen(pCardData))   {
		logprintf(pCardData, 1, "Denied 'generate key' mechanism to create container.\n");
		dwFlags &= ~CARD_CREATE_CONTAINER_KEY_GEN;
	}

	if (!md_is_supports_container_key_import(pCardData))   {
		logprintf(pCardData, 1, "Denied 'import key' mechanism to create container.\n");
		dwFlags &= ~CARD_CREATE_CONTAINER_KEY_IMPORT;
	}

	if (!dwFlags)   {
		logprintf(pCardData, 1, "Unsupported create container mechanism.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	if (dwFlags & CARD_CREATE_CONTAINER_KEY_GEN)   {
		dwret = md_pkcs15_generate_key(pCardData, bContainerIndex, dwKeySpec, dwKeySize, PinId);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key generation failed\n");
			FUNCTION_END (dwret);
		}
		logprintf(pCardData, 1, "key generated\n");
	}
	else if ((dwFlags & CARD_CREATE_CONTAINER_KEY_IMPORT) && (pbKeyData != NULL)) {
		dwret = md_pkcs15_store_key(pCardData, bContainerIndex, dwKeySpec, pbKeyData, dwKeySize, PinId);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "key store failed\n");
			FUNCTION_END (dwret);
		}
		logprintf(pCardData, 1, "key imported\n");
	}
	else   {
		logprintf(pCardData, 1, "Invalid dwFlags value: 0x%X\n", dwFlags);
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	FUNCTION_END (SCARD_S_SUCCESS);
}


typedef struct {
	PUBLICKEYSTRUC  publickeystruc;
	RSAPUBKEY rsapubkey;
} PUBRSAKEYSTRUCT_BASE;

DWORD WINAPI CardGetContainerInfo(__in PCARD_DATA pCardData, __in BYTE bContainerIndex, __in DWORD dwFlags,
	__inout PCONTAINER_INFO pContainerInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD sz = 0;
	DWORD dwret = SCARD_F_UNKNOWN_ERROR;
	struct md_pkcs15_container *cont = NULL;
	struct sc_pkcs15_der pubkey_der;
	struct sc_pkcs15_prkey_info *prkey_info = NULL;
	int rv;
	LONG lRet;

   FUNCTION_BEGIN;

	if(!pCardData || !pCardData->hScard)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pContainerInfo)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

   if (g_bLogEnabled)
	   logprintf(pCardData, 1, "CardGetContainerInfo bContainerIndex=%u, dwFlags=0x%08X, " \
		   "dwVersion=%u, cbSigPublicKey=%u, cbKeyExPublicKey=%u\n", \
		   bContainerIndex, dwFlags, pContainerInfo->dwVersion, \
		   pContainerInfo->cbSigPublicKey, pContainerInfo->cbKeyExPublicKey);

	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);
	if (pContainerInfo->dwVersion < 0 || pContainerInfo->dwVersion >  CONTAINER_INFO_CURRENT_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD)lRet);

	rv = check_reader_status(pCardData);
	if (rv != SCARD_S_SUCCESS)
		GOTO_END(rv);

	pContainerInfo->dwVersion = CONTAINER_INFO_CURRENT_VERSION;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	cont = &vs->p15_containers[bContainerIndex];

    if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %i is empty\n", bContainerIndex);
		GOTO_END(SCARD_E_NO_KEY_CONTAINER);
	}

	if (cont->p15card == NULL) {
		GOTO_END(SCARD_F_INTERNAL_ERROR);
	}

	prkey_info = (struct sc_pkcs15_prkey_info *)cont->prkey_obj->data;

	pubkey_der.value = NULL;
	pubkey_der.len = 0;

	if ((cont->prkey_obj->content.value != NULL) && (cont->prkey_obj->content.len > 0))   {
		sc_der_copy(&pubkey_der, &cont->prkey_obj->content);
		dwret = SCARD_S_SUCCESS;
	}

	if (!pubkey_der.value && cont->pubkey_obj)   {
		struct sc_pkcs15_pubkey *pubkey = NULL;

		logprintf(pCardData, 1, "now read public key '%.*s'\n", (int) sizeof cont->pubkey_obj->label, cont->pubkey_obj->label);
		rv = sc_pkcs15_read_pubkey(cont->p15card, cont->pubkey_obj, &pubkey);
		if (!rv)   {
			rv = sc_pkcs15_encode_pubkey(vs->ctx, pubkey, &pubkey_der.value, &pubkey_der.len);
			if (rv)   {
				logprintf(pCardData, 1, "encode public key error %d\n", rv);
				dwret = SCARD_F_INTERNAL_ERROR;
			}
			else   {
				logprintf(pCardData, 1, "public key encoded\n");
				dwret = SCARD_S_SUCCESS;
			}

			sc_pkcs15_free_pubkey(pubkey);
		}
		else {
			logprintf(pCardData, 1, "public key read error %d\n", rv);
			dwret = SCARD_E_FILE_NOT_FOUND;
		}
	}

	if (!pubkey_der.value && cont->cert_obj)   {
		struct sc_pkcs15_cert *cert = NULL;

		logprintf(pCardData, 1, "now read certificate '%.*s'\n", (int) sizeof cont->cert_obj->label, cont->cert_obj->label);
		rv = md_pkcs15_read_certificate(cont->p15card, (struct sc_pkcs15_cert_info *)(cont->cert_obj->data), &cert);
		if(!rv)   {
			rv = sc_pkcs15_encode_pubkey(vs->ctx, cert->key, &pubkey_der.value, &pubkey_der.len);
			if (rv)   {
				logprintf(pCardData, 1, "encode certificate public key error %d\n", rv);
				dwret = SCARD_F_INTERNAL_ERROR;
			}
			else   {
				logprintf(pCardData, 1, "certificate public key encoded\n");
				dwret = SCARD_S_SUCCESS;
			}

			sc_pkcs15_free_certificate(cert);
		}
		else   {
			logprintf(pCardData, 1, "certificate '%d' read error %d\n", bContainerIndex, rv);
			dwret = SCARD_E_FILE_NOT_FOUND;
		}
	}

	if (!pubkey_der.value && (cont->size_sign || cont->size_key_exchange)) {
		logprintf(pCardData, 2, "cannot find public key\n");
		GOTO_END(SCARD_F_INTERNAL_ERROR);
	}

	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 7, "GetContainerInfo(idx:%i) failed; error %X", bContainerIndex, dwret);
		GOTO_END(dwret);
	}

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "SubjectPublicKeyInfo:\n");
	   loghex(pCardData, 7, pubkey_der.value, pubkey_der.len);
   }

	if (prkey_info->modulus_length > 0) {
		logprintf(pCardData, 7, "Encoding RSA public key");
		if (pubkey_der.len && pubkey_der.value)   {
			sz = 0; /* get size */
			CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
					pubkey_der.value, (DWORD) pubkey_der.len, 0, NULL, &sz);

			{
				PUBRSAKEYSTRUCT_BASE *publicKey = (PUBRSAKEYSTRUCT_BASE *)pCardData->pfnCspAlloc(sz);
				if (!publicKey)
					GOTO_END(SCARD_E_NO_MEMORY);

				CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
						pubkey_der.value, (DWORD) pubkey_der.len, 0, publicKey, &sz);

				if (cont->size_sign)
				{
					publicKey->publickeystruc.aiKeyAlg = CALG_RSA_SIGN;
					pContainerInfo->cbSigPublicKey = sz;
					pContainerInfo->pbSigPublicKey = (PBYTE)publicKey;

					logprintf(pCardData, 3, "return info on SIGN_CONTAINER_INDEX %i\n", bContainerIndex);
				}
				else
				{
					publicKey->publickeystruc.aiKeyAlg = CALG_RSA_KEYX;
					pContainerInfo->cbKeyExPublicKey = sz;
					pContainerInfo->pbKeyExPublicKey = (PBYTE)publicKey;

					logprintf(pCardData, 3, "return info on KEYEXCH_CONTAINER_INDEX %i\n", bContainerIndex);
				}
			}

		}
	} else if (prkey_info->field_length > 0) {
		logprintf(pCardData, 7, "Encoding ECC public key");

		if (pubkey_der.len > 2 && pubkey_der.value && pubkey_der.value[0] == 4 && pubkey_der.value[1] == pubkey_der.len -2) {
			BCRYPT_ECCKEY_BLOB *publicKey = NULL;
			DWORD dwMagic = 0;
            size_t bit_size = (cont->size_sign? cont->size_sign: cont->size_key_exchange);
			{
				sz = (DWORD) (sizeof(BCRYPT_ECCKEY_BLOB) +  pubkey_der.len -3);

				switch(bit_size)
				{
				case 256:
					dwMagic = cont->size_sign ? BCRYPT_ECDSA_PUBLIC_P256_MAGIC : BCRYPT_ECDH_PUBLIC_P256_MAGIC;
					break;
				case 384:
					dwMagic = cont->size_sign ? BCRYPT_ECDSA_PUBLIC_P384_MAGIC : BCRYPT_ECDH_PUBLIC_P384_MAGIC;
					break;
				case 521:
					dwMagic = cont->size_sign ? BCRYPT_ECDSA_PUBLIC_P521_MAGIC : BCRYPT_ECDH_PUBLIC_P521_MAGIC;
					break;
				default:
					logprintf(pCardData, 3, "Unable to match the ECC public size to one of Microsoft algorithm %i\n", bit_size);
					GOTO_END(SCARD_F_INTERNAL_ERROR);
				}

				publicKey = (BCRYPT_ECCKEY_BLOB *)pCardData->pfnCspAlloc(sz);
				if (!publicKey)
					GOTO_END(SCARD_E_NO_MEMORY);

				publicKey->cbKey =  (DWORD)(pubkey_der.len -3) /2;
				publicKey->dwMagic = dwMagic;
				memcpy(((PBYTE)publicKey) + sizeof(BCRYPT_ECCKEY_BLOB),  pubkey_der.value + 3,  pubkey_der.len -3);

				if (cont->size_sign)
				{
					pContainerInfo->cbSigPublicKey = sz;
					pContainerInfo->pbSigPublicKey = (PBYTE)publicKey;
					logprintf(pCardData, 3, "return info on ECC SIGN_CONTAINER_INDEX %i\n", bContainerIndex);
				}
				else
				{
					pContainerInfo->cbKeyExPublicKey = sz;
					pContainerInfo->pbKeyExPublicKey = (PBYTE)publicKey;
					logprintf(pCardData, 3, "return info on ECC KEYEXCH_CONTAINER_INDEX %i\n", bContainerIndex);
				}
			}
			
		}
	}

	logprintf(pCardData, 7, "returns container(idx:%i) info", bContainerIndex);
	dwret = SCARD_S_SUCCESS;
end:
	SCardEndTransactionPtr(pCardData->hScard, SCARD_S_SUCCESS);
	FUNCTION_END (dwret);
}

DWORD WINAPI CardAuthenticatePin(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbPin) PBYTE pbPin,
	__in DWORD cbPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	PIN_ID PinId = 0;
   DWORD dwStatus;

   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardAuthenticatePin '%S': cbPin = %d\n", NULLWSTR(pwszUserId), cbPin);

    if (!pwszUserId)
    {
        FUNCTION_END (SCARD_E_INVALID_PARAMETER);
    }
	else if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0)	{
		PinId = ROLE_USER;
	}
	else if (wcscmp(pwszUserId, wszCARD_USER_ADMIN) == 0) {
		PinId = ROLE_ADMIN;
	}
	else {
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}
	if (pbPin == NULL)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	dwStatus = CardAuthenticateEx(pCardData, PinId, CARD_PIN_SILENT_CONTEXT, pbPin, cbPin, NULL, NULL, pcAttemptsRemaining);

   FUNCTION_END (dwStatus);
}


DWORD WINAPI CardGetChallenge(__in PCARD_DATA pCardData,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out                                 PDWORD pcbChallengeData)
{
   FUNCTION_BEGIN;

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 1, "CardGetChallenge (ppbChallengeData=%p, pcbChallengeData=%p)\n");
   }

	if(!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!ppbChallengeData || !pcbChallengeData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	logprintf(pCardData, 1, "CardGetChallenge - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}


DWORD WINAPI CardAuthenticateChallenge(__in PCARD_DATA  pCardData,
	__in_bcount(cbResponseData) PBYTE  pbResponseData,
	__in DWORD  cbResponseData,
	__out_opt PDWORD pcAttemptsRemaining)
{
   FUNCTION_BEGIN;
	logprintf(pCardData, 1, "CardAuthenticateChallenge - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}


DWORD WINAPI CardUnblockPin(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbAuthenticationData) PBYTE  pbAuthenticationData,
	__in DWORD  cbAuthenticationData,
	__in_bcount(cbNewPinData) PBYTE  pbNewPinData,
	__in DWORD  cbNewPinData,
	__in DWORD  cRetryCount,
	__in DWORD  dwFlags)
{
   DWORD dwRet;
   FUNCTION_BEGIN;

	if(!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	logprintf(pCardData, 1, "CardUnblockPin: UserID('%S'), AuthData(%p, %u), NewPIN(%p, %u), Retry(%u), dwFlags(0x%X)\n",
			pwszUserId, pbAuthenticationData, cbAuthenticationData, pbNewPinData, cbNewPinData,
			cRetryCount, dwFlags);

	if (pwszUserId == NULL)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN,pwszUserId) != 0)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (wcscmp(wszCARD_USER_ADMIN, pwszUserId) == 0)
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	if (dwFlags & CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	dwRet = InternalCardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_UNBLOCK, TRUE, ROLE_ADMIN, pbAuthenticationData, cbAuthenticationData, ROLE_USER, pbNewPinData, cbNewPinData, cRetryCount, NULL);

   FUNCTION_END (dwRet);
}


DWORD WINAPI CardChangeAuthenticator(__in PCARD_DATA  pCardData,
	__in LPWSTR pwszUserId,
	__in_bcount(cbCurrentAuthenticator) PBYTE pbCurrentAuthenticator,
	__in DWORD cbCurrentAuthenticator,
	__in_bcount(cbNewAuthenticator) PBYTE pbNewAuthenticator,
	__in DWORD cbNewAuthenticator,
	__in DWORD cRetryCount,
	__in DWORD dwFlags,
	__out_opt PDWORD pcAttemptsRemaining)
{
   DWORD dwRet;
	PIN_ID pinid;

   FUNCTION_BEGIN;

	if(!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	logprintf(pCardData, 1, "CardChangeAuthenticator: UserID('%S'), CurrentPIN(%p, %u), NewPIN(%p, %u), Retry(%u), dwFlags(0x%X)\n",
			pwszUserId, pbCurrentAuthenticator, cbCurrentAuthenticator, pbNewAuthenticator, cbNewAuthenticator,
			cRetryCount, dwFlags);

	if (pwszUserId == NULL || (dwFlags != CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE && dwFlags != CARD_AUTHENTICATE_PIN_PIN))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if (dwFlags == CARD_AUTHENTICATE_PIN_CHALLENGE_RESPONSE)   {
		logprintf(pCardData, 1, "Other then 'authentication' the PIN are not supported\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	if (wcscmp(wszCARD_USER_USER, pwszUserId) != 0 && wcscmp(wszCARD_USER_ADMIN, pwszUserId) != 0)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if (wcscmp(wszCARD_USER_USER, pwszUserId) == 0)
		pinid = ROLE_USER;
	else
		pinid = ROLE_ADMIN;

	dwRet = InternalCardChangeAuthenticatorEx(pCardData, PIN_CHANGE_FLAG_CHANGEPIN, TRUE, pinid, pbCurrentAuthenticator, cbCurrentAuthenticator, pinid, pbNewAuthenticator, cbNewAuthenticator, cRetryCount, pcAttemptsRemaining);

   FUNCTION_END (dwRet);
}

/* this function is not called on purpose.
If a deauthentication is not possible, it should be set to NULL in CardAcquireContext.
Because this function do nothing - it is not called.
Note: the PIN freshnesh will be managed by the Base CSP*/
DWORD WINAPI CardDeauthenticate(__in PCARD_DATA pCardData,
	__in LPWSTR pwszUserId,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC* vs = NULL;
    int rv = SC_SUCCESS;
	PIN_ID PinId;
	struct sc_pkcs15_card *p15card = NULL;
    FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardDeauthenticate(pwszUserId=%S, dwFlags=%d)\n", NULLWSTR(pwszUserId), dwFlags);

	if(!pCardData || (dwFlags != 0) || !pwszUserId)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

    if (wcscmp(pwszUserId, wszCARD_USER_USER) && wcscmp(pwszUserId, wszCARD_USER_ADMIN))	{
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	if (wcscmp(pwszUserId, wszCARD_USER_USER) == 0)
		PinId = ROLE_USER;
	else
		PinId = ROLE_ADMIN;

	if (!vs->pin_objs[PinId])
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	p15card = vs->pin_objs[PinId]->p15card;

	sc_pkcs15_free_object_content(vs->pin_objs[PinId]);

   if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
   {
		rv =  sc_pkcs15_logout_pin(p15card, vs->pin_objs[PinId]);

		if (rv < 0)
		{
			/* force a reset of a card - SCARD_S_SUCCESS do not lead to the reset of the card and leave it still authenticated */
			rv = SCARD_E_UNSUPPORTED_FEATURE;
		}
   }
    	
	FUNCTION_END (rv);
}

DWORD WINAPI CardCreateDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName,
	__in CARD_DIRECTORY_ACCESS_CONDITION AccessCondition)
{
   FUNCTION_BEGIN;
	logprintf(pCardData, 1, "CardCreateDirectory(%s) - unsupported\n", NULLSTR(pszDirectoryName));
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardDeleteDirectory(__in PCARD_DATA pCardData,
	__in LPSTR pszDirectoryName)
{
   FUNCTION_BEGIN;
	logprintf(pCardData, 1, "CardDeleteDirectory(%s) - unsupported\n", NULLSTR(pszDirectoryName));
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardCreateFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD cbInitialCreationSize,
	__in CARD_FILE_ACCESS_CONDITION AccessCondition)
{
	struct md_directory *dir = NULL;
	DWORD dwret;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardCreateFile(%s::%s, size %i, acl:0x%X) called\n",
			NULLSTR(pszDirectoryName), NULLSTR(pszFileName), cbInitialCreationSize, AccessCondition);

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

    if (md_is_read_only (pCardData))
    {
		logprintf(pCardData, 1, "card is read-only.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
    }

	dwret = md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardCreateFile() cannot find parent directory '%s'", NULLSTR(pszDirectoryName));
		FUNCTION_END (dwret);
	}

	dwret = md_fs_add_file(pCardData, &dir->files, pszFileName, AccessCondition, NULL, cbInitialCreationSize, NULL);

	FUNCTION_END (dwret);
}


DWORD WINAPI CardReadFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__deref_out_bcount_opt(*pcbData) PBYTE *ppbData,
	__out PDWORD pcbData)
{
	VENDOR_SPECIFIC *vs;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
    DWORD dwret;
	LONG lRet;
	int r;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardReadFile: pszDirectoryName = %s, pszFileName = %s, dwFlags = %X, ppbData=%p, pcbData=%p\n", 
      NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags, ppbData, pcbData);

	if(!pCardData || !pCardData->hScard)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!ppbData || !pcbData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	logprintf(pCardData, 2, "*pcbData=%u, *ppbData=%p\n",
		 *pcbData, *ppbData);

	if (!pszFileName || !strlen(pszFileName))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD) lRet);

	r = check_reader_status(pCardData);
	if (r != SCARD_S_SUCCESS)
		GOTO_END(r);

	dwret = md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardReadFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		GOTO_END (dwret);
	}

	if (!file->blob)
		md_fs_read_content(pCardData, pszDirectoryName, file);

	*ppbData = pCardData->pfnCspAlloc(file->size);
	if(!*ppbData)
		GOTO_END(SCARD_E_NO_MEMORY);
	*pcbData = (DWORD) file->size;
	memcpy(*ppbData, file->blob, file->size);

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "returns '%s' content:\n",  NULLSTR(pszFileName));
	   loghex(pCardData, 7, *ppbData, *pcbData);
   }
   vs->lastChecked = GetTickCount64();
   dwret = SCARD_S_SUCCESS;
end:
   SCardEndTransactionPtr(pCardData->hScard, SCARD_LEAVE_CARD);
	FUNCTION_END (dwret);
}


DWORD WINAPI CardWriteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags,
	__in_bcount(cbData) PBYTE pbData,
	__in DWORD cbData)
{
	struct md_file *file = NULL;
	DWORD dwret;
   FUNCTION_BEGIN;

   logprintf(pCardData, 1, "CardWriteFile: dirName:'%s', fileName:'%s', flags:%u, pbData=%p, cbData=%u\n", 
      NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags, pbData, cbData);

	if(!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	check_reader_status(pCardData);

	if (g_bLogEnabled && pbData && cbData)   {
		logprintf(pCardData, 1, "CardWriteFile try to write (%i):\n", cbData);
		loghex(pCardData, 2, pbData, cbData);
	}

    if (md_is_read_only (pCardData))
    {
		logprintf(pCardData, 1, "card is read-only.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
    }

	dwret = md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		FUNCTION_END (dwret);
	}

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "set content of '%s' to:\n",  NULLSTR(pszFileName));
	   loghex(pCardData, 7, pbData, cbData);
   }

	dwret = md_fs_set_content(pCardData, file, pbData, cbData);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "cannot set file content: %li\n", dwret);
		FUNCTION_END (dwret);
	}

	if (pszDirectoryName && !_stricmp(pszDirectoryName, "mscp"))   {
		if ((strstr(pszFileName, "kxc") == pszFileName) || (strstr(pszFileName, "ksc") == pszFileName))	{
			dwret = md_pkcs15_store_certificate(pCardData, pszFileName, pbData, cbData);
			if (dwret != SCARD_S_SUCCESS)
				FUNCTION_END (dwret);
			logprintf(pCardData, 2, "md_pkcs15_store_certificate() OK\n");
		}
	}

	logprintf(pCardData, 2, "write '%s' ok.\n",  NULLSTR(pszFileName));
	FUNCTION_END (SCARD_S_SUCCESS);
}

DWORD WINAPI CardDeleteFile(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__in DWORD dwFlags)
{
	struct md_file *file = NULL;
	DWORD dwret;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardDeleteFile(%s, %s, 0x%.8X) called\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), dwFlags);

	if(!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

    if (md_is_read_only (pCardData))
    {
		logprintf(pCardData, 1, "card is read-only.\n");
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
    }

	check_reader_status(pCardData);

	dwret = md_fs_delete_file(pCardData, pszDirectoryName, pszFileName);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "CardDeleteFile(): delete file error: %X\n", dwret);
	}

	FUNCTION_END (dwret);
}


DWORD WINAPI CardEnumFiles(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__deref_out_ecount(*pdwcbFileName) LPSTR *pmszFileNames,
	__out LPDWORD pdwcbFileName,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	char mstr[0x100];
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
	size_t offs;
	LONG lRet;
	DWORD dwret;
	int rv;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardEnumFiles() directory '%s', pmszFileNames=%p, pdwcbFileName=%p, dwFlags=0x%.8X\n", 
      NULLSTR(pszDirectoryName), pmszFileNames, pdwcbFileName, dwFlags);

	if (!pCardData || !pCardData->hScard)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pmszFileNames || !pdwcbFileName)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwFlags)   {
		logprintf(pCardData, 1, "CardEnumFiles() dwFlags not 'zero' -- %X\n", dwFlags);
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD)lRet);

	rv = check_reader_status(pCardData);
	if (rv != SCARD_S_SUCCESS)
		GOTO_END(rv);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	memset(mstr, 0, sizeof(mstr));

	if (!pszDirectoryName || !strlen(pszDirectoryName))
		dir = &vs->root;
	else
		md_fs_find_directory(pCardData, NULL, pszDirectoryName, &dir);
	if (!dir)   {
		logprintf(pCardData, 2, "enum files() failed: directory '%s' not found\n", NULLSTR(pszDirectoryName));
		GOTO_END(SCARD_E_DIR_NOT_FOUND);
	}

	file = dir->files;
	for (offs = 0; file != NULL && offs < sizeof(mstr) - 10;)   {
		logprintf(pCardData, 2, "enum files(): file name '%s'\n", file->name);
		strcpy_s(mstr+offs, sizeof(mstr) - offs, file->name);
		offs += strlen(file->name) + 1;
		file = file->next;
	}
	mstr[offs] = 0;
	offs += 1;

	*pmszFileNames = (LPSTR)(*pCardData->pfnCspAlloc)(offs);
	if (*pmszFileNames == NULL)
		GOTO_END(SCARD_E_NO_MEMORY);

	CopyMemory(*pmszFileNames, mstr, offs);
	*pdwcbFileName = (DWORD) offs;
	dwret = SCARD_S_SUCCESS;
end:
	SCardEndTransactionPtr(pCardData->hScard, SCARD_LEAVE_CARD);
	FUNCTION_END (dwret);
}


DWORD WINAPI CardGetFileInfo(__in PCARD_DATA pCardData,
	__in_opt LPSTR pszDirectoryName,
	__in LPSTR pszFileName,
	__inout PCARD_FILE_INFO pCardFileInfo)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_directory *dir = NULL;
	struct md_file *file = NULL;
    DWORD dwret;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardGetFileInfo(dirName:'%s',fileName:'%s', out %p)\n", NULLSTR(pszDirectoryName), NULLSTR(pszFileName), pCardFileInfo);

    if (!pCardData || !pCardFileInfo || !pszFileName || strlen(pszFileName) == 0)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

    logprintf(pCardData, 2, "pCardFileInfo->dwVersion = %d\n", pCardFileInfo->dwVersion);

    if (pCardFileInfo->dwVersion > CARD_FILE_INFO_CURRENT_VERSION)
        FUNCTION_END (ERROR_REVISION_MISMATCH);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	dwret = md_fs_find_file(pCardData, pszDirectoryName, pszFileName, &file);
	if (!file)   {
		logprintf(pCardData, 2, "CardWriteFile(): file '%s' not found in '%s'\n", NULLSTR(pszFileName), NULLSTR(pszDirectoryName));
		FUNCTION_END (dwret);
	}

	pCardFileInfo->dwVersion = CARD_FILE_INFO_CURRENT_VERSION;
	pCardFileInfo->cbFileSize = (DWORD) file->size;
	pCardFileInfo->AccessCondition = file->acl;

	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardQueryFreeSpace(__in PCARD_DATA pCardData, __in DWORD dwFlags,
	__inout PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
   FUNCTION_BEGIN;

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 1, "CardQueryFreeSpace %p, dwFlags=0x%.8X, version=0x%.8X\n",
		   pCardFreeSpaceInfo, dwFlags, pCardFreeSpaceInfo? pCardFreeSpaceInfo->dwVersion : 0);
   }

   if (!pCardData || (dwFlags != 0))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	check_reader_status(pCardData);

	dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
	if (dwret != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 1, "CardQueryFreeSpace() md free space error");
		FUNCTION_END (dwret);
	}

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "FreeSpace:\n");
      loghex(pCardData, 7, (BYTE *)pCardFreeSpaceInfo, sizeof(*pCardFreeSpaceInfo));
   }
	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardQueryKeySizes(__in PCARD_DATA pCardData,
	__in  DWORD dwKeySpec,
	__in  DWORD dwFlags,
	__inout PCARD_KEY_SIZES pKeySizes)
{
	DWORD dwret;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardQueryKeySizes dwKeySpec=%X, dwFlags=%X, pKeySizes=%p, version=%X\n",  dwKeySpec, dwFlags, pKeySizes, (pKeySizes?pKeySizes->dwVersion:0));

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( dwFlags != 0 )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( dwKeySpec == 0 )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	dwret = md_query_key_sizes(pCardData, dwKeySpec, pKeySizes);
	if (dwret != SCARD_S_SUCCESS)
		FUNCTION_END (dwret);

	logprintf(pCardData, 7, "pKeySizes:\n");
	loghex(pCardData, 7, (BYTE *)pKeySizes, sizeof(*pKeySizes));
	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardRSADecrypt(__in PCARD_DATA pCardData,
	__inout PCARD_RSA_DECRYPT_INFO  pInfo)

{
	int r, opt_crypt_flags = 0;
	unsigned ui;
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_prkey_info *prkey_info;
	BYTE *pbuf = NULL, *pbuf2 = NULL;
	DWORD lg= 0, lg2 = 0;
	struct sc_pkcs15_object *pkey = NULL;
	struct sc_algorithm_info *alg_info = NULL;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardRSADecrypt (pInfo=%p)\n", pInfo);
	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pInfo)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( pInfo->pbData == NULL )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (pInfo->dwVersion > CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if ( pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_CURRENT_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if (pInfo->dwKeySpec != AT_KEYEXCHANGE)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	/* check if the container exists */
	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);

	check_reader_status(pCardData);

	logprintf(pCardData, 2, "CardRSADecrypt dwVersion=%u, bContainerIndex=%u,dwKeySpec=%u pbData=%p, cbData=%u\n",
		pInfo->dwVersion,pInfo->bContainerIndex ,pInfo->dwKeySpec, pInfo->pbData,  pInfo->cbData);

	if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO)
		logprintf(pCardData, 2, "  pPaddingInfo=%p dwPaddingType=0x%08X\n", pInfo->pPaddingInfo, pInfo->dwPaddingType);

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;

   if (!pkey || (!vs->p15_containers[pInfo->bContainerIndex].size_key_exchange))  {
		logprintf(pCardData, 2, "CardRSADecrypt prkey not found\n");
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);
	}

	/* input and output buffers are always the same size */
	pbuf = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf)
		FUNCTION_END (SCARD_E_NO_MEMORY);

	lg2 = pInfo->cbData;
	pbuf2 = pCardData->pfnCspAlloc(pInfo->cbData);
	if (!pbuf2) {
		pCardData->pfnCspFree(pbuf);
		FUNCTION_END (SCARD_E_NO_MEMORY);
	}

	/*inversion donnees*/
	for(ui = 0; ui < pInfo->cbData; ui++)
		pbuf[ui] = pInfo->pbData[pInfo->cbData-ui-1];
	logprintf(pCardData, 2, "Data to be decrypted (inverted):\n");
	loghex(pCardData, 7, pbuf, pInfo->cbData);

	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);
	alg_info = sc_card_find_rsa_alg(pkey->p15card->card, (unsigned int) prkey_info->modulus_length);
	if (!alg_info)   {
		logprintf(pCardData, 2, "Cannot get appropriate RSA card algorithm for key size %i\n", prkey_info->modulus_length);
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		FUNCTION_END (SCARD_F_INTERNAL_ERROR);
	}

	/* filter boggus input: the data to decrypt is shorter than the RSA key ? */
	if ( pInfo->cbData < prkey_info->modulus_length / 8)
	{
		/* according to the minidriver specs, this is the error code to return
		(instead of invalid parameter when the call is forwarded to the card implementation) */
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		FUNCTION_END (SCARD_E_INSUFFICIENT_BUFFER);
	}

	if (alg_info->flags & SC_ALGORITHM_RSA_RAW)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher: using RSA-RAW mechanism\n");
		
		if (prkey_info->path.len != 0 || prkey_info->path.aid.len != 0) {
			r = md_select_key_file(pkey->p15card, prkey_info);
			logprintf(pCardData, 2, "md_select_key_file returned %d\n", r);
			if (r < 0)
			{
				logprintf(pCardData, 2, "md_select_key_file error(%i): %s\n", r, sc_strerror(r));
				pCardData->pfnCspFree(pbuf);
				pCardData->pfnCspFree(pbuf2);
				FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE));
			}
		}

		r = sc_pkcs15_decipher(pkey->p15card, pkey, opt_crypt_flags, pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);

		if (r > 0) {
			/* Need to handle padding */
			if (pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) {
				logprintf(pCardData, 2, "sc_pkcs15_decipher: DECRYPT-INFO dwVersion=%u\n", pInfo->dwVersion);
				if (pInfo->dwPaddingType == CARD_PADDING_PKCS1)   {
					size_t temp = pInfo->cbData;
					logprintf(pCardData, 2, "sc_pkcs15_decipher: stripping PKCS1 padding\n");
					r = sc_pkcs1_strip_02_padding(vs->ctx, pbuf2, pInfo->cbData, pbuf2, &temp);
					pInfo->cbData = (DWORD) temp;
					if (r < 0)   {
						logprintf(pCardData, 2, "Cannot strip PKCS1 padding: %i\n", r);
						pCardData->pfnCspFree(pbuf);
						pCardData->pfnCspFree(pbuf2);
						FUNCTION_END (SCARD_F_INTERNAL_ERROR);
					}
				}
				else if (pInfo->dwPaddingType == CARD_PADDING_OAEP)   {
					/* TODO: Handle OAEP padding if present - can call PFN_CSP_UNPAD_DATA */
					logprintf(pCardData, 2, "OAEP padding not implemented\n");
					pCardData->pfnCspFree(pbuf);
					pCardData->pfnCspFree(pbuf2);
					FUNCTION_END (SCARD_F_INTERNAL_ERROR);
				}
			}
		}
	}
	else if (alg_info->flags & SC_ALGORITHM_RSA_PAD_PKCS1)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher: using RSA_PAD_PKCS1 mechanism\n");
		
		if (prkey_info->path.len != 0 || prkey_info->path.aid.len != 0) {
			r = md_select_key_file(pkey->p15card, prkey_info);
			logprintf(pCardData, 2, "md_select_key_file returned %d\n", r);
			if (r < 0)
			{
				logprintf(pCardData, 2, "md_select_key_file error(%i): %s\n", r, sc_strerror(r));
				pCardData->pfnCspFree(pbuf);
				pCardData->pfnCspFree(pbuf2);
				FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE));
			}
		}

		r = sc_pkcs15_decipher(pkey->p15card, pkey, opt_crypt_flags | SC_ALGORITHM_RSA_PAD_PKCS1,
				pbuf, pInfo->cbData, pbuf2, pInfo->cbData);
		logprintf(pCardData, 2, "sc_pkcs15_decipher returned %d\n", r);
		if (r > 0) {
			/* No padding info, or padding info none */
			if ((pInfo->dwVersion < CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) ||
					((pInfo->dwVersion >= CARD_RSA_KEY_DECRYPT_INFO_VERSION_TWO) && (pInfo->dwPaddingType == CARD_PADDING_NONE))) {
				if ((unsigned)r <= pInfo->cbData - 9)	{
					/* add pkcs1 02 padding */
					logprintf(pCardData, 2, "Add '%s' to the output data", "PKCS#1 BT02 padding");
					memset(pbuf, 0x30, pInfo->cbData);
					*(pbuf + 0) = 0;
					*(pbuf + 1) = 2;
					memcpy(pbuf + pInfo->cbData - r, pbuf2, r);
					*(pbuf + pInfo->cbData - r - 1) = 0;
					memcpy(pbuf2, pbuf, pInfo->cbData);
				}
			}
			else if (pInfo->dwPaddingType == CARD_PADDING_PKCS1) {
				/* PKCS1 padding is already handled by the card... */
				pInfo->cbData = r;
			}
			/* TODO: Handle OAEP padding if present - can call PFN_CSP_UNPAD_DATA */
		}
	}
	else    {
		logprintf(pCardData, 2, "CardRSADecrypt: no usable RSA algorithm\n");
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_decipher error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(pbuf);
		pCardData->pfnCspFree(pbuf2);
		FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE));
	}

	logprintf(pCardData, 2, "decrypted data(%i):\n", pInfo->cbData);
	loghex(pCardData, 7, pbuf2, pInfo->cbData);

	/*inversion donnees */
	for(ui = 0; ui < pInfo->cbData; ui++)
		pInfo->pbData[ui] = pbuf2[pInfo->cbData-ui-1];

	pCardData->pfnCspFree(pbuf);
	pCardData->pfnCspFree(pbuf2);
	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardSignData(__in PCARD_DATA pCardData, __inout PCARD_SIGNING_INFO pInfo)
{
	VENDOR_SPECIFIC *vs;
	ALG_ID hashAlg;
	sc_pkcs15_prkey_info_t *prkey_info;
	BYTE dataToSign[0x200];
	int r, opt_crypt_flags = 0, opt_hash_flags = 0;
	size_t dataToSignLen = sizeof(dataToSign);
	sc_pkcs15_object_t *pkey;
   FUNCTION_BEGIN;

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 1, "CardSignData (pInfo=%p)\n", pInfo);
      if (pInfo)
      {
         logprintf(pCardData, 1, "pInfo->dwVersion=%d\npInfo->pbData=%p\npInfo->dwKeySpec=%u\npInfo->bContainerIndex=%u\npInfo->dwSigningFlags=0x%.8X\npInfo->aiHashAlg=0x%.8X\n", 
            pInfo->dwVersion,pInfo->pbData,pInfo->dwKeySpec,pInfo->bContainerIndex,pInfo->dwSigningFlags, pInfo->aiHashAlg);
      }
   }

	if (!pCardData || !pInfo)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( ( pInfo->dwVersion != CARD_SIGNING_INFO_BASIC_VERSION   ) &&
			( pInfo->dwVersion != CARD_SIGNING_INFO_CURRENT_VERSION ) )
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if ( pInfo->pbData == NULL )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	switch(pInfo->dwKeySpec)
	{
	case AT_SIGNATURE:
	case AT_KEYEXCHANGE:
	case AT_ECDSA_P256:
	case AT_ECDSA_P384:
	case AT_ECDSA_P521:
	case AT_ECDHE_P256:
	case AT_ECDHE_P384:
	case AT_ECDHE_P521:
		break;
	default:
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}
	if (pInfo->dwSigningFlags & ~(CARD_PADDING_INFO_PRESENT | CARD_PADDING_NONE | CARD_BUFFER_SIZE_ONLY | CARD_PADDING_PKCS1 | CARD_PADDING_PSS | CARD_PADDING_OAEP))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "pInfo->pbData(%i) ", pInfo->cbData);
	   loghex(pCardData, 7, pInfo->pbData, pInfo->cbData);
   }

	hashAlg = pInfo->aiHashAlg;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (pInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END( SCARD_E_NO_KEY_CONTAINER);

	pkey = vs->p15_containers[pInfo->bContainerIndex].prkey_obj;
	if (!pkey)
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);
	prkey_info = (struct sc_pkcs15_prkey_info *)(pkey->data);

	check_reader_status(pCardData);

	if (dataToSignLen < pInfo->cbData)
		FUNCTION_END (SCARD_E_INSUFFICIENT_BUFFER);
	memcpy(dataToSign, pInfo->pbData, pInfo->cbData);
	dataToSignLen = pInfo->cbData;

	if (CARD_PADDING_INFO_PRESENT & pInfo->dwSigningFlags)   {
		BCRYPT_PKCS1_PADDING_INFO *pinf = (BCRYPT_PKCS1_PADDING_INFO *)pInfo->pPaddingInfo;
		if (CARD_PADDING_PSS == pInfo->dwPaddingType)   {
			logprintf(pCardData, 0, "unsupported paddingtype CARD_PADDING_PSS\n");
			FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
		}
		else if (CARD_PADDING_PKCS1 != pInfo->dwPaddingType)   {
			logprintf(pCardData, 0, "unsupported paddingtype\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
			
		if (!pinf->pszAlgId)   {
			/* hashAlg = CALG_SSL3_SHAMD5; */
			logprintf(pCardData, 3, "Using CALG_SSL3_SHAMD5  hashAlg\n");
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		}
		else   {
			if (wcscmp(pinf->pszAlgId, L"MD5") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
			else if (wcscmp(pinf->pszAlgId, L"SHA1") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHAMD5") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
			else if (wcscmp(pinf->pszAlgId, L"SHA224") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA224;
			else if (wcscmp(pinf->pszAlgId, L"SHA256") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA256;
			else if (wcscmp(pinf->pszAlgId, L"SHA384") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA384;
			else if (wcscmp(pinf->pszAlgId, L"SHA512") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA512;
			else if (wcscmp(pinf->pszAlgId, L"RIPEMD160") == 0)
				opt_hash_flags = SC_ALGORITHM_RSA_HASH_RIPEMD160;
			else
         {
				FUNCTION_END (SCARD_E_INVALID_PARAMETER);
         }
		}
	}
	else   {
		logprintf(pCardData, 3, "CARD_PADDING_INFO_PRESENT not set\n");

		if (hashAlg == CALG_MD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5;
		else if (hashAlg == CALG_SHA1)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA1;
		else if (hashAlg == CALG_SSL3_SHAMD5)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_MD5_SHA1;
		else if (hashAlg == CALG_SHA_256)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA256;
		else if (hashAlg == CALG_SHA_384)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA384;
		else if (hashAlg == CALG_SHA_512)
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_SHA512;
		else if (hashAlg == (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_RIPEMD160))
			opt_hash_flags = SC_ALGORITHM_RSA_HASH_RIPEMD160;
		else if (hashAlg !=0) {
			logprintf(pCardData, 0, "bogus aiHashAlg %i\n", hashAlg);
         FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
	}
	
	if (pInfo->dwSigningFlags & CARD_PADDING_NONE)
	{
		/* do not add the digest info when called from CryptSignHash(CRYPT_NOHASHOID)

		Note: SC_ALGORITHM_RSA_HASH_MD5_SHA1 aka CALG_SSL3_SHAMD5 do not have a digest info to be added
		      CryptSignHash(CALG_SSL3_SHAMD5,CRYPT_NOHASHOID) is the same than CryptSignHash(CALG_SSL3_SHAMD5)
		*/
		opt_hash_flags = 0;
	}

	/* From sc-minidriver_specs_v7.docx pp.76:
	 * 'The Base CSP/KSP performs the hashing operation on the data before passing it
	 *	to CardSignData for signature.'
	 * So, the SC_ALGORITHM_RSA_HASH_* flags should not be passed to pkcs15 library
	 *	when calculating the signature .
	 *
	 * From sc-minidriver_specs_v7.docx pp.76:
	 * 'If the aiHashAlg member is nonzero, it specifies the hash algorithm’s object identifier (OID)
	 *  that is encoded in the PKCS padding.'
	 * So, the digest info has be included into the data to be signed.
	 * */
	if (opt_hash_flags)   {
		logprintf(pCardData, 2, "include digest info of the algorithm 0x%08X\n", opt_hash_flags);
		dataToSignLen = sizeof(dataToSign);
		r = sc_pkcs1_encode(vs->ctx, opt_hash_flags | SC_ALGORITHM_RSA_PAD_NONE, pInfo->pbData, pInfo->cbData, dataToSign, &dataToSignLen, 0);
		if (r)   {
			logprintf(pCardData, 2, "PKCS#1 encode error %s\n", sc_strerror(r));
			FUNCTION_END (SCARD_E_INVALID_VALUE);
		}
	}

	if (pInfo->dwKeySpec == AT_SIGNATURE)
	{
		/* for signing key, padding is mandatory, so we check if input data has correct OID */
		unsigned int algorithm = 0;
		r = sc_pkcs1_strip_digest_info_prefix (&algorithm, dataToSign, (size_t) dataToSignLen, NULL, NULL);
		if (r < 0)
		{
			logprintf(pCardData, 0, "input data has no digest info prefix which is mandatory for AT_SIGNATURE\n");
			FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
		}
		else
		{
			opt_hash_flags = (int) algorithm;
		}
	}

	/* Compute output size */
	if ( prkey_info->modulus_length > 0) {
		/* RSA */
		pInfo->cbSignedData = (DWORD) prkey_info->modulus_length / 8;
		opt_crypt_flags = SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE;
	} else if ( prkey_info->field_length > 0) {
		opt_crypt_flags = SC_ALGORITHM_ECDSA_HASH_NONE;
		switch(prkey_info->field_length) {
			case 256:
				/* ECDSA_P256 */
				pInfo->cbSignedData = 256 / 8 * 2;
				break;
			case 384:
				/* ECDSA_P384 */
				pInfo->cbSignedData = 384 / 8 * 2;
				break;
			case 512:
				/* ECDSA_P512 : special case !!!*/
				pInfo->cbSignedData = 132;
				break;
			default:
				logprintf(pCardData, 0, "unknown ECC key size %i\n", prkey_info->field_length);
				FUNCTION_END (SCARD_E_INVALID_VALUE);
		}
	} else {
		logprintf(pCardData, 0, "invalid private key\n");
		FUNCTION_END (SCARD_E_INVALID_VALUE);
	}

	logprintf(pCardData, 3, "pInfo->cbSignedData = %d\n", pInfo->cbSignedData);

	pInfo->pbSignedData = NULL;

	if(!(pInfo->dwSigningFlags&CARD_BUFFER_SIZE_ONLY))   {
		int r,i;
		BYTE *pbuf = NULL;
		DWORD lg;

		lg = pInfo->cbSignedData;
		logprintf(pCardData, 3, "lg = %d\n", lg);
		pbuf = pCardData->pfnCspAlloc(lg);
		if (!pbuf)
			FUNCTION_END (SCARD_E_NO_MEMORY);

		logprintf(pCardData, 7, "Data to sign: ");
		loghex(pCardData, 7, dataToSign, dataToSignLen);

		pInfo->pbSignedData = (PBYTE) pCardData->pfnCspAlloc(pInfo->cbSignedData);
		if (!pInfo->pbSignedData)   {
			pCardData->pfnCspFree(pbuf);
			FUNCTION_END (SCARD_E_NO_MEMORY);
		}

		if (prkey_info->path.len != 0 || prkey_info->path.aid.len != 0) {
			r = md_select_key_file(pkey->p15card, prkey_info);
			logprintf(pCardData, 2, "md_select_key_file returned %d\n", r);
			if(r < 0)   {
				logprintf(pCardData, 2, "md_select_key_file error %s\n", sc_strerror(r));
				pCardData->pfnCspFree(pbuf);
				FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_F_INTERNAL_ERROR));
			}
		}

		r = sc_pkcs15_compute_signature(pkey->p15card, pkey, opt_crypt_flags, dataToSign, dataToSignLen, pbuf, lg);
		logprintf(pCardData, 2, "sc_pkcs15_compute_signature return %d\n", r);
		if(r < 0)   {
			logprintf(pCardData, 2, "sc_pkcs15_compute_signature error %s\n", sc_strerror(r));
			pCardData->pfnCspFree(pbuf);
			FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_F_INTERNAL_ERROR));
		}

		pInfo->cbSignedData = r;

		
		/*revert data only for RSA (Microsoft uses the big endian version while everyone is using little endian*/
		if ( prkey_info->modulus_length > 0) {
			for(i = 0; i < r; i++)
				pInfo->pbSignedData[i] = pbuf[r-i-1];
		} else {
			for(i = 0; i < r; i++)
				pInfo->pbSignedData[i] = pbuf[i];
		}

		pCardData->pfnCspFree(pbuf);

		logprintf(pCardData, 7, "Signature (inverted): ");
		loghex(pCardData, 7, pInfo->pbSignedData, pInfo->cbSignedData);
	}

	logprintf(pCardData, 3, "CardSignData, dwVersion=%u, name=%S, hScard=0x%08X, hSCardCtx=0x%08X\n",
			pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName),pCardData->hScard, pCardData->hSCardCtx);

	FUNCTION_END (SCARD_S_SUCCESS);
}

DWORD WINAPI CardConstructDHAgreement(__in PCARD_DATA pCardData,
	__inout PCARD_DH_AGREEMENT_INFO pAgreementInfo)
{
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_object *pkey = NULL;
	int r, opt_derive_flags = 0;
	u8* out = 0;
	unsigned long outlen = 0;
	PBYTE pbPublicKey = NULL;
	DWORD dwPublicKeySize = 0;
	struct md_dh_agreement* dh_agreement = NULL;
	struct md_dh_agreement* temp = NULL;
	BYTE i;
   FUNCTION_BEGIN;

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 1, "CardConstructDHAgreement (pAgreementInfo=%p)\n", pAgreementInfo);
      if (pAgreementInfo)
      {
         logprintf(pCardData, 2, "pAgreementInfo->dwVersion=%u\npAgreementInfo->bContainerIndex=%u\npAgreementInfo->pbPublicKey=%p\npAgreementInfo->dwPublicKey=%u\n",
		      pAgreementInfo->dwVersion,pAgreementInfo->bContainerIndex , pAgreementInfo->pbPublicKey,  pAgreementInfo->dwPublicKey);
      }
   }

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pAgreementInfo)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( pAgreementInfo->pbPublicKey == NULL )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (pAgreementInfo->dwVersion > CARD_DH_AGREEMENT_INFO_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if ( pAgreementInfo->dwVersion < CARD_DH_AGREEMENT_INFO_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	/* check if the container exists */
	if (pAgreementInfo->bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);

	check_reader_status(pCardData);

	pkey = vs->p15_containers[pAgreementInfo->bContainerIndex].prkey_obj;
    if (!pkey)   {
		logprintf(pCardData, 2, "CardConstructDHAgreement prkey not found\n");
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);
	}

	/* convert the Windows public key into an OpenSC public key */
	dwPublicKeySize = pAgreementInfo->dwPublicKey - sizeof(BCRYPT_ECCKEY_BLOB) + 1;
	pbPublicKey = (PBYTE) pCardData->pfnCspAlloc(dwPublicKeySize);
	if (!pbPublicKey) {
		FUNCTION_END (ERROR_OUTOFMEMORY);
	}

	pbPublicKey[0] = 4;
	memcpy(pbPublicKey+1, pAgreementInfo->pbPublicKey +  sizeof(BCRYPT_ECCKEY_BLOB), dwPublicKeySize-1);

	/* derive the key using the OpenSC functions */
	r = sc_pkcs15_derive(pkey->p15card, pkey, opt_derive_flags, pbPublicKey, dwPublicKeySize, out, &outlen );
	logprintf(pCardData, 2, "sc_pkcs15_derive returned %d\n", r);

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_derive error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(pbPublicKey);
		FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE));
	}

	out = pCardData->pfnCspAlloc(outlen);

	if (!out) {
		FUNCTION_END (ERROR_OUTOFMEMORY);
	}

	r = sc_pkcs15_derive(pkey->p15card, pkey, opt_derive_flags, pbPublicKey, dwPublicKeySize, out, &outlen );
	logprintf(pCardData, 2, "sc_pkcs15_derive returned %d\n", r);

	pCardData->pfnCspFree(pbPublicKey);

	if ( r < 0)   {
		logprintf(pCardData, 2, "sc_pkcs15_derive error(%i): %s\n", r, sc_strerror(r));
		pCardData->pfnCspFree(out);
		FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_E_INVALID_VALUE));
	}

	/* save the dh agreement for later use */

	/* try to find an empty index */
	for (i = 0; i < vs->allocatedAgreements; i++) {
		dh_agreement = vs->dh_agreements + i;
		if (dh_agreement->pbAgreement == NULL) {
			pAgreementInfo->bSecretAgreementIndex = i;
			dh_agreement->pbAgreement = out;
			dh_agreement->dwSize = outlen;
			FUNCTION_END (SCARD_S_SUCCESS);
		}
	}
	/* no empty space => need to allocate memory */
	temp = (struct md_dh_agreement*) pCardData->pfnCspAlloc((vs->allocatedAgreements+1) * sizeof(struct md_dh_agreement));
	if (!temp) {
		pCardData->pfnCspFree(out);
		FUNCTION_END (SCARD_E_NO_MEMORY);
	}
	if ((vs->allocatedAgreements) > 0) {
		memcpy(temp, vs->dh_agreements, sizeof(struct md_dh_agreement) * (vs->allocatedAgreements));
		pCardData->pfnCspFree(vs->dh_agreements);
	}
	vs->dh_agreements = temp;
	dh_agreement = vs->dh_agreements + (vs->allocatedAgreements);
	pAgreementInfo->bSecretAgreementIndex = (vs->allocatedAgreements);
	dh_agreement->pbAgreement = out;
	dh_agreement->dwSize = outlen;
	vs->allocatedAgreements++;
	FUNCTION_END (SCARD_S_SUCCESS);
}


DWORD WINAPI CardDeriveHashOrHMAC(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo,
	__in struct md_dh_agreement* agreement,
	__in PWSTR szAlgorithm,
	__in PBYTE pbHmacKey, __in DWORD dwHmacKeySize 
	)
{
	DWORD dwReturn = 0;
	/* CNG variables */
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	DWORD dwSize, dwHashSize;
	PBYTE pbBuffer = NULL;
	DWORD dwBufferSize = 0;
	ULONG i;
	NCryptBufferDesc* parameters = NULL;

	dwReturn = BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgorithm, NULL, (pbHmacKey?BCRYPT_ALG_HANDLE_HMAC_FLAG:0));
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to find a provider for the algorithm %S 0x%08X\n", szAlgorithm, dwReturn);
		goto cleanup;
	}
	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the hash length\n");
		goto cleanup;
	}
	pAgreementInfo->cbDerivedKey = dwHashSize;
	if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY) {
		dwReturn = SCARD_S_SUCCESS;
		goto cleanup;
	}
	pAgreementInfo->pbDerivedKey = (PBYTE)pCardData->pfnCspAlloc(dwHashSize);
	if (pAgreementInfo->pbDerivedKey == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}

	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBufferSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the buffer length 0x%08X\n", dwReturn);
		goto cleanup;
	}

	pbBuffer = (PBYTE)LocalAlloc(0, dwBufferSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0) {
		dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, pbHmacKey, dwHmacKeySize, 0);
	}
	else {
		dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, NULL, 0, 0);
	}
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to create the alg object 0x%08X\n", dwReturn);
		goto cleanup;
	}

	parameters = (NCryptBufferDesc*) pAgreementInfo->pParameterList;
	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			if (buffer->BufferType == KDF_SECRET_PREPEND) {
				dwReturn = BCryptHashData(hHash, (PUCHAR)buffer->pvBuffer, buffer->cbBuffer, 0);
				if (dwReturn) {
					logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
					goto cleanup;
				}
			}
		}
	}

	dwReturn = BCryptHashData(hHash, (PUCHAR)agreement->pbAgreement, agreement->dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
		goto cleanup;
	}

	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			if (buffer->BufferType == KDF_SECRET_APPEND) {
				dwReturn = BCryptHashData(hHash, (PUCHAR)buffer->pvBuffer, buffer->cbBuffer, 0);
				if (dwReturn) {
					logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
					goto cleanup;
				}
			}
		}
	}

	dwReturn = BCryptFinishHash(hHash, pAgreementInfo->pbDerivedKey, pAgreementInfo->cbDerivedKey, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to finish hash 0x%08X\n", dwReturn);
		goto cleanup;
	}

cleanup:

	if (hHash)
		BCryptDestroyHash(hHash);
	if (pbBuffer)
		LocalFree(pbBuffer);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return dwReturn;
}

/* Generic function to perform hash. Could have been OpenSSL but used BCrypt* functions.
BCrypt is loaded as a delay load library. The dll can be loaded into Windows XP until this code is called.
Hopefully, ECC is not available in Windows XP and BCrypt functions are not called */
DWORD HashDataWithBCrypt(__in PCARD_DATA pCardData, BCRYPT_ALG_HANDLE hAlgorithm, 
		PBYTE pbOuput, DWORD dwOutputSize, PBYTE pbSecret, DWORD dwSecretSize, 
		PBYTE pbData1, DWORD dwDataSize1,
		PBYTE pbData2, DWORD dwDataSize2, 
		PBYTE pbData3, DWORD dwDataSize3 )
{
	DWORD dwReturn, dwSize, dwBufferSize;
	BCRYPT_HASH_HANDLE hHash = NULL;
	PBYTE pbBuffer = NULL;
	
	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&dwBufferSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the buffer length 0x%08X\n", dwReturn);
		goto cleanup;
	}
	pbBuffer = (PBYTE)LocalAlloc(0, dwBufferSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	dwReturn = BCryptCreateHash(hAlgorithm, &hHash, pbBuffer, dwBufferSize, pbSecret, dwSecretSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to create the alg object 0x%08X\n", dwReturn);
		goto cleanup;
	}
	if (pbData1) {
		dwReturn = BCryptHashData(hHash, pbData1, dwDataSize1, 0);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
			goto cleanup;
		}
	}
	if (pbData2) {
		dwReturn = BCryptHashData(hHash, pbData2, dwDataSize2, 0);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
			goto cleanup;
		}
	}
	if (pbData3) {
		dwReturn = BCryptHashData(hHash, pbData3, dwDataSize3, 0);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: unable to hash data 0x%08X\n", dwReturn);
			goto cleanup;
		}
	}
	dwReturn = BCryptFinishHash(hHash, pbOuput, dwOutputSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to finish hash 0x%08X\n", dwReturn);
		goto cleanup;
	}
cleanup:
	if (hHash)
		BCryptDestroyHash(hHash);
	if (pbBuffer)
		LocalFree(pbBuffer);
	return dwReturn;
}

/* Generic function for TLS PRF. Compute the P_HASH function */
DWORD WINAPI DoTlsPrf(__in PCARD_DATA pCardData,
					__in PBYTE pbOutput,
					__in PBYTE pbSecret,
					__in DWORD dwSecretSize,
					__in PWSTR szAlgorithm,
					__in PBYTE pbLabel, __in DWORD dwLabelSize,
					__in PBYTE pbSeed
	)
{
	DWORD dwReturn = 0, i;
	/* CNG variables */
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	DWORD dwSize, dwHashSize, dwNumberOfRounds, dwLastRoundSize;
	PBYTE pbBuffer = NULL;
	/* TLS intermediate results */
	PBYTE pbAx = NULL;
	
	dwReturn = BCryptOpenAlgorithmProvider(&hAlgorithm, szAlgorithm, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to find a provider for the algorithm %S 0x%08X\n", szAlgorithm, dwReturn);
		goto cleanup;
	}
	dwSize = sizeof(DWORD);
	dwReturn = BCryptGetProperty(hAlgorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&dwHashSize, dwSize, &dwSize, 0);
	if (dwReturn) {
		logprintf(pCardData, 0, "CardDeriveKey: unable to get the hash length\n");
		goto cleanup;
	}
	
	/* size is always 48 */
	dwLastRoundSize = TLS_DERIVE_KEY_SIZE % dwHashSize;
	if (dwLastRoundSize == 0) dwLastRoundSize = dwHashSize;
	dwNumberOfRounds = (DWORD) (TLS_DERIVE_KEY_SIZE / dwHashSize) + (dwLastRoundSize == dwHashSize?0:1);

	/* store TLS A1, A2 intermediate operations */
	pbAx = (PBYTE) LocalAlloc(0, dwNumberOfRounds * dwHashSize);
	if (pbAx == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}

	pbBuffer = (PBYTE) LocalAlloc(0, dwHashSize);
	if (pbBuffer == NULL) {
		dwReturn = SCARD_E_NO_MEMORY;
		goto cleanup;
	}
	
	for (i = 0; i<dwNumberOfRounds; i++) {
		/* A1, A2, ... */
		if (i == 0) {
			/* A(1) = HMAC_hash(secret, label + seed)*/
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbAx, dwHashSize, pbSecret, dwSecretSize, 
					pbLabel, dwLabelSize,
					pbSeed, 64, 
					NULL, 0);
		} else {
			/* A(i) = HMAC_hash(secret, A(i-1))*/
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbAx + i * dwHashSize, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + (i-1) * dwHashSize, dwHashSize,
					NULL, 0, 
					NULL, 0);
		}
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: unable to hash Ax 0x%08X\n", szAlgorithm, dwReturn);
			goto cleanup;
		}
		if (dwNumberOfRounds -1 == i) {
			/* last round */
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbBuffer, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + i * dwHashSize, dwHashSize,
					pbLabel, dwLabelSize,
					pbSeed, 64);
			memcpy(pbOutput + i * dwHashSize, pbBuffer, dwLastRoundSize);
		} else {
			dwReturn = HashDataWithBCrypt(pCardData, hAlgorithm, 
					pbOutput + i * dwHashSize, dwHashSize, pbSecret, dwSecretSize, 
					pbAx + i * dwHashSize, dwHashSize,
					pbLabel, dwLabelSize,
					pbSeed, 64);
		}
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: unable to hash Ax 0x%08X\n", szAlgorithm, dwReturn);
			goto cleanup;
		}
	}
	

cleanup:
	if (pbBuffer)
		LocalFree(pbBuffer);
	if (pbAx)
		LocalFree(pbAx);
	if (hAlgorithm)
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	return dwReturn;
}

/* Implement TLS 1.0, 1.1 and 1.2 PRF */
DWORD WINAPI CardDeriveTlsPrf(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo,
	__in struct md_dh_agreement* agreement,
	__in DWORD dwProtocol,
	__in PWSTR szAlgorithm,
	__in PBYTE pbLabel, __in DWORD dwLabelSize,
	__in PBYTE pbSeed
	)
{
	DWORD dwReturn = 0;
	PBYTE pbBuffer = NULL;
	DWORD i;
	if(dwProtocol == 0) {
		dwProtocol = TLS1_0_PROTOCOL_VERSION;
	} else if (dwProtocol == TLS1_0_PROTOCOL_VERSION || dwProtocol == TLS1_1_PROTOCOL_VERSION) {
		/* TLS 1.0 & 1.1 */
	} else if (dwProtocol == TLS1_2_PROTOCOL_VERSION) {
		/* TLS 1.2 */
		if (szAlgorithm && wcscmp(szAlgorithm, BCRYPT_SHA256_ALGORITHM) != 0 && wcscmp(szAlgorithm, BCRYPT_SHA384_ALGORITHM) != 0) {
			logprintf(pCardData, 0, "CardDeriveKey: The algorithm for TLS_PRF is invalid %S\n", szAlgorithm);
			return SCARD_E_INVALID_PARAMETER;
		}
	} else {
		logprintf(pCardData, 0, "CardDeriveTlsPrf: TLS protocol unknwon 0x%08X\n", dwReturn);
		return SCARD_E_INVALID_PARAMETER;
	}
	/* size is always 48 according to msdn */
	pAgreementInfo->cbDerivedKey = TLS_DERIVE_KEY_SIZE;
	if (pAgreementInfo->dwFlags & CARD_BUFFER_SIZE_ONLY) {
		return SCARD_S_SUCCESS;
	}

	pAgreementInfo->pbDerivedKey = (PBYTE)pCardData->pfnCspAlloc(TLS_DERIVE_KEY_SIZE);
	if (pAgreementInfo->pbDerivedKey == NULL) {
		return SCARD_E_NO_MEMORY;
	}

	if (dwProtocol == TLS1_0_PROTOCOL_VERSION || dwProtocol == TLS1_1_PROTOCOL_VERSION) {
		/* TLS 1.0 & 1.1 */
		DWORD dwNewSecretLength = (((agreement->dwSize) + (2) - 1) / (2));
		dwReturn = DoTlsPrf(pCardData,
						pAgreementInfo->pbDerivedKey,
						agreement->pbAgreement,
						dwNewSecretLength,
						BCRYPT_MD5_ALGORITHM,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n", szAlgorithm, dwReturn);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
		pbBuffer = (PBYTE) LocalAlloc(0, TLS_DERIVE_KEY_SIZE);
		if (!pbBuffer) {
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return SCARD_E_NO_MEMORY;
		}
		dwReturn = DoTlsPrf(pCardData,
						pbBuffer,
						agreement->pbAgreement + dwNewSecretLength,
						dwNewSecretLength,
						BCRYPT_SHA1_ALGORITHM,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n", szAlgorithm, dwReturn);
			LocalFree(pbBuffer);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
		for (i = 0; i< TLS_DERIVE_KEY_SIZE; i++) {
			pAgreementInfo->pbDerivedKey[i] = pAgreementInfo->pbDerivedKey[i] ^ pbBuffer[i];
		}
		LocalFree(pbBuffer);

	} else if (dwProtocol == TLS1_2_PROTOCOL_VERSION) {
		dwReturn = DoTlsPrf(pCardData,
						pAgreementInfo->pbDerivedKey,
						agreement->pbAgreement,
						agreement->dwSize,
						szAlgorithm,
						pbLabel, dwLabelSize,
						pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveTlsPrf: unable to DoTlsPrf with %S 0x%08X\n", szAlgorithm, dwReturn);
			pCardData->pfnCspFree(pAgreementInfo->pbDerivedKey );
			pAgreementInfo->pbDerivedKey  = NULL;
			return dwReturn;
		}
	}
	return SCARD_S_SUCCESS;
}

DWORD WINAPI CardDeriveKey(__in PCARD_DATA pCardData,
	__inout PCARD_DERIVE_KEY pAgreementInfo)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwAgreementIndex = 0;
	struct md_dh_agreement* agreement = NULL;
	NCryptBufferDesc* parameters = NULL;
	ULONG i;
	DWORD dwReturn = 0;
	/* store parameter references */
	PWSTR szAlgorithm = NULL;
	PBYTE pbHmacKey = NULL;
	DWORD dwHmacKeySize = 0;
	PBYTE pbLabel = NULL;
	DWORD dwLabelSize = 0;
	PBYTE pbSeed = NULL;
	DWORD dwProtocol = 0;
   FUNCTION_BEGIN;
	
   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 1, "CardDeriveKey (pAgreementInfo=%p)\n", pAgreementInfo);
      if (pAgreementInfo)
      {
         logprintf(pCardData, 1, "pAgreementInfo->dwVersion=%u\n", pAgreementInfo->dwVersion);
         logprintf(pCardData, 1, "pAgreementInfo->dwFlags=%u\n", pAgreementInfo->dwFlags);
         logprintf(pCardData, 1, "pAgreementInfo->pwszKDF=%S\n", NULLWSTR(pAgreementInfo->pwszKDF));
         logprintf(pCardData, 1, "pAgreementInfo->bSecretAgreementIndex=%d\n", (int) pAgreementInfo->bSecretAgreementIndex);
         logprintf(pCardData, 1, "pAgreementInfo->pParameterList=%p\n", pAgreementInfo->pParameterList);
         logprintf(pCardData, 1, "pAgreementInfo->pbDerivedKey=%p\n", pAgreementInfo->pbDerivedKey);
         logprintf(pCardData, 1, "pAgreementInfo->cbDerivedKey=%u\n", pAgreementInfo->cbDerivedKey);
      }
   }

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pAgreementInfo)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pAgreementInfo->dwVersion)
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if (pAgreementInfo->dwVersion > CARD_DERIVE_KEY_CURRENT_VERSION)
		FUNCTION_END (ERROR_REVISION_MISMATCH);
	if (pAgreementInfo->pwszKDF == NULL)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (pAgreementInfo->dwFlags & ~(KDF_USE_SECRET_AS_HMAC_KEY_FLAG | CARD_RETURN_KEY_HANDLE | CARD_BUFFER_SIZE_ONLY))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	/* according to the documenation, CARD_DERIVE_KEY_CURRENT_VERSION should be equal to 2. 
	In pratice it is not 2 but 1

	if ( pAgreementInfo->dwVersion < CARD_DERIVE_KEY_CURRENT_VERSION
			&& pCardData->dwVersion == CARD_DATA_CURRENT_VERSION)
		return ERROR_REVISION_MISMATCH;*/

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	/* check if the agreement index is ok */
	if (pAgreementInfo->bSecretAgreementIndex >= vs->allocatedAgreements) {
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	agreement = vs->dh_agreements + pAgreementInfo->bSecretAgreementIndex;
	if (agreement->pbAgreement == NULL) {
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	if (pAgreementInfo->dwFlags & CARD_RETURN_KEY_HANDLE ) {
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	/* find the algorithm, checks parameters */

	parameters = (NCryptBufferDesc*)pAgreementInfo->pParameterList;
	
	if (parameters) {
		for (i = 0; i < parameters->cBuffers; i++) {
			NCryptBuffer* buffer = parameters->pBuffers + i;
			switch(buffer->BufferType) {
				case KDF_HASH_ALGORITHM:
					if (szAlgorithm != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one algorithm\n");
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA1_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA1_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA256_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA256_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA384_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA384_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_SHA512_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_SHA512_ALGORITHM;
					} else if (wcscmp((PWSTR) buffer->pvBuffer, BCRYPT_MD5_ALGORITHM) == 0) {
						szAlgorithm = BCRYPT_MD5_ALGORITHM;
					} else {
						logprintf(pCardData, 0, "CardDeriveKey: unsupported algorithm %S\n", buffer->pvBuffer);
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					break;
				case KDF_HMAC_KEY:
					if (pbHmacKey != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one hhmac key\n");
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					pbHmacKey = (PBYTE) buffer->pvBuffer;
					dwHmacKeySize = buffer->cbBuffer;
					break;
				case KDF_SECRET_APPEND:
				case KDF_SECRET_PREPEND:
					/* do not throw an error for invalid arg*/
					break;
				case KDF_TLS_PRF_LABEL:
					if (pbLabel != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one Label\n");
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					pbLabel = (PBYTE)buffer->pvBuffer;
					dwLabelSize = buffer->cbBuffer;
					break;
				case KDF_TLS_PRF_SEED:
					if (pbSeed != NULL) {
						logprintf(pCardData, 0, "CardDeriveKey: got more than one Seed\n");
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					if (buffer->cbBuffer != 64)
					{
						logprintf(pCardData, 0, "CardDeriveKey: invalid seed size %u\n", buffer->cbBuffer);
						FUNCTION_END (SCARD_E_INVALID_PARAMETER);
					}
					pbSeed = (PBYTE)buffer->pvBuffer;
					break;
				case KDF_TLS_PRF_PROTOCOL:
					dwProtocol = *((PDWORD)buffer->pvBuffer);
					break;
				/*case KDF_ALGORITHMID:
				case KDF_PARTYUINFO:
				case KDF_PARTYVINFO:
				case KDF_SUPPPUBINFO:
				case KDF_SUPPPRIVINFO:
					break;*/
				default:
					logprintf(pCardData, 0, "CardDeriveKey: unknown buffer type %u\n", (parameters->pBuffers + i)->BufferType);
					FUNCTION_END (SCARD_E_INVALID_PARAMETER);
			}
		}
	}
	/* default parameters */
	if (szAlgorithm == NULL && wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) != 0) {
		szAlgorithm = BCRYPT_SHA1_ALGORITHM;
	}
	
	/* check the values with the KDF choosen */
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HASH) == 0) {
	}
	else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0) {
		if (pbHmacKey == NULL) {
			logprintf(pCardData, 0, "CardDeriveKey: no hhmac key for hmac KDF\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
	}
	else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) == 0) {
		if (!pbSeed) {
			logprintf(pCardData, 0, "CardDeriveKey: No seed was provided\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
		if (!pbLabel) {
			logprintf(pCardData, 0, "CardDeriveKey: No label was provided\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
	} else {
		logprintf(pCardData, 0, "CardDeriveKey: unsupported KDF %S\n", pAgreementInfo->pwszKDF);
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	/* do the job for the KDF Hash & Hmac */
	if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HASH) == 0 ||
		wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_HMAC) == 0 ) {
		
		dwReturn = CardDeriveHashOrHMAC(pCardData, pAgreementInfo, agreement, szAlgorithm, pbHmacKey, dwHmacKeySize);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: got an error while deriving the Key (hash or HMAC) 0x%08X\n", dwReturn);
			FUNCTION_END (dwReturn);
		}

	} else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_TLS_PRF) == 0) {
		dwReturn = CardDeriveTlsPrf(pCardData, pAgreementInfo, agreement, dwProtocol, szAlgorithm, pbLabel, dwLabelSize, pbSeed);
		if (dwReturn) {
			logprintf(pCardData, 0, "CardDeriveKey: got an error while deriving the Key (TlsPrf) 0x%08X\n", dwReturn);
			FUNCTION_END (dwReturn);
		}
	}
	/*else if (wcscmp(pAgreementInfo->pwszKDF, BCRYPT_KDF_SP80056A_CONCAT ) == 0) {
	}*/


	FUNCTION_END (SCARD_S_SUCCESS);

}

DWORD WINAPI CardDestroyDHAgreement(
	__in PCARD_DATA pCardData,
	__in BYTE bSecretAgreementIndex,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	struct md_dh_agreement* agreement = NULL;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardDestroyDHAgreement (bSecretAgreementIndex=%d, dwFlags=0x%.8X)\n", bSecretAgreementIndex, dwFlags);

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (bSecretAgreementIndex >= vs->allocatedAgreements) {
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	agreement = vs->dh_agreements + bSecretAgreementIndex;
	if (agreement->pbAgreement == NULL) {
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}
	SecureZeroMemory(agreement->pbAgreement, agreement->dwSize);
	pCardData->pfnCspFree(agreement->pbAgreement);
	agreement->pbAgreement = 0;
	agreement->dwSize = 0;
	FUNCTION_END (SCARD_S_SUCCESS);
}

DWORD WINAPI CardGetChallengeEx(__in PCARD_DATA pCardData,
	__in PIN_ID PinId,
	__deref_out_bcount(*pcbChallengeData) PBYTE *ppbChallengeData,
	__out PDWORD pcbChallengeData,
	__in DWORD dwFlags)
{
   FUNCTION_BEGIN;
	logprintf(pCardData, 1, "CardGetChallengeEx - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

DWORD WINAPI CardAuthenticateEx(__in PCARD_DATA pCardData,
	__in   PIN_ID PinId,
	__in   DWORD dwFlags,
	__in_bcount(cbPinData) PBYTE pbPinData,
	__in   DWORD cbPinData,
	__deref_opt_out_bcount(*pcbSessionPin) PBYTE *ppbSessionPin,
	__out_opt PDWORD pcbSessionPin,
	__out_opt PDWORD pcAttemptsRemaining)
{
	VENDOR_SPECIFIC *vs;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info = NULL;
   BOOL DisplayPinpadUI = FALSE;
	int r;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardAuthenticateEx: PinId=%u, dwFlags=0x%08X, cbPinData=%u, Attempts %s\n",
		PinId, dwFlags, cbPinData, pcAttemptsRemaining ? "YES" : "NO");

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	r = check_reader_status(pCardData);

	if (dwFlags & ~(CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN | CARD_PIN_SILENT_CONTEXT))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if ((dwFlags & (CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN)) == (CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if (dwFlags & (CARD_AUTHENTICATE_GENERATE_SESSION_PIN | CARD_AUTHENTICATE_SESSION_PIN)) {
		if (! (vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
			FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	/* using a pin pad */
	if (NULL == pbPinData) {
		if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	if ((dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN) && pbPinData)
	{
		logprintf(pCardData, 2, "pbPinData non NULL while asking to generated session: error.");
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	if (PinId != ROLE_USER && PinId != ROLE_ADMIN && PinId != MD_ROLE_USER_SIGN)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

	r = md_get_pin_by_role(pCardData, PinId, &pin_obj);
	if (r != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object");
		FUNCTION_END (r);
	}

	if (!pin_obj)
		FUNCTION_END (SCARD_F_INTERNAL_ERROR);
	auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;

	/* Do we need to display a prompt to enter PIN on pin pad? */
	logprintf(pCardData, 7, "PIN pad=%s, pbPinData=%p, hwndParent=%p\n",
		vs->reader->capabilities & SC_READER_CAP_PIN_PAD ? "yes" : "no", pbPinData, vs->hwndParent);

	/* using a pin pad */
	if (  (NULL == pbPinData) 
      && !(dwFlags & CARD_PIN_SILENT_CONTEXT)
      && (vs->reader->capabilities & SC_READER_CAP_PIN_PAD)
      )
   {
		DisplayPinpadUI = TRUE;
	}

	/* check if the pin is the session pin generated by a previous authentication with a pinpad */
	if (pbPinData != NULL && cbPinData == (sizeof(MAGIC_SESSION_PIN) + sizeof (DWORD) + sizeof (time_t))  && memcmp(MAGIC_SESSION_PIN, pbPinData, sizeof(MAGIC_SESSION_PIN)) == 0) {
		/* extract PIN ID */
		PIN_ID sessionPinID;
		memcpy (&sessionPinID, pbPinData + sizeof(MAGIC_SESSION_PIN), sizeof (DWORD));

		if ((dwFlags & CARD_AUTHENTICATE_SESSION_PIN) && (sessionPinID == PinId))
		{
			time_t t1, t2 = time(NULL);
			memcpy (&t1, pbPinData + sizeof(MAGIC_SESSION_PIN) + sizeof (DWORD), sizeof (time_t));

         /* check that we are still authenticated */
         r = md_perform_pin_operation(pCardData, SC_PIN_CMD_VERIFY, pin_obj->p15card, NULL, pin_obj, (const u8 *) "", 0, NULL, 0);
         if (r == 0)
         {
			   if (t2 >= t1 && (t2 - t1) <= 180) /* 3 minutes max validity of session PIN */
			   {
				   logprintf(pCardData, 2, "Session Pin value is correct.\n");
				   FUNCTION_END (SCARD_S_SUCCESS);
			   }
			   else
			   {
				   logprintf(pCardData, 2, "Session Pin has expired\n");
				   FUNCTION_END (SCARD_W_WRONG_CHV);
			   }
         }
         else
         {
				logprintf(pCardData, 2, "Card not authenticated. Session Pin can't ve used\n");
				FUNCTION_END (SCARD_W_WRONG_CHV);
         }
		}
		else
		{
			logprintf(pCardData, 2, "Session Pin is invalid (wrong Pin ID)\n");
			FUNCTION_END (SCARD_W_WRONG_CHV);
		}
	}

   if (DisplayPinpadUI)
      DisplayPinPadDlg (vs->hwndParent, PinId);

	r = md_perform_pin_operation(pCardData, SC_PIN_CMD_VERIFY, pin_obj->p15card, NULL, pin_obj, (const u8 *) pbPinData, cbPinData, NULL, 0);

   if (DisplayPinpadUI)
      HidePinPadDlg ();

	if (r)   {
		logprintf(pCardData, 1, "PIN code verification failed: %s; tries left %i\n", sc_strerror(r), auth_info->tries_left);

		if (r == SC_ERROR_AUTH_METHOD_BLOCKED) {
			if(pcAttemptsRemaining)
				(*pcAttemptsRemaining) = 0;
			FUNCTION_END (SCARD_W_CHV_BLOCKED);
		}

		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = auth_info->tries_left;
		FUNCTION_END (md_translate_OpenSC_to_Windows_error(r, SCARD_W_WRONG_CHV));
	}

	logprintf(pCardData, 2, "Pin code correct.\n");

	/* set the session pin according to the minidriver specification */
	if ((dwFlags & CARD_AUTHENTICATE_GENERATE_SESSION_PIN) && (vs->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
		/* we set it to a special value for pinpad authentication to force a new pinpad authentication */
		if (pcbSessionPin) *pcbSessionPin = sizeof(MAGIC_SESSION_PIN) + sizeof (DWORD) + sizeof (time_t);
		if (ppbSessionPin) {
			*ppbSessionPin = pCardData->pfnCspAlloc(sizeof(MAGIC_SESSION_PIN) + sizeof (DWORD) + sizeof (time_t));
			if (ppbSessionPin) {
				time_t t = time(NULL);
				memcpy(*ppbSessionPin, MAGIC_SESSION_PIN, sizeof(MAGIC_SESSION_PIN));
				memcpy((*ppbSessionPin) + sizeof(MAGIC_SESSION_PIN), &PinId, sizeof (PIN_ID));
				memcpy((*ppbSessionPin) + sizeof(MAGIC_SESSION_PIN) + sizeof (PIN_ID), &t, sizeof (time_t));
			}
		}
	} else {
		if (pcbSessionPin) *pcbSessionPin = 0;
		if (ppbSessionPin) *ppbSessionPin = NULL;
	}

	FUNCTION_END (SCARD_S_SUCCESS);
}

DWORD WINAPI CardChangeAuthenticatorEx(__in PCARD_DATA pCardData,
	__in   DWORD dwFlags,
	__in   PIN_ID dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in   DWORD cbAuthenticatingPinData,
	__in   PIN_ID dwTargetPinId,
	__in_bcount(cbTargetData) PBYTE pbTargetData,
	__in   DWORD cbTargetData,
	__in   DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	return InternalCardChangeAuthenticatorEx (pCardData, dwFlags, FALSE, dwAuthenticatingPinId, pbAuthenticatingPinData, cbAuthenticatingPinData,
		dwTargetPinId, pbTargetData, cbTargetData, cRetryCount, pcAttemptsRemaining);
}


DWORD WINAPI InternalCardChangeAuthenticatorEx(__in PCARD_DATA pCardData,
	__in   DWORD dwFlags,
	__in	 BOOL bSilent,
	__in   PIN_ID dwAuthenticatingPinId,
	__in_bcount(cbAuthenticatingPinData) PBYTE pbAuthenticatingPinData,
	__in   DWORD cbAuthenticatingPinData,
	__in   PIN_ID dwTargetPinId,
	__in_bcount(cbTargetData) PBYTE pbTargetData,
	__in   DWORD cbTargetData,
	__in   DWORD cRetryCount,
	__out_opt PDWORD pcAttemptsRemaining)
{
	VENDOR_SPECIFIC *vs = NULL;
	DWORD dw_rv;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_object *puk_obj = NULL;
	int rv;
	struct sc_pkcs15_auth_info *auth_info;
	BOOL DisplayPinpadUI = FALSE;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardChangeAuthenticatorEx: AuthenticatingPinId=%u, dwFlags=0x%08X, cbAuthenticatingPinData=%u, TargetPinId=%u, cbTargetData=%u, Attempts %s\n",
		dwAuthenticatingPinId, dwFlags, cbAuthenticatingPinData, dwTargetPinId, cbTargetData, pcAttemptsRemaining ? "YES" : "NO");

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if ((dwFlags != PIN_CHANGE_FLAG_UNBLOCK) && (dwFlags != PIN_CHANGE_FLAG_CHANGEPIN)){
		logprintf(pCardData, 1, "Unknown flag\n");
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	if (dwFlags & PIN_CHANGE_FLAG_UNBLOCK && dwAuthenticatingPinId == dwTargetPinId)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwAuthenticatingPinId != ROLE_USER && dwAuthenticatingPinId != MD_ROLE_USER_SIGN && (dwAuthenticatingPinId != ROLE_ADMIN))
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwTargetPinId != ROLE_USER && dwTargetPinId != MD_ROLE_USER_SIGN && dwTargetPinId != ROLE_ADMIN) {
        logprintf(pCardData, 1, "Only ROLE_USER, ROLE 3 or ROLE_ADMIN is supported\n");
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}
	/* according to the spec: cRetryCount MUST be zero */
	if (cRetryCount)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	check_reader_status(pCardData);

	if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD)) {
		if (pbAuthenticatingPinData == NULL  || cbAuthenticatingPinData == 0)    {
			logprintf(pCardData, 1, "Invalid current PIN data\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}

		if (pbTargetData == NULL  || cbTargetData == 0)   {
			logprintf(pCardData, 1, "Invalid new PIN data\n");
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
	}
	/* using a pin pad */
	if (  (NULL == pbAuthenticatingPinData)
      && !bSilent
      && (vs->reader->capabilities & SC_READER_CAP_PIN_PAD)
      )
   {
      DisplayPinpadUI = TRUE;
	}

	dw_rv = md_get_pin_by_role(pCardData, dwTargetPinId, &pin_obj);
	if (dw_rv != SCARD_S_SUCCESS)   {
		logprintf(pCardData, 2, "Cannot get User PIN object %s", (dwTargetPinId==ROLE_ADMIN?"admin":"user"));
		FUNCTION_END (dw_rv);
	}
	if (!pin_obj)
		FUNCTION_END (SCARD_F_INTERNAL_ERROR);

	if (dwFlags & PIN_CHANGE_FLAG_UNBLOCK)
	{
		dw_rv = md_get_pin_by_role(pCardData, ROLE_ADMIN, &puk_obj);
		if (dw_rv != SCARD_S_SUCCESS) {
			logprintf(pCardData, 2, "Cannot get User PIN object admin");
			FUNCTION_END(dw_rv);
		}
		if (!puk_obj)
			FUNCTION_END(SCARD_F_INTERNAL_ERROR);
	}

	if(pcAttemptsRemaining)
		(*pcAttemptsRemaining) = (DWORD) -1;

   if (DisplayPinpadUI)
      DisplayPinPadDlg (vs->hwndParent, dwTargetPinId);

	rv = md_perform_pin_operation(pCardData, (dwFlags & PIN_CHANGE_FLAG_UNBLOCK ? SC_PIN_CMD_UNBLOCK:SC_PIN_CMD_CHANGE), 
		pin_obj->p15card, (dwFlags & PIN_CHANGE_FLAG_UNBLOCK ? puk_obj : NULL), pin_obj, (const u8 *) pbAuthenticatingPinData, cbAuthenticatingPinData, pbTargetData, cbTargetData);

   if (DisplayPinpadUI)
      HidePinPadDlg (vs->hwndParent);
	
	if (rv)   {
		logprintf(pCardData, 2, "Failed to %s %s PIN: '%s' (%i)\n",
																(dwFlags & PIN_CHANGE_FLAG_CHANGEPIN?"change":"unblock"),
																(dwTargetPinId==ROLE_ADMIN?"admin":"user"), sc_strerror(rv), rv);
		auth_info = (struct sc_pkcs15_auth_info *)pin_obj->data;
		if (rv == SC_ERROR_AUTH_METHOD_BLOCKED) {
			if(pcAttemptsRemaining)
				(*pcAttemptsRemaining) = 0;
			FUNCTION_END (SCARD_W_CHV_BLOCKED);
		}

		if(pcAttemptsRemaining)
			(*pcAttemptsRemaining) = auth_info->tries_left;
		FUNCTION_END (md_translate_OpenSC_to_Windows_error(rv, SCARD_W_WRONG_CHV));
	}

	logprintf(pCardData, 7, "returns success\n");
	FUNCTION_END (SCARD_S_SUCCESS);
}

DWORD WINAPI CardDeauthenticateEx(__in PCARD_DATA pCardData,
	__in PIN_SET PinId,
	__in DWORD dwFlags)
{
   DWORD dwRet = SCARD_S_SUCCESS;
   PIN_SET inputPinSet = PinId;
   PIN_ID targetPin;
   VENDOR_SPECIFIC* vs = NULL;
   struct sc_pkcs15_card *p15card = NULL;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardDeauthenticateEx PinId=%d dwFlags=0x%08X\n",PinId, dwFlags);

	CLEAR_PIN (inputPinSet, ROLE_EVERYONE);
	CLEAR_PIN (inputPinSet, ROLE_USER);
	CLEAR_PIN (inputPinSet, ROLE_ADMIN);
	CLEAR_PIN (inputPinSet, MD_ROLE_USER_SIGN);

	if (	(dwFlags != 0)
		|| (!pCardData)
		|| (PinId == 0)
		|| (PinId > PIN_SET_ALL_ROLES)
		|| ((PinId != PIN_SET_ALL_ROLES) && ((inputPinSet != 0)))
		)
	{
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	}

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	if (IS_PIN_SET(PinId, ROLE_USER))
		targetPin = ROLE_USER;
	else if (IS_PIN_SET(PinId, ROLE_ADMIN))
		targetPin = ROLE_ADMIN;
	else if (IS_PIN_SET(PinId, MD_ROLE_USER_SIGN))
		targetPin = MD_ROLE_USER_SIGN;
	else
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	if (!vs->pin_objs[targetPin])
		FUNCTION_END(SCARD_E_INVALID_PARAMETER);

	p15card = vs->pin_objs[targetPin]->p15card;

	sc_pkcs15_free_object_content(vs->pin_objs[targetPin]);

	if (!(vs->reader->capabilities & SC_READER_CAP_PIN_PAD))
	{
		int rv = sc_pkcs15_logout_pin(p15card, vs->pin_objs[targetPin]);

		if (rv < 0)
		{
			/* force a reset of a card - SCARD_S_SUCCESS do not lead to the reset of the card and leave it still authenticated */
			dwRet = SCARD_E_UNSUPPORTED_FEATURE;
		}
	}

   FUNCTION_END (dwRet);
}

DWORD WINAPI CardGetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs = NULL;
	struct md_pkcs15_container *cont = NULL;
	LONG lRet;
	DWORD dwret;
	int rv;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardGetContainerProperty: bContainerIndex=%u, wszProperty=%S," \
		"cbData=%u, dwFlags=0x%08X\n",bContainerIndex,NULLWSTR(wszProperty),cbData,dwFlags);

	if (!pCardData || !pCardData->hScard) FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	if (!wszProperty)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pbData || !pdwDataLen)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (bContainerIndex >= MD_MAX_KEY_CONTAINERS)
		FUNCTION_END (SCARD_E_NO_KEY_CONTAINER);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD)lRet);

	rv = check_reader_status(pCardData);
	if (rv != SCARD_S_SUCCESS)
		GOTO_END(rv);

	/* the test for the existence of containers is redondant with the one made in CardGetContainerInfo but CCP_PIN_IDENTIFIER does not do it */
	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	cont = &vs->p15_containers[bContainerIndex];

	if (!cont->prkey_obj)   {
		logprintf(pCardData, 7, "Container %i is empty\n", bContainerIndex);
		GOTO_END(SCARD_E_NO_KEY_CONTAINER);
	}

	if (wcscmp(CCP_CONTAINER_INFO,wszProperty)  == 0)   {
      DWORD dwRet;
		PCONTAINER_INFO p = (PCONTAINER_INFO) pbData;
		if (pdwDataLen) *pdwDataLen = sizeof(*p);
		if (cbData >= sizeof(DWORD))
			if (p->dwVersion != CONTAINER_INFO_CURRENT_VERSION && p->dwVersion != 0 )
				GOTO_END(ERROR_REVISION_MISMATCH);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		dwRet = CardGetContainerInfo(pCardData,bContainerIndex,0,p);
		GOTO_END(dwRet);
	}

	if (wcscmp(CCP_PIN_IDENTIFIER,wszProperty) == 0)   {
		PPIN_ID p = (PPIN_ID) pbData;
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END( ERROR_INSUFFICIENT_BUFFER);
		if (cont->size_key_exchange || !cont->non_repudiation)
			*p = ROLE_USER;
		else
			*p = MD_ROLE_USER_SIGN;
		logprintf(pCardData, 2,"Return Pin id %u\n",*p);
		GOTO_END(SCARD_S_SUCCESS);
	}
	vs->lastChecked = GetTickCount64();
	dwret = SCARD_S_SUCCESS;
end:
	SCardEndTransactionPtr(pCardData->hScard, SCARD_LEAVE_CARD);
	FUNCTION_END (dwret);
}

DWORD WINAPI CardSetContainerProperty(__in PCARD_DATA pCardData,
	__in BYTE bContainerIndex,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen) PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
   FUNCTION_BEGIN;
	logprintf(pCardData, 1, "CardSetContainerProperty - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}


DWORD WINAPI CardGetProperty(__in PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__out_bcount_part_opt(cbData, *pdwDataLen) PBYTE pbData,
	__in DWORD cbData,
	__out PDWORD pdwDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret;
	LONG lRet;
	int rv;
   FUNCTION_BEGIN;

	logprintf(pCardData, 2, "CardGetProperty('%S',pbData=0x%p,cbData=%u,pdwDataLen=0x%p,dwFlags=%u) called\n", NULLWSTR(wszProperty),pbData, cbData,pdwDataLen,dwFlags);

	if (!pCardData || !pCardData->hScard || !wszProperty)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!pbData || !pdwDataLen)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
		FUNCTION_END((DWORD)lRet);

	rv = check_reader_status(pCardData);
	if (rv != SCARD_S_SUCCESS)
		GOTO_END(rv);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs || !vs->fws_data[0])
		GOTO_END(SCARD_E_INVALID_PARAMETER);

	if (wcscmp(CP_CARD_FREE_SPACE,wszProperty) == 0)   {
		PCARD_FREE_SPACE_INFO pCardFreeSpaceInfo = (PCARD_FREE_SPACE_INFO )pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*pCardFreeSpaceInfo);
		if (cbData < sizeof(*pCardFreeSpaceInfo))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		dwret = md_free_space(pCardData, pCardFreeSpaceInfo);
		if (dwret != SCARD_S_SUCCESS)   {
			logprintf(pCardData, 1, "Get free space error");
			GOTO_END(dwret);
		}
	}
	else if (wcscmp(CP_CARD_CAPABILITIES, wszProperty) == 0)   {
		PCARD_CAPABILITIES pCardCapabilities = (PCARD_CAPABILITIES )pbData;

        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*pCardCapabilities);
		if (cbData < sizeof(*pCardCapabilities))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		dwret = md_card_capabilities(pCardData, pCardCapabilities);
		if (dwret != SCARD_S_SUCCESS)
			GOTO_END( dwret );
	}
	else if (wcscmp(CP_CARD_KEYSIZES,wszProperty) == 0)   {
		PCARD_KEY_SIZES pKeySizes = (PCARD_KEY_SIZES )pbData;
        if (dwFlags > AT_ECDHE_P521)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*pKeySizes);
		if (cbData < sizeof(*pKeySizes))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		dwret = md_query_key_sizes(pCardData, dwFlags, pKeySizes);
		if (dwret != SCARD_S_SUCCESS)
			GOTO_END(dwret);
	}
	else if (wcscmp(CP_CARD_READ_ONLY, wszProperty) == 0)   {
		BOOL *p = (BOOL *)pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		*p = md_is_read_only(pCardData);
	}
	else if (wcscmp(CP_CARD_CACHE_MODE, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		*p = CP_CACHE_MODE_GLOBAL_CACHE;
	}
	else if (wcscmp(CP_SUPPORTS_WIN_X509_ENROLLMENT, wszProperty) == 0)   {
		BOOL *p = (BOOL *)pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		*p = md_is_supports_X509_enrollment(pCardData);
	}
	else if (wcscmp(CP_CARD_GUID, wszProperty) == 0)   {
		struct md_file *cardid = NULL;

        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		md_fs_find_file(pCardData, NULL, "cardid", &cardid);
		if (!cardid)   {
			logprintf(pCardData, 2, "file 'cardid' not found\n");
			GOTO_END(SCARD_E_FILE_NOT_FOUND);
		}

		if (pdwDataLen)
			*pdwDataLen = (DWORD) cardid->size;
		if (cbData < cardid->size)
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		CopyMemory(pbData, cardid->blob, cardid->size);
	}
	else if (wcscmp(CP_CARD_SERIAL_NO, wszProperty) == 0)   {
		unsigned char buf[64];
		size_t buf_len = sizeof(buf);
		struct sc_pkcs15_card *p15card = vs->fws_data[0]->p15card;
		size_t sn_len = strlen(p15card->tokeninfo->serial_number)/2;

		if (sc_hex_to_bin(p15card->tokeninfo->serial_number, buf, &buf_len))   {
			buf_len = strlen(p15card->tokeninfo->serial_number);
			if (buf_len > SC_MAX_SERIALNR) {
				buf_len = SC_MAX_SERIALNR;
			}
			memcpy(buf, p15card->tokeninfo->serial_number, buf_len);
		}
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = (DWORD) buf_len;
		if (cbData < buf_len)
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		CopyMemory(pbData, buf, buf_len);
	}
	else if (wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0)   {
		PPIN_INFO p = (PPIN_INFO) pbData;
        if (dwFlags != ROLE_USER && dwFlags != MD_ROLE_USER_SIGN && dwFlags != ROLE_ADMIN)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);

		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		if (p->dwVersion != PIN_INFO_CURRENT_VERSION)
			GOTO_END(ERROR_REVISION_MISMATCH);

		p->PinType = vs->reader->capabilities & SC_READER_CAP_PIN_PAD ? ExternalPinType : AlphaNumericPinType;
		p->dwFlags = 0;
		switch (dwFlags)   {
			case ROLE_USER:
				logprintf(pCardData, 2,"returning info on PIN ROLE_USER ( Auth ) [%u]\n",dwFlags);
				p->PinPurpose = AuthenticationPin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(ROLE_USER);
				p->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
				break;
			case ROLE_ADMIN:
				logprintf(pCardData, 2,"returning info on PIN ROLE_ADMIN ( Unblock ) [%u]\n",dwFlags);
				p->PinPurpose = UnblockOnlyPin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheNormal;
				p->dwChangePermission = CREATE_PIN_SET(ROLE_ADMIN);
				p->dwUnblockPermission = 0;
				break;
			case MD_ROLE_USER_SIGN:
				logprintf(pCardData, 2,"returning info on PIN MD_ROLE_USER_SIGN ( Sign ) [%u]\n",dwFlags);
				p->PinPurpose = DigitalSignaturePin;
				p->PinCachePolicy.dwVersion = PIN_CACHE_POLICY_CURRENT_VERSION;
				p->PinCachePolicy.dwPinCachePolicyInfo = 0;
				p->PinCachePolicy.PinCachePolicyType = PinCacheAlwaysPrompt;
				p->dwChangePermission = CREATE_PIN_SET(MD_ROLE_USER_SIGN);
				p->dwUnblockPermission = CREATE_PIN_SET(ROLE_ADMIN);
				break;
			default:
				logprintf(pCardData, 0,"Invalid Pin number %u requested\n",dwFlags);
				GOTO_END(SCARD_E_INVALID_PARAMETER);
		}
	}
	else if (wcscmp(CP_CARD_LIST_PINS,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		SET_PIN(*p, ROLE_USER);
		SET_PIN(*p, ROLE_ADMIN);
		SET_PIN(*p, MD_ROLE_USER_SIGN);
	}
	else if (wcscmp(CP_CARD_AUTHENTICATED_STATE,wszProperty) == 0)   {
		PPIN_SET p = (PPIN_SET) pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);

		logprintf(pCardData, 7, "CARD_AUTHENTICATED_STATE invalid\n");
		GOTO_END(SCARD_E_INVALID_PARAMETER);
	}
	else if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY,wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;

		if (dwFlags != ROLE_USER && dwFlags != MD_ROLE_USER_SIGN && dwFlags != ROLE_ADMIN)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		*p = CARD_PIN_STRENGTH_PLAINTEXT;
		if ((vs->reader->capabilities & SC_READER_CAP_PIN_PAD) && (dwFlags != ROLE_ADMIN))
			*p |= CARD_PIN_STRENGTH_SESSION_PIN;
	}
	else if (wcscmp(CP_KEY_IMPORT_SUPPORT, wszProperty) == 0)   {
		DWORD *p = (DWORD *)pbData;
        if (dwFlags != 0)
			GOTO_END(SCARD_E_INVALID_PARAMETER);
		if (pdwDataLen)
			*pdwDataLen = sizeof(*p);
		if (cbData < sizeof(*p))
			GOTO_END(ERROR_INSUFFICIENT_BUFFER);
		*p = 0;
	}
	else if (wcscmp(CP_ENUM_ALGORITHMS, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		GOTO_END(SCARD_E_INVALID_PARAMETER);
	}
	else if (wcscmp(CP_PADDING_SCHEMES, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		GOTO_END(SCARD_E_INVALID_PARAMETER);
	}
	else if (wcscmp(CP_CHAINING_MODES, wszProperty) == 0)   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		//TODO
		GOTO_END(SCARD_E_INVALID_PARAMETER);
	}
	else if (wcscmp(CP_CARD_PIN_STRENGTH_CHANGE,wszProperty) == 0)   {
		GOTO_END(SCARD_E_UNSUPPORTED_FEATURE);
    }
	else if (wcscmp(CP_CARD_PIN_STRENGTH_UNBLOCK,wszProperty) == 0)   {
		GOTO_END(SCARD_E_UNSUPPORTED_FEATURE);
    }
	else   {
		logprintf(pCardData, 3, "Unsupported property '%S'\n", wszProperty);
		GOTO_END(SCARD_E_INVALID_PARAMETER);

	}

   if (g_bLogEnabled)
   {
	   logprintf(pCardData, 7, "returns '%S' ", wszProperty);
	   loghex(pCardData, 7, pbData, *pdwDataLen);
   }
   dwret = SCARD_S_SUCCESS;
end:
   SCardEndTransactionPtr(pCardData->hScard, SCARD_S_SUCCESS);
	FUNCTION_END (dwret);
}

DWORD WINAPI CardSetProperty(__in   PCARD_DATA pCardData,
	__in LPCWSTR wszProperty,
	__in_bcount(cbDataLen)  PBYTE pbData,
	__in DWORD cbDataLen,
	__in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
   FUNCTION_BEGIN;

	logprintf(pCardData, 1, "CardSetProperty: wszProperty=\"%S\", pbData=0x%p, cbDataLen=%u, dwFlags=%u\n",\
		NULLWSTR(wszProperty),pbData,cbDataLen,dwFlags);

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);

	if (!wszProperty)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	/* the following properties cannot be set according to the minidriver specifications */
	if (wcscmp(wszProperty,CP_CARD_FREE_SPACE) == 0 ||
			wcscmp(wszProperty,CP_CARD_CAPABILITIES) == 0 ||
			wcscmp(wszProperty,CP_CARD_KEYSIZES) == 0 ||
			wcscmp(wszProperty,CP_CARD_LIST_PINS) == 0 ||
			wcscmp(wszProperty,CP_CARD_AUTHENTICATED_STATE) == 0 ||
            wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_VERIFY) == 0 ||
            wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_CHANGE) == 0 ||
            wcscmp(wszProperty,CP_CARD_PIN_STRENGTH_UNBLOCK) == 0 ||
			wcscmp(wszProperty,CP_KEY_IMPORT_SUPPORT) == 0 ||
			wcscmp(wszProperty,CP_ENUM_ALGORITHMS) == 0 ||
			wcscmp(wszProperty,CP_PADDING_SCHEMES) == 0 ||
			wcscmp(wszProperty,CP_CHAINING_MODES) == 0 ||
			wcscmp(wszProperty,CP_SUPPORTS_WIN_X509_ENROLLMENT) == 0 ||
			wcscmp(wszProperty,CP_CARD_CACHE_MODE) == 0 ||
			wcscmp(wszProperty,CP_CARD_SERIAL_NO) == 0
			)   {
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

    if (md_is_read_only (pCardData))
    {
        if (wcscmp(wszProperty,CP_CARD_PIN_INFO) == 0 ||
            wcscmp(wszProperty,CP_CARD_GUID) == 0
		)   {
		    FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	    }
    }

	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	/* the following properties can be set, but are not implemented by the minidriver */
	if (wcscmp(CP_CARD_PIN_STRENGTH_VERIFY, wszProperty) == 0 ||
			wcscmp(CP_CARD_PIN_INFO, wszProperty) == 0 ||
			wcscmp(CP_CARD_GUID, wszProperty) == 0 ) {
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	/* This property and CP_PIN_CONTEXT_STRING are set just prior to a call to
	 * CardAuthenticateEx if the PIN required is declared of type ExternalPinType.
	 */
	if (wcscmp(CP_PARENT_WINDOW, wszProperty) == 0) {
		if (cbDataLen != sizeof(HWND) || !pbData)   {
			FUNCTION_END (SCARD_E_INVALID_PARAMETER);
		}
		else   {
			HWND cp = *((HWND *) pbData);
			if (cp!=0 && !IsWindow(cp))
				FUNCTION_END (SCARD_E_INVALID_PARAMETER);
			vs->hwndParent = cp;
		}
		logprintf(pCardData, 3, "Saved parent window (%p)\n", vs->hwndParent);
		FUNCTION_END (SCARD_S_SUCCESS);
	}
	
	if (wcscmp(CP_PIN_CONTEXT_STRING, wszProperty) == 0) {
		vs->wszPinContext = (PWSTR) pbData;
		logprintf(pCardData, 3, "Saved PIN context string: %S\n", pbData? (PWSTR) pbData : L"");
		FUNCTION_END (SCARD_S_SUCCESS);
	}
	logprintf(pCardData, 3, "INVALID PARAMETER\n");
	FUNCTION_END (SCARD_E_INVALID_PARAMETER);
}


// 4.8 Secure key injection


/** The CardImportSessionKey function imports a temporary session key to the card.
The session key is encrypted with a key exchange key, and the function returns a
handle of the imported session key to the caller.*/

DWORD WINAPI CardImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in VOID  *pPaddingInfo,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out CARD_KEY_HANDLE  *phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(bContainerIndex);
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pPaddingInfo);
	UNREFERENCED_PARAMETER(pwszBlobType);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(phKey);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);

	logprintf(pCardData, 1, "CardImportSessionKey - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** The MDImportSessionKey function imports a temporary session key to the card minidriver
and returns a key handle to the caller.*/

DWORD WINAPI MDImportSessionKey(
    __in PCARD_DATA  pCardData,
    __in LPCWSTR  pwszBlobType,
    __in LPCWSTR  pwszAlgId,
    __out PCARD_KEY_HANDLE  phKey,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pwszBlobType);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(phKey);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);

	logprintf(pCardData, 1, "MDImportSessionKey - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** The MDEncryptData function uses a key handle to encrypt data with a symmetric key.
The data is encrypted in a format that the smart card supports.*/

DWORD WINAPI MDEncryptData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags,
    __deref_out_ecount(*pcEncryptedData)
        PCARD_ENCRYPTED_DATA  *ppEncryptedData,
    __out PDWORD  pcEncryptedData
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszSecureFunction);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);
	UNREFERENCED_PARAMETER(ppEncryptedData);
	UNREFERENCED_PARAMETER(pcEncryptedData);

	logprintf(pCardData, 1, "MDEncryptData - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}


/** The CardGetSharedKeyHandle function returns a session key handle to the caller.
Note:  The manner in which this session key has been established is outside the
scope of this specification. For example, the session key could be established
by either a permanent shared key or a key derivation algorithm that has occurred
before the call to CardGetSharedKeyHandle.*/

DWORD WINAPI CardGetSharedKeyHandle(
    __in PCARD_DATA  pCardData,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __deref_opt_out_bcount(*pcbOutput)
        PBYTE  *ppbOutput,
    __out_opt PDWORD  pcbOutput,
    __out PCARD_KEY_HANDLE  phKey
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(ppbOutput);
	UNREFERENCED_PARAMETER(pcbOutput);
	UNREFERENCED_PARAMETER(phKey);

	logprintf(pCardData, 1, "CardGetSharedKeyHandle - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** The CardDestroyKey function releases a temporary key on the card. The card
should delete all of the key material that is associated with that key handle.*/

DWORD WINAPI CardDestroyKey(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);

	logprintf(pCardData, 1, "CardDestroyKey - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** This function can be used to get properties for a cryptographic algorithm.*/
DWORD WINAPI CardGetAlgorithmProperty (
    __in PCARD_DATA  pCardData,
    __in LPCWSTR   pwszAlgId,
    __in LPCWSTR   pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen)
        PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(pwszAlgId);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbData);
	UNREFERENCED_PARAMETER(cbData);
	UNREFERENCED_PARAMETER(pdwDataLen);
	UNREFERENCED_PARAMETER(dwFlags);

	logprintf(pCardData, 1, "CardGetAlgorithmProperty - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** This function is used to get the properties of a key.*/
DWORD WINAPI CardGetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __out_bcount_part_opt(cbData, *pdwDataLen) PBYTE  pbData,
    __in DWORD  cbData,
    __out PDWORD  pdwDataLen,
    __in DWORD  dwFlags
    )
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbData);
	UNREFERENCED_PARAMETER(cbData);
	UNREFERENCED_PARAMETER(pdwDataLen);
	UNREFERENCED_PARAMETER(dwFlags);

	logprintf(pCardData, 1, "CardGetKeyProperty - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** This function is used to set the properties of a key.*/
DWORD WINAPI CardSetKeyProperty(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszProperty,
    __in_bcount(cbInput) PBYTE  pbInput,
    __in DWORD  cbInput,
    __in DWORD  dwFlags
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(dwFlags);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszProperty);
	UNREFERENCED_PARAMETER(pbInput);
	UNREFERENCED_PARAMETER(cbInput);
	UNREFERENCED_PARAMETER(dwFlags);

	logprintf(pCardData, 1, "CardSetKeyProperty - unsupported\n");
	FUNCTION_END ( SCARD_E_UNSUPPORTED_FEATURE );
}

/** CardProcessEncryptedData processes a set of encrypted data BLOBs by
sending them to the card where the data BLOBs are decrypted.*/

DWORD WINAPI CardProcessEncryptedData(
    __in PCARD_DATA  pCardData,
    __in CARD_KEY_HANDLE  hKey,
    __in LPCWSTR  pwszSecureFunction,
    __in_ecount(cEncryptedData)
        PCARD_ENCRYPTED_DATA  pEncryptedData,
    __in DWORD  cEncryptedData,
    __out_bcount_part_opt(cbOutput, *pdwOutputLen)
        PBYTE  pbOutput,
    __in DWORD  cbOutput,
    __out_opt PDWORD  pdwOutputLen,
    __in DWORD  dwFlags
)
{
   FUNCTION_BEGIN;
	UNREFERENCED_PARAMETER(pCardData);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pwszSecureFunction);
	UNREFERENCED_PARAMETER(pEncryptedData);
	UNREFERENCED_PARAMETER(cEncryptedData);
	UNREFERENCED_PARAMETER(pbOutput);
	UNREFERENCED_PARAMETER(cbOutput);
	UNREFERENCED_PARAMETER(pdwOutputLen);
	UNREFERENCED_PARAMETER(dwFlags);

	logprintf(pCardData, 1, "CardProcessEncryptedData - unsupported\n");
	FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
}

/** The CardCreateContainerEx function creates a new key container that the
container index identifies and the bContainerIndex parameter specifies. The function
associates the key container with the PIN that the PinId parameter specified.
This function is useful if the card-edge does not allow for changing the key attributes
after the key container is created. This function replaces the need to call
CardSetContainerProperty to set the CCP_PIN_IDENTIFIER property CardCreateContainer
is called.
The caller of this function can provide the key material that the card imports.
This is useful in those situations in which the card either does not support internal
key generation or the caller requests that the key be archived in the card.*/

DWORD WINAPI CardCreateContainer(
    __in PCARD_DATA  pCardData,
    __in BYTE  bContainerIndex,
    __in DWORD  dwFlags,
    __in DWORD  dwKeySpec,
    __in DWORD  dwKeySize,
    __in PBYTE  pbKeyData
)
{
   DWORD dwret;
   FUNCTION_BEGIN;
   logprintf(pCardData, 1, "CardCreateContainer: bContainerIndex=%d, dwFlags=%u, dwKeySpec=%u, dwKeySize=%u\n",
      (int) bContainerIndex, dwFlags, dwKeySpec, dwKeySize);
	dwret = CardCreateContainerEx(pCardData, bContainerIndex, dwFlags, dwKeySpec, dwKeySize, pbKeyData, ROLE_USER);
   FUNCTION_END (dwret);
}

DWORD WINAPI CardAcquireContext(__inout PCARD_DATA pCardData, __in DWORD dwFlags)
{
	VENDOR_SPECIFIC *vs;
	DWORD dwret, suppliedVersion = 0;
   char szReaderName[MAX_PATH];
   DWORD cbReaderName = MAX_PATH;
   BYTE rgbAtr[38];
   DWORD cbAtr = sizeof (rgbAtr);
   LONG lRet;
   BOOL bNew = FALSE;
	SCARD_READERSTATE_A readerState = {0};
	DWORD dwEventsCounter = 0;

   FUNCTION_BEGIN;

   if (g_bLogEnabled)
   {
      logprintf(pCardData, 1, "CardAcquireContext: dwFlags=%u\n", dwFlags);
      if (pCardData)
      {
	      logprintf(pCardData, 1, "pCardData->dwVersion=%u\npCardData->pwszCardName=%S\n",
		   	   pCardData->dwVersion, NULLWSTR(pCardData->pwszCardName));
      }
   }

	if (!pCardData)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (dwFlags)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if (!(dwFlags & CARD_SECURE_KEY_INJECTION_NO_CARD_MODE)) {
		if( pCardData->hSCardCtx == 0)   {
			logprintf(pCardData, 0, "Invalide handle.\n");
			FUNCTION_END (SCARD_E_INVALID_HANDLE);
		}
		if( pCardData->hScard == 0)   {
			logprintf(pCardData, 0, "Invalide handle.\n");
			FUNCTION_END (SCARD_E_INVALID_HANDLE);
		}
	}
	else
	{
		/* secure key injection not supported */
		FUNCTION_END (SCARD_E_UNSUPPORTED_FEATURE);
	}

	if (pCardData->pbAtr == NULL)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	if ( pCardData->pwszCardName == NULL )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	/* <2 lenght or >=0x22 are not ISO compliant */
	if (pCardData->cbAtr >= 0x22 || pCardData->cbAtr <= 0x2)
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);
	/* ATR beginning by 0x00 or 0xFF are not ISO compliant */
	if (pCardData->pbAtr[0] == 0xFF || pCardData->pbAtr[0] == 0x00)
		FUNCTION_END (SCARD_E_UNKNOWN_CARD);
	/* Memory management functions */
	if ( ( pCardData->pfnCspAlloc   == NULL ) ||
		( pCardData->pfnCspReAlloc == NULL ) ||
		( pCardData->pfnCspFree    == NULL ) )
		FUNCTION_END (SCARD_E_INVALID_PARAMETER);

	/* The lowest supported version is 6 - maximum is 7. */
	if (pCardData->dwVersion < MD_MINIMUM_VERSION_SUPPORTED)
		FUNCTION_END ((DWORD) ERROR_REVISION_MISMATCH);

	lRet = SCardBeginTransactionPtr(pCardData->hScard);
	if (lRet != SCARD_S_SUCCESS)
	{
		logprintf(pCardData, 1, "SCardBeginTransaction failed with error 0x%.8X\n", lRet);
		FUNCTION_END((DWORD)lRet);
	}

   lRet = SCardGetAttribPtr(pCardData->hScard, SCARD_ATTR_DEVICE_SYSTEM_NAME, (LPBYTE)szReaderName, &cbReaderName);
   if (lRet != SCARD_S_SUCCESS)
   {
      logprintf(pCardData, 1, "SCardGetAttrib(SCARD_ATTR_DEVICE_SYSTEM_NAME) failed with error 0x%.8X\n", lRet);
      GOTO_END (SCARD_E_UNKNOWN_CARD);
   }

   lRet = SCardGetAttribPtr(pCardData->hScard, SCARD_ATTR_ATR_STRING, rgbAtr, &cbAtr);
   if (lRet != SCARD_S_SUCCESS)
   {
      logprintf(pCardData, 1, "SCardGetAttrib(SCARD_ATTR_ATR_STRING) failed with error 0x%.8X\n", lRet);
	  GOTO_END(SCARD_E_UNKNOWN_CARD);
   }

	readerState.szReader = szReaderName;

	lRet = SCardGetStatusChangePtr (pCardData->hSCardCtx, 0, &readerState, 1);
   if (lRet != SCARD_S_SUCCESS)
   {
      logprintf(pCardData, 1, "SCardGetStatusChange failed with error 0x%.8X\n", lRet);
	  GOTO_END(SCARD_E_UNKNOWN_CARD);
   }

	dwEventsCounter = (readerState.dwEventState  >> 16) & 0x0000FFFF;

	suppliedVersion = pCardData->dwVersion;
	
	/* VENDOR SPECIFIC */
   vs = GetContext (pCardData, szReaderName, rgbAtr, cbAtr, &bNew);
   if (vs)
   {
      pCardData->pvVendorSpecific = vs;
      if (!bNew)
      {         
			if (dwEventsCounter == vs->dwEventsCounter)
			{
				logprintf(pCardData, 1, "Existing context found (vs=0x%p, vs->ctx=0x%p). Updating handles\n", vs, vs->ctx);
				sc_ctx_use_reader(vs->ctx, &pCardData->hSCardCtx, &pCardData->hScard);
			}
			else
			{
				logprintf(pCardData, 1, "Existing context found (vs=0x%p, vs->ctx=0x%p) but the card has changed. updating internal data.\n", vs, vs->ctx);
				
				disassociate_card(pCardData);
				if(vs->ctx)   {
					sc_release_context(vs->ctx);
				}
				md_fs_finalize(pCardData);

				memset(vs, 0, sizeof(VENDOR_SPECIFIC));
				bNew = TRUE;
			}
      }
      else
         logprintf(pCardData, 1, "New context created and added to global list (vs=0x%p).\n", vs);
   }
   else
   {
      bNew = TRUE;
	   vs = pCardData->pvVendorSpecific = pCardData->pfnCspAlloc(sizeof(VENDOR_SPECIFIC));
	   memset(vs, 0, sizeof(VENDOR_SPECIFIC));
      logprintf(pCardData, 1, "New standalone context created (vs=0x%p).\n", vs);
   }

	vs->hScard = pCardData->hScard;
	vs->hSCardCtx = pCardData->hSCardCtx;

   if (bNew)
   {
	   dwret = md_create_context(pCardData, vs);
	   if (dwret != SCARD_S_SUCCESS) {
		   DeleteContext(pCardData, TRUE);
		   GOTO_END(dwret);
	   }

	   dwret = associate_card(pCardData);
	   if (dwret != SCARD_S_SUCCESS) {
		   DeleteContext(pCardData, TRUE);
		   GOTO_END(dwret);
	   }

	   dwret = md_fs_init(pCardData);
	   if (dwret != SCARD_S_SUCCESS) {
		   DeleteContext(pCardData, TRUE);
		   GOTO_END(dwret);
	   }

		vs->dwEventsCounter = dwEventsCounter;

	   logprintf(pCardData, 1, "OpenSC init done.\n");
   }

	logprintf(pCardData, 2, "request version pCardData->dwVersion = %d\n", pCardData->dwVersion);
	pCardData->dwVersion = min(pCardData->dwVersion, MD_CURRENT_VERSION_SUPPORTED);
	logprintf(pCardData, 2, "pCardData->dwVersion = %d\n", pCardData->dwVersion);
   logprintf(pCardData, 1, "Supplied version %u - version used %u.\n", suppliedVersion, pCardData->dwVersion);

	pCardData->pfnCardDeleteContext = CardDeleteContext;
	pCardData->pfnCardQueryCapabilities = CardQueryCapabilities;
	pCardData->pfnCardDeleteContainer = CardDeleteContainer;
	pCardData->pfnCardCreateContainer = CardCreateContainer;
	pCardData->pfnCardGetContainerInfo = CardGetContainerInfo;
	pCardData->pfnCardAuthenticatePin = CardAuthenticatePin;
	pCardData->pfnCardGetChallenge = CardGetChallenge;
	pCardData->pfnCardAuthenticateChallenge = CardAuthenticateChallenge;
	pCardData->pfnCardUnblockPin = CardUnblockPin;
	pCardData->pfnCardChangeAuthenticator = CardChangeAuthenticator;
	pCardData->pfnCardDeauthenticate = CardDeauthenticate;
	pCardData->pfnCardCreateDirectory = CardCreateDirectory;
	pCardData->pfnCardDeleteDirectory = CardDeleteDirectory;
	pCardData->pvUnused3 = NULL;
	pCardData->pvUnused4 = NULL;
	pCardData->pfnCardCreateFile = CardCreateFile;
	pCardData->pfnCardReadFile = CardReadFile;
	pCardData->pfnCardWriteFile = CardWriteFile;
	pCardData->pfnCardDeleteFile = CardDeleteFile;
	pCardData->pfnCardEnumFiles = CardEnumFiles;
	pCardData->pfnCardGetFileInfo = CardGetFileInfo;
	pCardData->pfnCardQueryFreeSpace = CardQueryFreeSpace;
	pCardData->pfnCardQueryKeySizes = CardQueryKeySizes;
	pCardData->pfnCardSignData = CardSignData;
	pCardData->pfnCardRSADecrypt = CardRSADecrypt;
	pCardData->pfnCardConstructDHAgreement = md_has_ecdh_key(pCardData)? CardConstructDHAgreement : NULL;

	if (pCardData->dwVersion >= CARD_DATA_VERSION_FIVE) {
		pCardData->pfnCardDeriveKey = md_has_ecdh_key(pCardData)? CardDeriveKey : NULL;
		pCardData->pfnCardDestroyDHAgreement = md_has_ecdh_key(pCardData)? CardDestroyDHAgreement : NULL;

		if (pCardData->dwVersion >= CARD_DATA_VERSION_SIX) {

			pCardData->pfnCardGetChallengeEx = CardGetChallengeEx;
			pCardData->pfnCardAuthenticateEx = CardAuthenticateEx;
			pCardData->pfnCardChangeAuthenticatorEx = CardChangeAuthenticatorEx;
			pCardData->pfnCardDeauthenticateEx = CardDeauthenticateEx;
			pCardData->pfnCardGetContainerProperty = CardGetContainerProperty;
			pCardData->pfnCardSetContainerProperty = CardSetContainerProperty;
			pCardData->pfnCardGetProperty = CardGetProperty;
			pCardData->pfnCardSetProperty = CardSetProperty;
			if (pCardData->dwVersion >= CARD_DATA_VERSION_SEVEN) {

				pCardData->pfnMDImportSessionKey         = MDImportSessionKey;
				pCardData->pfnMDEncryptData              = MDEncryptData;
				pCardData->pfnCardImportSessionKey       = CardImportSessionKey;
				pCardData->pfnCardGetSharedKeyHandle     = CardGetSharedKeyHandle;
				pCardData->pfnCardGetAlgorithmProperty   = CardGetAlgorithmProperty;
				pCardData->pfnCardGetKeyProperty         = CardGetKeyProperty;
				pCardData->pfnCardSetKeyProperty         = CardSetKeyProperty;
				pCardData->pfnCardProcessEncryptedData   = CardProcessEncryptedData;
				pCardData->pfnCardDestroyKey             = CardDestroyKey;
				pCardData->pfnCardCreateContainerEx      = CardCreateContainerEx;
			}
		}
	}

	vs->lastChecked = GetTickCount64();
	dwret = SCARD_S_SUCCESS;
end:
	SCardEndTransactionPtr(pCardData->hScard, SCARD_LEAVE_CARD);
	FUNCTION_END (dwret);
}

static int md_bind(VENDOR_SPECIFIC* vs, struct sc_app_info *app_info)
{
	md_fw_data **fw_data = vs->fws_data;
	struct sc_aid *aid = app_info ? &app_info->aid : NULL;
	int rc, idx;

	for (idx = 0; idx < 4; idx++)
		if (!fw_data[idx])
			break;
	if (idx == 4)
		return SC_ERROR_NOT_ENOUGH_MEMORY;

	if (!(fw_data[idx] = calloc(1, sizeof(*fw_data))))
		return SC_ERROR_NOT_ENOUGH_MEMORY;

	rc = sc_pkcs15_bind(vs->card, aid, &fw_data[idx]->p15card);

	return rc;
}

static DWORD associate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	int  r, j;
	struct sc_app_info *app_generic;

	logprintf(pCardData, 1, "associate_card\n");
	if (!pCardData)
		return SCARD_E_INVALID_PARAMETER;

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs)
		return SCARD_E_INVALID_PARAMETER;

	/*
	 * set the addresses of the reader and card handles
	 * Our pcsc code will use these  when we call sc_ctx_use_reader
	 * We use the address of the handles as provided in the pCardData
	 */
	vs->hSCardCtx = pCardData->hSCardCtx;
	vs->hScard = pCardData->hScard;

	/* set the provided reader and card handles into ctx */
	r = sc_ctx_use_reader(vs->ctx, &vs->hSCardCtx, &vs->hScard);
	if (r != SC_SUCCESS) {
		logprintf(pCardData, 0, "sc_ctx_use_reader() failed with %d\n", r);
		return SCARD_E_COMM_DATA_LOST;
	}

	/* should be only one reader */
	logprintf(pCardData, 5, "sc_ctx_get_reader_count(ctx): %d\n", sc_ctx_get_reader_count(vs->ctx));

	vs->reader = sc_ctx_get_reader(vs->ctx, 0);
	if (!vs->reader)
		return SCARD_E_COMM_DATA_LOST;

	r = sc_connect_card(vs->reader, &(vs->card));
	if (r != SC_SUCCESS) {
		logprintf(pCardData, 0, "Cannot connect card in reader '%s'\n", NULLSTR(vs->reader->name));
		return SCARD_E_UNKNOWN_CARD;
	}
	logprintf(pCardData, 3, "Connected card in '%s'\n", NULLSTR(vs->reader->name));

	app_generic = sc_pkcs15_get_application_by_type(vs->card, "generic");
	if (app_generic)
	{
		logprintf(pCardData, 3, "Use generic application '%s'\n", app_generic->label);
		r = md_bind(vs, app_generic);
		logprintf(pCardData, 2, "PKCS#15 initialization result: %d, %s\n", r, sc_strerror(r));
		if (r != SC_SUCCESS) {
			logprintf(pCardData, 0, "PKCS#15 init failed.\n");
			sc_disconnect_card(vs->card);
			return SCARD_E_UNKNOWN_CARD;
		}
	}

	for (j = 0; j < vs->card->app_count; j++) {
		struct sc_app_info *app_info = vs->card->app[j];
		char *app_name = app_info ? app_info->label : "<anonymous>";

		if (app_generic && app_generic == vs->card->app[j])
			continue;

		r = md_bind(vs, app_info);
		if (r != SC_SUCCESS) {
			continue;
		}
	}

	vs->initialized = TRUE;
	vs->lastChecked = GetTickCount64();

	return SCARD_S_SUCCESS;

}

static void disassociate_card(PCARD_DATA pCardData)
{
	VENDOR_SPECIFIC *vs;
	md_fw_data *fw_data;
	int idx;

	if (!pCardData) {
		logprintf(pCardData, 1,
			"disassociate_card called without card data\n");
		return;
	}

	logprintf(pCardData, 1, "disassociate_card\n");

	vs = (VENDOR_SPECIFIC*)(pCardData->pvVendorSpecific);
	if (!vs) {
		logprintf(pCardData, 1,
			"disassociate_card called without vendor specific data\n");
		return;
	}

	memset(vs->pin_objs, 0, sizeof(vs->pin_objs));
	memset(vs->p15_containers, 0, sizeof(vs->p15_containers));

	for (idx = 0; idx < 4; idx++)
	{
		if (!vs->fws_data[idx])
			break;
		fw_data = vs->fws_data[idx];
		if (fw_data->p15card) {
			logprintf(pCardData, 6, "sc_pkcs15_unbind\n");
			sc_pkcs15_unbind(fw_data->p15card);
			fw_data->p15card = NULL;
		}
		vs->fws_data[idx] = NULL;
	}

	if (vs->card) {
		logprintf(pCardData, 6, "sc_disconnect_card\n");
		sc_disconnect_card(vs->card);
		vs->card = NULL;
	}

	vs->reader = NULL;

	vs->hSCardCtx = -1;
	vs->hScard = -1;
	vs->initialized = FALSE;
	vs->lastChecked = 0;
}

#ifdef _MANAGED
#pragma managed(pop)
#endif
#endif
