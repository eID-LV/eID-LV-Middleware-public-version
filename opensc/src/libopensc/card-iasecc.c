/*
 * card-iasecc.c: Support for IAS/ECC smart cards
 *
 * Copyright (C) 2010  Viktor Tarasov <vtarasov@gmail.com>
 * 			OpenTrust <www.opentrust.com>
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef ENABLE_OPENSSL   /* empty file without openssl */

#include <string.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include "internal.h"
#include "asn1.h"
#include "cardctl.h"
#include "opensc.h"
/* #include "sm.h" */
#include "pkcs15.h"
/* #include "hash-strings.h" */
#include "gp.h"

#include "iasecc.h"

#include "sm/sm-eac.h"

#define IASECC_CARD_DEFAULT_FLAGS ( 0			\
		| SC_ALGORITHM_ONBOARD_KEY_GEN		\
		| SC_ALGORITHM_RSA_PAD_ISO9796		\
		| SC_ALGORITHM_RSA_PAD_PKCS1		\
		| SC_ALGORITHM_RSA_HASH_NONE		\
		| SC_ALGORITHM_RSA_HASH_SHA1		\
		| SC_ALGORITHM_RSA_HASH_SHA256)

#define SC_CARD_FLAG_CONTACTLESS					0x00010000
#define SC_CARD_FLAG_PACE_STATE_ACTIVE			0x00020000
#define SC_CARD_FLAG_PACE_STATE_NOT_ACTIVE	0x00040000
#define SC_CARD_FLAG_PACE_STATE_UNKNOWN		0x00040000

#ifdef ENABLE_OPENPACE

#ifdef _WIN32
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <shellapi.h>
#include <wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#define SOCKET int
#define SOCKET_ERROR -1
#define INVALID_SOCKET -1
#define ARRAYSIZE(b)	(sizeof(b) / sizeof (b[0]))
#define closesocket(s)	close(s)
#endif

static void iasecc_pace_data_free(struct iasecc_private_data *drv_data)
{
	if (drv_data) {
		if (drv_data->ef_cardaccess)
		{
			free(drv_data->ef_cardaccess);
			drv_data->ef_cardaccess = NULL;
			drv_data->ef_cardaccess_length = 0;
		}
		if (drv_data->can)
		{
			sc_mem_clear(drv_data->can, drv_data->can_length);
			sc_mem_secure_free(drv_data->can, drv_data->can_length);
			drv_data->can = NULL;
			drv_data->can_length = 0;
		}
	}
}

static void iasecc_get_cached_pace_params(sc_card_t *card,
	struct establish_pace_channel_input *pace_input,
	struct establish_pace_channel_output *pace_output)
{
	struct iasecc_private_data *drv_data;

	if (card->drv_data) {
		drv_data = (struct iasecc_private_data*) card->drv_data;

		if (pace_output) {
			pace_output->ef_cardaccess = drv_data->ef_cardaccess;
			pace_output->ef_cardaccess_length = drv_data->ef_cardaccess_length;
		}

		if (pace_input && pace_input->pin_id == PACE_PIN_ID_CAN) {
			pace_input->pin = drv_data->can;
			pace_input->pin_length = drv_data->can_length;
		}
	}
}

static void iasecc_cache_pace_data(sc_card_t *card,
	const unsigned char *ef_cardaccess, size_t ef_cardaccess_length,
	const unsigned char *can, size_t can_length)
{
	struct iasecc_private_data *drv_data;

	if (card && card->drv_data) {
		drv_data = (struct iasecc_private_data*) card->drv_data;

		if (ef_cardaccess && ef_cardaccess_length && (drv_data->ef_cardaccess != ef_cardaccess)) {
			if (drv_data->ef_cardaccess)
				free(drv_data->ef_cardaccess);
			drv_data->ef_cardaccess_length = ef_cardaccess_length;
			drv_data->ef_cardaccess = (unsigned char*) malloc (ef_cardaccess_length);
			memcpy(drv_data->ef_cardaccess, ef_cardaccess, ef_cardaccess_length);
		}

		if (can && can_length && (drv_data->can != can))
		{
			if (drv_data->can)
				sc_mem_secure_free(drv_data->can, drv_data->can_length);
			drv_data->can_length = can_length;
			drv_data->can = (unsigned char*) sc_mem_secure_alloc(can_length + 1);
			memcpy(drv_data->can, can, can_length);
			drv_data->can[can_length] = 0;
		}
	}
}

#endif

/* generic iso 7816 operations table */
static const struct sc_card_operations *iso_ops = NULL;

/* our operations table with overrides */
static struct sc_card_operations iasecc_ops;

static struct sc_card_driver iasecc_drv = {
	"IAS-ECC",
	"iasecc",
	&iasecc_ops,
	NULL, 0, NULL
};

static const struct sc_atr_table iasecc_known_atrs[] = {
/*	{ "3B:7F:96:00:00:00:31:B8:64:40:70:14:10:73:94:01:80:82:90:00",
	  "FF:FF:FF:FF:FF:FF:FF:FE:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF", 
		"IAS/ECC Gemalto", SC_CARD_TYPE_IASECC_GEMALTO,  0, NULL },
        { "3B:DD:18:00:81:31:FE:45:80:F9:A0:00:00:00:77:01:08:00:07:90:00:FE", NULL,
		"IAS/ECC v1.0.1 Oberthur", SC_CARD_TYPE_IASECC_OBERTHUR,  0, NULL },
	{ "3B:7D:13:00:00:4D:44:57:2D:49:41:53:2D:43:41:52:44:32", NULL,
		"IAS/ECC v1.0.1 Sagem MDW-IAS-CARD2", SC_CARD_TYPE_IASECC_SAGEM,  0, NULL },
	{ "3B:7F:18:00:00:00:31:B8:64:50:23:EC:C1:73:94:01:80:82:90:00", NULL,
		"IAS/ECC v1.0.1 Sagem ypsID S3", SC_CARD_TYPE_IASECC_SAGEM,  0, NULL },
	{ "3B:DF:96:00:80:31:FE:45:00:31:B8:64:04:1F:EC:C1:73:94:01:80:82:90:00:EC", NULL,
		"IAS/ECC Morpho MinInt - Agent Card", SC_CARD_TYPE_IASECC_MI, 0, NULL },
	{ "3B:DF:18:FF:81:91:FE:1F:C3:00:31:B8:64:0C:01:EC:C1:73:94:01:80:82:90:00:B3", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
	{ "3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:02:04:03:55:00:02:34", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },
	{ "3B:DC:18:FF:81:91:FE:1F:C3:80:73:C8:21:13:66:01:0B:03:52:00:05:38", NULL,
		"IAS/ECC v1.0.1 Amos", SC_CARD_TYPE_IASECC_AMOS, 0, NULL },*/
	{ "3B:DD:18:00:81:31:FE:45:90:4C:41:54:56:49:41:2D:65:49:44:90:00:8C", NULL,
		"Latvia eID", SC_CARD_TYPE_IASECC_OBERTHUR,  0, NULL },
	{ "3B:DB:96:00:80:B1:FE:45:1F:83:00:12:42:8F:53:65:49:44:0F:90:00:20", NULL,
	"Latvia eID v2", SC_CARD_TYPE_IASECC_LATVIA,  0, NULL },
	{ "3B:8B:80:01:00:12:42:8F:53:65:49:44:0F:90:00:71", NULL,
	"Latvia eID v2 - Contactless", SC_CARD_TYPE_IASECC_LATVIA,  0, NULL },
	{ NULL, NULL, NULL, 0, 0, NULL }
};


static struct sc_aid OberthurIASECC_AID = {
	{0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00}, 16
};

static struct sc_aid LatviaV2_ADF_QSCD = {
	{
		0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61,
		0x74, 0x69, 0x6F, 0x6E
	},
	16
};

//proprietary ATR to match
static struct sc_aid LatviaEid_ATR_MATCH = {
	{0x4C,0x41,0x54,0x56,0x49,0x41,0x2D,0x65,0x49,0x44}, 10
};

static struct sc_aid LatviaEidV2_ATR_MATCH = {
	{0x12,0x42,0x8F,0x53,0x65,0x49,0x44,0x0F}, 8
};

static struct sc_aid MIIASECC_AID = {
	{ 0x4D, 0x49, 0x4F, 0x4D, 0x43, 0x54}, 6
};

static int iasecc_select_file_pace(struct sc_card *card, const struct sc_path *path, struct sc_file **file_out, int ignorePaceError);

static int iasecc_select_file(struct sc_card *card, const struct sc_path *path, struct sc_file **file_out);
static int iasecc_process_fci(struct sc_card *card, struct sc_file *file, const unsigned char *buf, size_t buflen);
static int iasecc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial);
static int iasecc_sdo_get_data(struct sc_card *card, struct iasecc_sdo *sdo);
static int iasecc_pin_get_policy (struct sc_card *card, struct sc_pin_cmd_data *data);
static int iasecc_pin_is_verified(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, int *tries_left);
static int iasecc_get_free_reference(struct sc_card *card, struct iasecc_ctl_get_free_reference *ctl_data);
static int iasecc_sdo_put_data(struct sc_card *card, struct iasecc_sdo_update *update);

#ifdef ENABLE_SM
static int _iasecc_sm_read_binary(struct sc_card *card, unsigned int offs, unsigned char *buf, size_t count);
static int _iasecc_sm_update_binary(struct sc_card *card, unsigned int offs, const unsigned char *buff, size_t count);
#endif

#ifdef ENABLE_OPENPACE

const char* szHelloClientHeader = "eidLVUI Client Hello";
const char* szHelloServerHeader = "eidLVUI Server Hello";
const char* szCmdHeader = "eidLVUI Client CMD: ";
const char* szresponseHeader = "eidLVUI Server RESP: ";

int SendData(SOCKET sock, const char* buf, size_t len)
{
#ifdef _WIN32
	int ret;
#else
	ssize_t ret;
#endif
	if (len == (size_t)-1)
		len = strlen(buf);
	while (len)
	{
		ret = send(sock, buf, len, 0);
		if (ret == 0)
			break;
		else if (ret == SOCKET_ERROR)
		{
			break;
		}
		len -= ret;
		buf += ret;
	}

	return len == 0? 1 : 0;
}

typedef enum
{
	SRV_REQ_CAN = 0,
} eServerRequestType;

typedef struct
{
	struct sc_card *card;
	eServerRequestType type;
	int request_counter;
	char* outputText;
	int outputTextSize;
	volatile int* completed_flag;
	int bStatus;
} tServerRequestParam;

int iasecc_ui_process_request(int srvPort, struct sc_card *card, const char* szCmd, char* outputText, int outputTextSize)
{
	SOCKET sClient = INVALID_SOCKET;
	char szBuffer[4096];
#ifdef _WIN32
	int ret;
#else
	ssize_t ret;
#endif
	struct sockaddr_in server;
	struct hostent *host = NULL;
	int bStatus = -1;
#ifdef _WIN32
	int free_winsock = 0;
#endif
	struct sc_context *ctx = card->ctx;

	sc_log(ctx, "iasecc_ui_process_request called (port = %d)", (int) srvPort);

	//
	// Create the socket, and attempt to connect to the server
	//

	sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#ifdef _WIN32
	if ((sClient == INVALID_SOCKET) && (WSAGetLastError() == WSANOTINITIALISED))
	{
		WSADATA wsaData;
		WSAStartup(MAKEWORD(2, 2), &wsaData);
		free_winsock = 1;
		sClient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}
#endif
	if (sClient == INVALID_SOCKET)
	{
		sc_log(ctx, "failed to create socket");
		goto req_end;
	}

	inet_pton(AF_INET, "127.0.0.1", &server.sin_addr.s_addr);
	server.sin_family = AF_INET;
	server.sin_port = htons(srvPort);

	if (connect(sClient, (struct sockaddr *)&server, sizeof(server)) != SOCKET_ERROR)
	{
		if (SendData(sClient, szHelloClientHeader, -1))
		{
			ret = recv(sClient, szBuffer, ARRAYSIZE(szBuffer), 0);
			if (ret > strlen(szHelloServerHeader) && memcmp(szBuffer, szHelloServerHeader, strlen(szHelloServerHeader)) == 0)
			{
				sprintf(szBuffer, "%s%s", szCmdHeader, szCmd);
				if (SendData(sClient, szBuffer, -1))
				{
					ret = recv(sClient, szBuffer, ARRAYSIZE(szBuffer), 0);
					if (ret > strlen(szresponseHeader) && ret < sizeof(szBuffer) && 0 == memcmp(szBuffer, szresponseHeader, strlen(szresponseHeader)))
					{
						szBuffer[ret] = 0;
						char* szValue = &szBuffer[strlen(szresponseHeader)];
						if (strlen(szValue) < (size_t)outputTextSize)
						{
							strcpy(outputText, szValue);

							bStatus = 0;
						}
					}
				}
			}
		}
		else
			sc_log(ctx, "failed to send data to UI server");
	}
	else
		sc_log(ctx, "failed to connect");

	closesocket(sClient);

req_end:
#ifdef _WIN32
	if (free_winsock)
		WSACleanup();
#endif
	return bStatus;
}

int iasecc_ui_request_can(int srvPort, struct sc_card *card, char* outputText, int outputTextSize, int request_counter)
{
	int bStatus = -1;
	char szCmd[512];
	const char* szReader = card->reader->name;

	if (outputTextSize >= 7)
	{
		sprintf(szCmd, "PACE#%s#%d#%d", szReader, 6, request_counter);
		bStatus = iasecc_ui_process_request(srvPort, card, szCmd, outputText, outputTextSize);
	}

	return bStatus;
}

int iasecc_ui_cache_can(int srvPort, struct sc_card *card, const char* can)
{
	int bStatus = -1;
	char szCmd[512];
	const char* szReader = card->reader->name;
	sprintf(szCmd, "CACHE#%s#%s", szReader, can);
	bStatus = iasecc_ui_process_request(srvPort, card, szCmd, szCmd, sizeof(szCmd));
	if (bStatus == 0)
	{
		if (strcmp(szCmd, "OK") != 0)
			bStatus = -1;
	}

	return bStatus;
}

#ifdef _WIN32
BOOL GetUIServerPort(HKEY hUserKey, DWORD* pdwPort)
{
	BOOL bStatus = FALSE;
	HKEY hKey;
	LONG lRet = RegCreateKeyEx(hUserKey, TEXT("Software\\Latvia eID"), 0, NULL, 0, KEY_READ, NULL, &hKey, NULL);
	if (lRet == SCARD_S_SUCCESS)
	{
		DWORD dwPort = 0, dwType, dwLen = sizeof(DWORD);
		lRet = RegQueryValueEx(hKey, TEXT("SrvAccess"), NULL, &dwType, (LPBYTE)&dwPort, &dwLen);
		if ((lRet == SCARD_S_SUCCESS) && (dwType == REG_DWORD))
		{
			*pdwPort = dwPort;
			bStatus = TRUE;
		}

		RegCloseKey(hKey);
	}

	return bStatus;
}

int restart_ui_server()
{
	DWORD dwSessionId, dwPort;
	HINSTANCE h;
	BOOL bIsLocalService = FALSE;
	int ui_srv_port = 0;
	
	if (ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId) && dwSessionId == 0)
		bIsLocalService = TRUE;
	
	if (bIsLocalService)
	{
		dwSessionId = WTSGetActiveConsoleSessionId ();
		if (dwSessionId != 0xFFFFFFFF)
		{
			HANDLE hUserToken = NULL;
			HANDLE hFakeToken = NULL;

			if (WTSQueryUserToken(dwSessionId, &hUserToken))
			{
				if (DuplicateTokenEx(hUserToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &hFakeToken) == TRUE)
				{
					if (ImpersonateLoggedOnUser(hFakeToken))
					{
						HKEY hUserKey;

						if (ERROR_SUCCESS == RegOpenCurrentUser(KEY_READ, &hUserKey))
						{
							if (GetUIServerPort(hUserKey, &dwPort))
								ui_srv_port = (int)dwPort;
							else
							{
								PROCESS_INFORMATION pi;
								STARTUPINFO si;
								ZeroMemory(&si, sizeof(si));
								ZeroMemory(&pi, sizeof(pi));
								if (CreateProcessAsUserA(hFakeToken, "eidLvUI.exe", NULL, NULL, NULL, FALSE, CREATE_DEFAULT_ERROR_MODE, NULL, NULL, &si, &pi))
								{
									CloseHandle(pi.hProcess);
									CloseHandle(pi.hThread);

									/* wait 2 seconds max*/
									int counter = 0;
									do
									{
										Sleep(500);
										if (GetUIServerPort(hUserKey, &dwPort))
										{
											ui_srv_port = (int)dwPort;
											break;
										}
									} while (counter < 4);
								}
							}
							RegCloseKey(hUserKey);
						}

						RevertToSelf();
					}

					CloseHandle(hFakeToken);
				}

				CloseHandle(hUserToken);
			}
		}
	}
	else
	{
		h = ShellExecuteA(NULL, "open", "eidLvUI.exe", NULL, NULL, SW_SHOW);
		if (((int) h) > 32)
		{
			/* wait 2 seconds max*/
			int counter = 0;
			do
			{
				Sleep(500);
				if (GetUIServerPort(HKEY_CURRENT_USER, &dwPort))
				{
					ui_srv_port = (int)dwPort;
					break;
				}
			} while (counter < 4);
		}
	}

	return ui_srv_port;
} 

BOOL GetUIServerPortForCurrentUser(DWORD* pdwPort)
{
	DWORD dwSessionId;
	HINSTANCE h;
	BOOL bIsLocalService = FALSE;
	HKEY hUserKey = HKEY_CURRENT_USER;

	if (ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId) && dwSessionId == 0)
		bIsLocalService = TRUE;

	if (bIsLocalService)
	{
		BOOL bSuccess = FALSE;
		dwSessionId = WTSGetActiveConsoleSessionId();
		if (dwSessionId != 0xFFFFFFFF)
		{
			HANDLE hUserToken = NULL;
			HANDLE hFakeToken = NULL;

			if (WTSQueryUserToken(dwSessionId, &hUserToken))
			{
				if (DuplicateTokenEx(hUserToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &hFakeToken) == TRUE)
				{
					if (ImpersonateLoggedOnUser(hFakeToken))
					{
						HKEY hUserKey;

						if (ERROR_SUCCESS == RegOpenCurrentUser(KEY_READ, &hUserKey))
						{
							bSuccess = GetUIServerPort(hUserKey, pdwPort);
							RegCloseKey(hUserKey);
						}

						RevertToSelf();
					}

					CloseHandle(hFakeToken);
				}

				CloseHandle(hUserToken);
			}
		}

		return bSuccess;
	}
	else
		return GetUIServerPort(hUserKey, pdwPort);
}

BOOL IsPaceDisabledForMinidriver(HKEY hUserKey)
{
	BOOL bStatus = FALSE;
	HKEY hKey;
	LONG lRet = RegCreateKeyEx(hUserKey, TEXT("Software\\Latvia eID"), 0, NULL, 0, KEY_READ, NULL, &hKey, NULL);
	if (lRet == SCARD_S_SUCCESS)
	{
		DWORD dwPolicy = 0, dwType, dwLen = sizeof(DWORD);
		lRet = RegQueryValueEx(hKey, TEXT("DisablePaceUI"), NULL, &dwType, (LPBYTE)&dwPolicy, &dwLen);
		if ((lRet == SCARD_S_SUCCESS) && (dwType == REG_DWORD))
		{
			if (dwPolicy & 1)
				bStatus = TRUE;
		}

		RegCloseKey(hKey);
	}

	return bStatus;
}

BOOL IsImpersonating()
{
	BOOL bSuccess = FALSE;
	HANDLE hThreadToken;
	BOOL bRet = OpenThreadToken(GetCurrentThread(), MAXIMUM_ALLOWED, TRUE, &hThreadToken);
	if (bRet)
	{
		SECURITY_IMPERSONATION_LEVEL level;
		DWORD dwCount = 0;
		if (GetTokenInformation(hThreadToken, TokenImpersonationLevel, &level, sizeof(level), &dwCount))
		{
			if (level == SecurityImpersonation)
				bSuccess = TRUE;
		}

		CloseHandle(hThreadToken);
	}

	return bSuccess;
}

BOOL IsPaceDisabledForMinidriverForLocalUser()
{
	DWORD dwSessionId = 0, dwPort;
	HINSTANCE h;
	BOOL bIsLocalService = FALSE;

	ProcessIdToSessionId(GetCurrentProcessId(), &dwSessionId);


	if (dwSessionId == 0)
		bIsLocalService = TRUE;

	if (bIsLocalService && !IsImpersonating())
	{
		BOOL bSuccess = FALSE;
		dwSessionId = WTSGetActiveConsoleSessionId();
		if (dwSessionId != 0xFFFFFFFF)
		{
			HANDLE hUserToken = NULL;
			HANDLE hFakeToken = NULL;

			if (WTSQueryUserToken(dwSessionId, &hUserToken))
			{
				if (DuplicateTokenEx(hUserToken, TOKEN_ASSIGN_PRIMARY | TOKEN_ALL_ACCESS, 0, SecurityImpersonation, TokenPrimary, &hFakeToken) == TRUE)
				{
					if (ImpersonateLoggedOnUser(hFakeToken))
					{
						HKEY hUserKey;

						if (ERROR_SUCCESS == RegOpenCurrentUser(KEY_READ, &hUserKey))
						{
							bSuccess = IsPaceDisabledForMinidriver(hUserKey);
							RegCloseKey(hUserKey);
						}

						RevertToSelf();
					}

					CloseHandle(hFakeToken);
				}

				CloseHandle(hUserToken);
			}
		}

		return bSuccess;
	}
	else
		return IsPaceDisabledForMinidriver(HKEY_CURRENT_USER);
}

#endif

#ifdef _WIN32
void _cdecl perform_server_request_thread(void* pArg)
#else
void perform_server_request_thread(void* pArg)
#endif
{
	tServerRequestParam* pParam = (tServerRequestParam*) pArg;
	struct sc_context *ctx = pParam->card->ctx;
	struct iasecc_private_data *drv_data = (struct iasecc_private_data*) pParam->card->drv_data;
	pParam->bStatus = -1;
	*pParam->completed_flag = 0;
	
	sc_log(ctx, "perform_server_request_thread called");

	if (drv_data->ui_srv_port == 0)
	{
#ifdef _WIN32
		DWORD dwPort = 0;
		if (!GetUIServerPortForCurrentUser(&dwPort))
		{
			/* start server manually */
			drv_data->ui_srv_port = restart_ui_server();
			sc_log(ctx, "restart_ui_server called.");
		}
		else
		{
			drv_data->ui_srv_port = (int)dwPort;
		}
#else
		FILE* f = fopen ("/var/tmp/.eidLvUI.port", "r");
		if (f)
		{
			size_t len;
			unsigned char* pbData = NULL;
			long lValue = 0;
			fseek (f, 0, SEEK_END);
			len = ftell (f);
			fseek (f, 0, SEEK_SET);
			pbData = (unsigned char*) malloc (len + 1);
			fread (pbData, 1, len, f);
			fclose (f);
			
			pbData[len] = 0;
			
			lValue = strtol ((const char*) pbData, NULL, 10);
			
			sc_log(ctx, "port value is %d", (int) lValue);
			
			if (lValue > 0)
			{
				drv_data->ui_srv_port = (int) lValue;
			} 
			
			free (pbData);
		}
		else
			sc_log(ctx, "failed to open port file");
#endif
	}

	if (drv_data->ui_srv_port)
	{
		if (pParam->type == SRV_REQ_CAN)
		{
			pParam->bStatus = iasecc_ui_request_can(drv_data->ui_srv_port, pParam->card, pParam->outputText, pParam->outputTextSize, pParam->request_counter);
		}
	}
	*pParam->completed_flag = 1;
}

void perform_server_request(tServerRequestParam* pParam)
{
	struct sc_context *ctx = pParam->card->ctx;
	clock_t previousTime = 0, currentTime = 0;
	*pParam->completed_flag = 0;
	sc_log(ctx, "perform_server_request called");
#ifdef _WIN32
	_beginthread(perform_server_request_thread, 0, pParam);
	while (1)
	{
		Sleep(500);
		if (*pParam->completed_flag)
			break;
		else
		{
			int rv = 0;
			struct sc_apdu apdu;
			unsigned char rbuf[0xC0];

			currentTime = clock();

			if ((previousTime == 0) || (((currentTime - previousTime) / CLOCKS_PER_SEC) > 2))
			{
				sc_format_apdu(pParam->card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x80 | 0x1C, 0);
				apdu.le = sizeof(rbuf);
				apdu.resp = rbuf;
				apdu.resplen = sizeof(rbuf);
				rv = sc_transmit_apdu(pParam->card, &apdu);

				previousTime = currentTime;
			}
			else if (previousTime == 0)
				previousTime = currentTime;
		}
	}
#else
	perform_server_request_thread(pParam);
#endif
}

#endif


static int do_pace(struct sc_card *card, int *pace_result)
{
    int r;
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *drv_data = (struct iasecc_private_data*) card->drv_data;
    struct establish_pace_channel_input pace_input;
    struct establish_pace_channel_output pace_output;
	 memset(&pace_input, 0, sizeof(pace_input));
	 memset(&pace_output, 0, sizeof(pace_output));

	 pace_input.pin_id = PACE_PIN_ID_CAN;

#ifdef _WIN32
	 if (drv_data->cardmod && IsPaceDisabledForMinidriverForLocalUser())
	 {
		 sc_log(ctx, "IsPaceDisabledForMinidriverForLocalUser returned TRUE. PACE disabled for Minidriver!");
		 return -1;
	 }
#endif

	 if (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)
	 {
		 r = card->reader->ops->perform_pace(card->reader, &pace_input, &pace_output);
	 }
	 else
	 {		
#ifdef ENABLE_OPENPACE
		 char szCan[7];
		 int fromCache = 1;
		 tServerRequestParam param = { 0 };
		 volatile int completed_flag = 0;
		 
		 param.card = card;
		 param.completed_flag = &completed_flag;
		 param.outputText = szCan;
		 param.outputTextSize = sizeof(szCan);
		 param.request_counter = 0;
		 param.type = SRV_REQ_CAN;
		 param.bStatus = -1;

		 iasecc_get_cached_pace_params(card, &pace_input, &pace_output);
		 if (!pace_input.pin)
		 {
			 perform_server_request(&param);

			 if (param.bStatus)
				 return -1;
			 pace_input.pin = (unsigned char*)szCan;
			 pace_input.pin_length = strlen(szCan);
			 fromCache = 0;
		 }

		 do
		 {
			 r = perform_pace(card, pace_input, &pace_output, EAC_TR_VERSION_2_02);
			 if (r == 0)
			 {
				 iasecc_cache_pace_data(card, NULL, 0, pace_input.pin, pace_input.pin_length);
				 iasecc_ui_cache_can(drv_data->ui_srv_port, card, pace_input.pin);
				 break;
			 }
			 else if (!fromCache && r == SC_ERROR_CARD_CMD_FAILED && pace_output.mse_set_at_sw1 == 0x90 && pace_output.mse_set_at_sw2 == 0x00)
			 {
				 param.request_counter++;
				 perform_server_request(&param);
				 if (param.bStatus)
					 return -1;
				 pace_input.pin = (unsigned char*)szCan;
				 pace_input.pin_length = strlen(szCan);
				 memset(&pace_output, 0, sizeof(pace_output));
			 }
			 else
				 break;
		 } while (1);
#else
		return -1;
#endif
	 }
	 if (pace_result)
		 *pace_result = pace_output.result;
	if (r && (pace_output.result != 0xF0026985)) {// PACE already active => 0x6985
		// printf("PACE failed: %s\n", sc_strerror(r));
		return -1;
    }

	card->flags |= SC_CARD_FLAG_PACE_STATE_ACTIVE;
	card->flags &= ~(SC_CARD_FLAG_PACE_STATE_NOT_ACTIVE | SC_CARD_FLAG_PACE_STATE_UNKNOWN);

    //printf("Established PACE channel.\n");

	return 0;
}

static int
iasecc_restore_context(struct sc_card *card)
{
	struct sc_file *save_current_df = NULL, *save_current_ef = NULL;
	struct sc_path apppath;
	int local_rv;

	if (card->ef_atr && card->ef_atr->aid.len)
	{
		if (card->cache.valid && card->cache.current_df) {
			sc_file_dup(&save_current_df, card->cache.current_df);
		}

		if (card->cache.valid && card->cache.current_ef) {
			sc_file_dup(&save_current_ef, card->cache.current_ef);
		}
		sc_file_free(card->cache.current_df);
		card->cache.current_df = NULL;
		sc_file_free(card->cache.current_ef);
		card->cache.current_ef = NULL;
		card->cache.valid = 1;

		memset(&apppath, 0, sizeof(struct sc_path));
		apppath.type = SC_PATH_TYPE_DF_NAME;
		memcpy(apppath.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
		apppath.len = card->ef_atr->aid.len;

		local_rv = iasecc_select_file(card, &apppath, NULL);
		if (!local_rv)
		{
			if (save_current_df) {
				int localRv;

				localRv = iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
				if (localRv < 0)
				{
					sc_file_free(card->cache.current_df);
					card->cache.current_df = NULL;
				}
			}

			if (save_current_ef) {
				int localRv;

				localRv = iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
				if (localRv < 0)
				{
					sc_file_free(card->cache.current_ef);
					card->cache.current_ef = NULL;
				}
			}
		}
	}
	else
		local_rv = SC_ERROR_INTERNAL;

	if (save_current_df)
		sc_file_free(save_current_df);
	if (save_current_ef)
		sc_file_free(save_current_ef);

	return local_rv;
}


static int
iasecc_select_mf(struct sc_card *card, struct sc_file **file_out)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *mf_file = NULL;
	struct sc_path path;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (file_out)
		*file_out = NULL;

	memset(&path, 0, sizeof(struct sc_path));
	if (!card->ef_atr || !card->ef_atr->aid.len)   {
		struct sc_apdu apdu;
		unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];

		/* ISO 'select' command fails when not FCP data returned */
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xA4, 0x00, 0x00);
		apdu.lc = path.len;
		apdu.data = path.value;
		apdu.datalen = path.len;
		apdu.resplen = sizeof(apdu_resp);
		apdu.resp = apdu_resp;

		if (card->type == SC_CARD_TYPE_IASECC_MI2)
			apdu.p2 = 0x04;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(card->ctx, rv, "Cannot select MF");
	}
	else   {
		memset(&path, 0, sizeof(path));
		path.type = SC_PATH_TYPE_DF_NAME;
		memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
		path.len = card->ef_atr->aid.len;
		rv = iasecc_select_file(card, &path, file_out);
		LOG_TEST_RET(ctx, rv, "Unable to ROOT selection");
	}

	/* Ignore the FCP of the MF, because:
	 * - some cards do not return it;
	 * - there is not need of it -- create/delete of the files in MF is not envisaged.
	 */
	mf_file = sc_file_new();
	if (mf_file == NULL)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate MF file");
	mf_file->type = SC_FILE_TYPE_DF;
	mf_file->path = path;

	if (card->cache.valid)
		 sc_file_free(card->cache.current_df);
	card->cache.current_df = NULL;

	if (card->cache.valid)
		sc_file_free(card->cache.current_ef);
	card->cache.current_ef = NULL;

	sc_file_dup(&card->cache.current_df, mf_file);
	card->cache.valid = 1;

	if (file_out && *file_out == NULL)
		*file_out = mf_file;
	else
		sc_file_free(mf_file);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_select_aid(struct sc_card *card, struct sc_aid *aid, unsigned char *out, size_t *out_len)
{
	struct sc_apdu apdu;
	unsigned char apdu_resp[SC_MAX_APDU_BUFFER_SIZE];
	int rv;

	/* Select application (deselect previously selected application) */
	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x04, 0x00);
	apdu.lc = aid->len;
	apdu.data = aid->value;
	apdu.datalen = aid->len;
	apdu.resplen = sizeof(apdu_resp);
	apdu.resp = apdu_resp;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, rv, "Cannot select AID");
	
	if (*out_len < apdu.resplen)
		LOG_TEST_RET(card->ctx, SC_ERROR_BUFFER_TOO_SMALL, "Cannot select AID");
	memcpy(out, apdu.resp, apdu.resplen);

	return SC_SUCCESS;
}


static int
iasecc_match_card(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	int i;

	sc_log(ctx, "iasecc_match_card(%s) called", sc_dump_hex(card->atr.value, card->atr.len));
	i = _sc_match_atr(card, iasecc_known_atrs, &card->type);
	if (i < 0)   {
		sc_log(ctx, "card not matched");
		return 0;
	}

	if (strstr (iasecc_known_atrs[i].name, "Contactless"))
		card->flags |= SC_CARD_FLAG_CONTACTLESS;
	card->flags |= SC_CARD_FLAG_PACE_STATE_UNKNOWN;

	sc_log(ctx, "'%s' card matched", iasecc_known_atrs[i].name);
	return 1;
}

static int iasecc_parse_ef_atr(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *pdata = (struct iasecc_private_data *) card->drv_data;
	struct iasecc_version *version = &pdata->version;
	struct iasecc_io_buffer_sizes *sizes = &pdata->max_sizes;
	int rv;

	LOG_FUNC_CALLED(ctx);
	rv = sc_parse_ef_atr(card);
	LOG_TEST_RET(ctx, rv, "MF selection error");

	if (card->ef_atr->pre_issuing_len < 4)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid pre-issuing data");

	version->ic_manufacturer =	card->ef_atr->pre_issuing[0];
	version->ic_type = 		card->ef_atr->pre_issuing[1];
	version->os_version = 		card->ef_atr->pre_issuing[2];
	version->iasecc_version = 	card->ef_atr->pre_issuing[3];
	sc_log(ctx, "EF.ATR: IC manufacturer/type %X/%X, OS/IasEcc versions %X/%X",
		version->ic_manufacturer, version->ic_type, version->os_version, version->iasecc_version);

	if (card->ef_atr->issuer_data_len < 16)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid issuer data");

      	sizes->send =	 card->ef_atr->issuer_data[2] * 0x100 + card->ef_atr->issuer_data[3];
      	sizes->send_sc = card->ef_atr->issuer_data[6] * 0x100 + card->ef_atr->issuer_data[7];
      	sizes->recv =	 card->ef_atr->issuer_data[10] * 0x100 + card->ef_atr->issuer_data[11];
      	sizes->recv_sc = card->ef_atr->issuer_data[14] * 0x100 + card->ef_atr->issuer_data[15];

	card->max_send_size = sizes->send;
	card->max_recv_size = sizes->recv;

	/* Most of the card producers interpret 'send' values as "maximum APDU data size".
	 * Oberthur strictly follows specification and interpret these values as "maximum APDU command size".
	 * Here we need 'data size'.
	 */
	if (card->max_send_size > 0xFF)
		card->max_send_size -= 5;

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA && card->flags & SC_CARD_FLAG_CONTACTLESS)
	{
		if (card->max_send_size > 223)
			card->max_send_size = 223;
		if (card->max_recv_size)
			card->max_recv_size = 223;
	}
	sc_log(ctx,
	       "EF.ATR: max send/recv sizes %"SC_FORMAT_LEN_SIZE_T"X/%"SC_FORMAT_LEN_SIZE_T"X",
	       card->max_send_size, card->max_recv_size);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init_gemalto(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	card->caps = SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT; 
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	sc_format_path("3F00", &path);
	rv = sc_select_file(card, &path, NULL);
	/* Result ignored*/

	rv = iasecc_parse_ef_atr(card);
	sc_log(ctx, "rv %i", rv);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		sc_log(ctx, "Select MF");
		rv = iasecc_select_mf(card, NULL);
		sc_log(ctx, "rv %i", rv);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		rv = iasecc_parse_ef_atr(card);
		sc_log(ctx, "rv %i", rv);
	}
	sc_log(ctx, "rv %i", rv);
	LOG_TEST_RET(ctx, rv, "Cannot read/parse EF.ATR");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int 
iasecc_oberthur_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *hist = card->reader->atr_info.hist_bytes;

	LOG_FUNC_CALLED(ctx);

	if (*hist != 0x80 || ((*(hist+1)&0xF0) != 0xF0))
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

	sc_log(ctx, "AID in historical_bytes '%s'", sc_dump_hex(hist + 2, *(hist+1) & 0x0F));

	if (memcmp(hist + 2, OberthurIASECC_AID.value, *(hist+1) & 0x0F))
		LOG_FUNC_RETURN(ctx, SC_ERROR_RECORD_NOT_FOUND);

	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, OberthurIASECC_AID.value, OberthurIASECC_AID.len);
	card->ef_atr->aid.len = OberthurIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int 
iasecc_LATVIA_EID_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *hist = card->reader->atr_info.hist_bytes;
	size_t hist_len = card->reader->atr_info.hist_bytes_len;

	LOG_FUNC_CALLED(ctx);

	//check 90:4C:41:54:56:49:41:2D:65:49:44
	//do not take AID from ATR (because not 0x80 with TLV sequence, with AID...)	

	if (*hist != 0x90 || ((hist_len - 1) < LatviaEid_ATR_MATCH.len))
	LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

 	if (memcmp(hist + 1, LatviaEid_ATR_MATCH.value, LatviaEid_ATR_MATCH.len))
		LOG_FUNC_RETURN(ctx, SC_ERROR_RECORD_NOT_FOUND);


	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, OberthurIASECC_AID.value, OberthurIASECC_AID.len);
	card->ef_atr->aid.len = OberthurIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_LATVIA_EIDV2_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *hist = card->reader->atr_info.hist_bytes;
	size_t hist_len = card->reader->atr_info.hist_bytes_len;

	LOG_FUNC_CALLED(ctx);

	if (*hist != 0x00 || hist_len < (LatviaEidV2_ATR_MATCH.len + 1))
		LOG_FUNC_RETURN(ctx, SC_ERROR_OBJECT_NOT_FOUND);

	if (memcmp(hist + 1, LatviaEidV2_ATR_MATCH.value, LatviaEidV2_ATR_MATCH.len))
		LOG_FUNC_RETURN(ctx, SC_ERROR_RECORD_NOT_FOUND);


	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, OberthurIASECC_AID.value, OberthurIASECC_AID.len);
	card->ef_atr->aid.len = OberthurIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_init_oberthur(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	card->caps = SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT; 
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	iasecc_parse_ef_atr(card);

	/* if we fail to select CM, */
	if (gp_select_card_manager(card)) {
		gp_select_isd_rid(card);
	}

	rv = iasecc_LATVIA_EID_match(card);
    if (SC_SUCCESS != rv)
        rv = iasecc_oberthur_match(card);
	LOG_TEST_RET(ctx, rv, "unknown Oberthur's IAS/ECC card");

	rv = iasecc_select_mf(card, NULL);
	LOG_TEST_RET(ctx, rv, "MF selection error");

	rv = iasecc_parse_ef_atr(card);
	LOG_TEST_RET(ctx, rv, "EF.ATR read or parse error");

	sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_init_latvia(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags, ext_flags;
	int rv = 0;
	struct sc_apdu apdu;
	unsigned char rbuf[0xC0];

	LOG_FUNC_CALLED(ctx);

	card->caps = SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	card->flags |= SC_CARD_FLAG_GETRESP_NO_SM;

	/* avoid compatibility issues with OpenSC during SM */
	if (card->flags & SC_CARD_FLAG_CONTACTLESS)
	{
		card->max_send_size = 223;
		card->max_recv_size = 223;
	}

	rv = iasecc_LATVIA_EIDV2_match(card);
	LOG_TEST_RET(ctx, rv, "unknown Latvia eID v2 card");

#ifdef ENABLE_SM
	memset(&card->sm_ctx, 0, sizeof card->sm_ctx);
#endif

#ifdef ENABLE_OPENPACE
	EAC_init();
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_ALL;
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_TA;
	eac_default_flags |= EAC_FLAG_DISABLE_CHECK_CA;
#endif

	rv = iasecc_parse_ef_atr(card);
	if (rv < 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_CARD, "EF.ATR read or parse error");

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x80 | 0x1C, 0);
	apdu.le = sizeof(rbuf);
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU ReadBinary EF CardAccess transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Get 'EF Card Access' data failed");

	iasecc_cache_pace_data(card, rbuf, apdu.resplen, NULL, 0);

	flags = SC_ALGORITHM_RSA_PAD_PKCS1
		| SC_ALGORITHM_RSA_HASH_NONE
		| SC_ALGORITHM_RSA_HASH_SHA1
		| SC_ALGORITHM_RSA_HASH_SHA256
		| SC_ALGORITHM_RSA_HASH_SHA384
		| SC_ALGORITHM_RSA_HASH_SHA512;

	ext_flags = SC_ALGORITHM_EXT_EC_UNCOMPRESES;
	ext_flags |= SC_ALGORITHM_EXT_EC_NAMEDCURVE;
	ext_flags |= SC_ALGORITHM_EXT_EC_F_P;

	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	flags = SC_ALGORITHM_ECDSA_RAW | SC_ALGORITHM_ECDH_CDH_RAW | SC_ALGORITHM_ECDSA_HASH_NONE | SC_ALGORITHM_ECDSA_HASHES;

	_sc_card_add_ec_alg(card, 384, flags, ext_flags, NULL);

	if (card->flags & SC_CARD_FLAG_CONTACTLESS)
		card->name = "Latvia eID v2 Card - Contacless";
	else
		card->name = "Latvia eID v2 Card";

	sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_latvia_select_ADF_QSCD(struct sc_card *card)
{
	/* Select ADF again in case it got de-selected by another application */
	struct sc_path path;

	if (card->cache.current_df)
	{
		sc_file_free(card->cache.current_df);
		card->cache.current_df = NULL;
	}

	memset(&path, 0, sizeof(struct sc_path));
	path.type = SC_PATH_TYPE_DF_NAME;
	memcpy(path.value, LatviaV2_ADF_QSCD.value, LatviaV2_ADF_QSCD.len);
	path.len = LatviaV2_ADF_QSCD.len;

	return iasecc_select_file_pace(card, &path, NULL, 0);
}


static int
iasecc_mi_match(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned char resp[0x100];
	size_t resp_len;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	resp_len = sizeof(resp);
	rv = iasecc_select_aid(card, &MIIASECC_AID, resp, &resp_len);
	LOG_TEST_RET(ctx, rv, "IASECC: failed to select MI IAS/ECC applet");

	if (!card->ef_atr)
		card->ef_atr = calloc(1, sizeof(struct sc_ef_atr));
	if (!card->ef_atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	memcpy(card->ef_atr->aid.value, MIIASECC_AID.value, MIIASECC_AID.len);
	card->ef_atr->aid.len = MIIASECC_AID.len;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_init_amos_or_sagem(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	unsigned int flags;
	int rv = 0;

	LOG_FUNC_CALLED(ctx);

	flags = IASECC_CARD_DEFAULT_FLAGS;

	_sc_card_add_rsa_alg(card, 1024, flags, 0x10001);
	_sc_card_add_rsa_alg(card, 2048, flags, 0x10001);

	card->caps = SC_CARD_CAP_RNG;
	card->caps |= SC_CARD_CAP_APDU_EXT;
	card->caps |= SC_CARD_CAP_USE_FCI_AC;

	if (card->type == SC_CARD_TYPE_IASECC_MI)   {
		rv = iasecc_mi_match(card);
		if (rv)
			card->type = SC_CARD_TYPE_IASECC_MI2;
		else
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	rv = iasecc_parse_ef_atr(card);
	if (rv == SC_ERROR_FILE_NOT_FOUND)   {
		rv = iasecc_select_mf(card, NULL);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		rv = iasecc_parse_ef_atr(card);
	}
	LOG_TEST_RET(ctx, rv, "IASECC: ATR parse failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_init(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *private_data = NULL;
	int ii, rv = SC_ERROR_NO_CARD_SUPPORT;

	LOG_FUNC_CALLED(ctx);
	private_data = (struct iasecc_private_data *) calloc(1, sizeof(struct iasecc_private_data));
	if (private_data == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);

	for(ii=0;iasecc_known_atrs[ii].atr;ii++)   {
		if (card->type == iasecc_known_atrs[ii].type)   {
			card->name = iasecc_known_atrs[ii].name;
			card->flags |= iasecc_known_atrs[ii].flags;
			break;
		}
	}

	if (!iasecc_known_atrs[ii].atr)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_CARD_SUPPORT);

	if (strcmp(ctx->app_name, "cardmod") == 0) {
		private_data->cardmod = 1;
	}

	card->cla  = 0x00;
	card->drv_data = private_data;

	if (card->type == SC_CARD_TYPE_IASECC_GEMALTO)
		rv = iasecc_init_gemalto(card);
	else if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR)
		rv = iasecc_init_oberthur(card);
	else if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
		rv = iasecc_init_latvia(card);
	else if (card->type == SC_CARD_TYPE_IASECC_SAGEM)
		rv = iasecc_init_amos_or_sagem(card);
	else if (card->type == SC_CARD_TYPE_IASECC_AMOS)
		rv = iasecc_init_amos_or_sagem(card);
	else if (card->type == SC_CARD_TYPE_IASECC_MI)
		rv = iasecc_init_amos_or_sagem(card);
	else
		LOG_FUNC_RETURN(ctx, SC_ERROR_NO_CARD_SUPPORT);


	if (!rv)   {
		if (card->ef_atr && card->ef_atr->aid.len)   {
			struct sc_path path;

			memset(&path, 0, sizeof(struct sc_path));
			path.type = SC_PATH_TYPE_DF_NAME;
			memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
			path.len = card->ef_atr->aid.len;
	
			rv = iasecc_select_file(card, &path, NULL);
			sc_log(ctx, "Select ECC ROOT with the AID from EF.ATR: rv %i", rv);
			LOG_TEST_RET(ctx, rv, "Select EF.ATR AID failed");
		}

		rv = iasecc_get_serialnr(card, NULL);
	}

#ifdef ENABLE_SM
	if (!(card->flags & SC_CARD_FLAG_PACE_STATE_ACTIVE))
	{
		card->sm_ctx.ops.read_binary = _iasecc_sm_read_binary;
		card->sm_ctx.ops.update_binary = _iasecc_sm_update_binary;
	}
#endif

	if (!rv)
		sc_log(ctx, "EF.ATR(aid:'%s')", sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len));
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buf, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int rv;
	int pace_workaround = (card->type == SC_CARD_TYPE_IASECC_LATVIA && card->flags & SC_CARD_FLAG_CONTACTLESS)? 1 : 0;
	size_t maxLe = pace_workaround? 223 : 256;
	size_t maxReadLength = pace_workaround? 223 : IASECC_READ_BINARY_LENGTH_MAX;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_read_binary(card:%p) offs %i; count %"SC_FORMAT_LEN_SIZE_T"u",
	       card, offs, count);
	if (offs > 0x7fff) {
		sc_log(ctx, "invalid EF offset: 0x%X > 0x7FFF", offs);
		return SC_ERROR_OFFSET_TOO_LARGE;
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, (offs >> 8) & 0x7F, offs & 0xFF);
	apdu.le = count < maxLe ? count : maxLe;
	apdu.resplen = count;
	apdu.resp = buf;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_read_binary() failed");
	sc_log(ctx,
	       "iasecc_read_binary() apdu.resplen %"SC_FORMAT_LEN_SIZE_T"u",
	       apdu.resplen);

	if (apdu.resplen == maxReadLength && apdu.resplen < count)   {
		rv = iasecc_read_binary(card, offs + apdu.resplen, buf + apdu.resplen, count - apdu.resplen, flags);
		if (rv != SC_ERROR_WRONG_LENGTH)   {
			LOG_TEST_RET(ctx, rv, "iasecc_read_binary() read tail failed");
			apdu.resplen += rv;
		}
	}

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


static int
iasecc_erase_binary(struct sc_card *card, unsigned int offs, size_t count, unsigned long flags)
{
	struct sc_context *ctx = card->ctx;
	unsigned char *tmp = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_erase_binary(card:%p) count %"SC_FORMAT_LEN_SIZE_T"u",
	       card, count);
	if ((card->type == SC_CARD_TYPE_IASECC_LATVIA))
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	if (!count)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "'ERASE BINARY' failed: invalid size to erase");

	tmp = malloc(count);
	if (!tmp)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot allocate temporary buffer");
	memset(tmp, 0xFF, count);

	rv = sc_update_binary(card, offs, tmp, count, flags);
	free(tmp);
	LOG_TEST_RET(ctx, rv, "iasecc_erase_binary() update binary error");
	LOG_FUNC_RETURN(ctx, rv);
}


#if ENABLE_SM
static int
_iasecc_sm_read_binary(struct sc_card *card, unsigned int offs,
		unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_sm_read_binary() card:%p offs:%i count:%"SC_FORMAT_LEN_SIZE_T"u ",
	       card, offs, count);
	if (offs > 0x7fff)
		LOG_TEST_RET(ctx, SC_ERROR_OFFSET_TOO_LARGE, "Invalid arguments");

	if (count == 0)
		return 0;

	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_ef)   {
		entry = sc_file_get_acl_entry(card->cache.current_ef, SC_AC_OP_READ);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_sm_read() 'READ' ACL not present");

		sc_log(ctx, "READ method/reference %X/%X", entry->method, entry->key_ref);
		if ((entry->method == SC_AC_SCB) && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
			unsigned char se_num = (entry->method == SC_AC_SCB) ? (entry->key_ref & IASECC_SCB_METHOD_MASK_REF) : 0;

			rv = iasecc_sm_read_binary(card, se_num, offs, buff, count);
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
_iasecc_sm_update_binary(struct sc_card *card, unsigned int offs,
		const unsigned char *buff, size_t count)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	int rv;

	if (count == 0)
		return SC_SUCCESS;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_sm_read_binary() card:%p offs:%i count:%"SC_FORMAT_LEN_SIZE_T"u ",
	       card, offs, count);
	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_ef)   {
		entry = sc_file_get_acl_entry(card->cache.current_ef, SC_AC_OP_UPDATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_sm_update() 'UPDATE' ACL not present");

		sc_log(ctx, "UPDATE method/reference %X/%X", entry->method, entry->key_ref);
		if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
			unsigned char se_num = entry->method == SC_AC_SCB ? entry->key_ref & IASECC_SCB_METHOD_MASK_REF : 0;

			rv = iasecc_sm_update_binary(card, se_num, offs, buff, count);
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	LOG_FUNC_RETURN(ctx, 0);
}
#endif


static int
iasecc_emulate_fcp(struct sc_context *ctx, struct sc_apdu *apdu)
{
	unsigned char dummy_df_fcp[] = {
		0x62,0xFF,
			0x82,0x01,0x38,
			0x8A,0x01,0x05,
			0xA1,0x04,0x8C,0x02,0x02,0x00,
			0x84,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
				0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
	};

	LOG_FUNC_CALLED(ctx);

	if (apdu->p1 != 0x04)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "FCP emulation supported only for the DF-NAME selection type");
	if (apdu->datalen > 16)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid DF-NAME length");
	if (apdu->resplen < apdu->datalen + 16)
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "not enough space for FCP data");

	memcpy(dummy_df_fcp + 16, apdu->data, apdu->datalen);
	dummy_df_fcp[15] = apdu->datalen;
	dummy_df_fcp[1] = apdu->datalen + 14;
	memcpy(apdu->resp, dummy_df_fcp, apdu->datalen + 16);
	apdu->resplen = apdu->datalen + 16;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


/* TODO: redesign using of cache
 * TODO: do not keep intermediate results in 'file_out' argument */
static int
iasecc_select_file(struct sc_card *card, const struct sc_path *path,
		 struct sc_file **file_out)
{
	int r = iasecc_select_file_pace (card, path, file_out, 0);
	if (r == SC_ERROR_INS_NOT_SUPPORTED || r == SC_ERROR_WRONG_LENGTH)
	{
		if (SC_SUCCESS == iasecc_restore_context(card))
			r = iasecc_select_file_pace(card, path, file_out, 0);
	}

	return r;
}

static int
iasecc_select_file_pace(struct sc_card *card, const struct sc_path *path,
		 struct sc_file **file_out, int ignorePaceError)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path lpath;
	int cache_valid = card->cache.valid, df_from_cache = 0;
	int rv, ii;
	int mf_selected = 0;

	LOG_FUNC_CALLED(ctx);
	memcpy(&lpath, path, sizeof(struct sc_path));
	if (file_out)
		*file_out = NULL;

	sc_log(ctx,
	       "iasecc_select_file(card:%p) path.len %"SC_FORMAT_LEN_SIZE_T"u; path.type %i; aid_len %"SC_FORMAT_LEN_SIZE_T"u",
	       card, path->len, path->type, path->aid.len);
	sc_log(ctx, "iasecc_select_file() path:%s", sc_print_path(path));

	sc_print_cache(card);
	if (path->type != SC_PATH_TYPE_DF_NAME
			&& lpath.len >= 2
			&& lpath.value[0] == 0x3F && lpath.value[1] == 0x00)   {
		sc_log(ctx, "EF.ATR(aid:'%s')", card->ef_atr ? sc_dump_hex(card->ef_atr->aid.value, card->ef_atr->aid.len) : "");

		rv = iasecc_select_mf(card, file_out);
		LOG_TEST_RET(ctx, rv, "MF selection error");

		memmove(&lpath.value[0], &lpath.value[2], lpath.len - 2);
		lpath.len -=  2;
		mf_selected = 1;
	}

	if (lpath.aid.len)	{
		struct sc_file *file = NULL;
		struct sc_path ppath;

		sc_log(ctx,
		       "iasecc_select_file() select parent AID:%p/%"SC_FORMAT_LEN_SIZE_T"u",
		       lpath.aid.value, lpath.aid.len);
		sc_log(ctx, "iasecc_select_file() select parent AID:%s", sc_dump_hex(lpath.aid.value, lpath.aid.len));
		memset(&ppath, 0, sizeof(ppath));
		memcpy(ppath.value, lpath.aid.value, lpath.aid.len);
		ppath.len = lpath.aid.len;
		ppath.type = SC_PATH_TYPE_DF_NAME;

		if (card->cache.valid && card->cache.current_df
				&& card->cache.current_df->path.len == lpath.aid.len
				&& !memcmp(card->cache.current_df->path.value, lpath.aid.value, lpath.aid.len))
			df_from_cache = 1;

		rv = iasecc_select_file_pace(card, &ppath, &file, ignorePaceError);
		LOG_TEST_RET(ctx, rv, "select AID path failed");

		if (file_out)
			*file_out = file;
		else
		   sc_file_free(file);

		if (lpath.type == SC_PATH_TYPE_DF_NAME)
			lpath.type = SC_PATH_TYPE_FROM_CURRENT;
	}

	if (lpath.type == SC_PATH_TYPE_PATH)
		lpath.type = SC_PATH_TYPE_FROM_CURRENT;

	if (!lpath.len)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);

	sc_print_cache(card);

	if (card->cache.valid && card->cache.current_df && lpath.type == SC_PATH_TYPE_DF_NAME
			&& card->cache.current_df->path.len == lpath.len
			&& !memcmp(card->cache.current_df->path.value, lpath.value, lpath.len))   {
		sc_log(ctx, "returns current DF path %s", sc_print_path(&card->cache.current_df->path));
		if (file_out)   {
			sc_file_free(*file_out);
			sc_file_dup(file_out, card->cache.current_df);
		}

		sc_print_cache(card);
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	}

	do   {
		struct sc_apdu apdu;
		struct sc_file *file = NULL;
		unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE] = { 0 };
		int pathlen = lpath.len;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xA4, 0x00, 0x00);

		if (card->type != SC_CARD_TYPE_IASECC_GEMALTO
				&& card->type != SC_CARD_TYPE_IASECC_OBERTHUR
				&& card->type != SC_CARD_TYPE_IASECC_LATVIA
				&& card->type != SC_CARD_TYPE_IASECC_SAGEM
				&& card->type != SC_CARD_TYPE_IASECC_AMOS
				&& card->type != SC_CARD_TYPE_IASECC_MI
				&& card->type != SC_CARD_TYPE_IASECC_MI2)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Unsupported card");

		if (lpath.type == SC_PATH_TYPE_FILE_ID)   {
			apdu.p1 = 0x02;
			if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR || card->type == SC_CARD_TYPE_IASECC_LATVIA)   {
				apdu.p1 = 0x01;
				apdu.p2 = 0x04;
			}

			if (card->type == SC_CARD_TYPE_IASECC_AMOS)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_MI)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_MI2)
				apdu.p2 = 0x04;
		}
		else if (lpath.type == SC_PATH_TYPE_FROM_CURRENT) {
			apdu.p1 = 0x09;
			if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR || card->type == SC_CARD_TYPE_IASECC_LATVIA)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_AMOS)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_MI)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_MI2)
				apdu.p2 = 0x04;

		}
		else if (lpath.type == SC_PATH_TYPE_PARENT)   {
			apdu.p1 = 0x03;
			pathlen = 0;
			apdu.cse = SC_APDU_CASE_2_SHORT;
		}
		else if (lpath.type == SC_PATH_TYPE_DF_NAME)   {
			apdu.p1 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_AMOS)
				apdu.p2 = 0x04;
			if (card->type == SC_CARD_TYPE_IASECC_MI2)
				apdu.p2 = 0x04;
		}
		else   {
			sc_log(ctx, "Invalid PATH type: 0x%X", lpath.type);
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "iasecc_select_file() invalid PATH type");
		}

		for (ii=0; ii<2; ii++)   {
			apdu.lc = pathlen;
			apdu.data = lpath.value;
			apdu.datalen = pathlen;

			apdu.resp = rbuf;
			apdu.resplen = sizeof(rbuf);
			apdu.le = 256;

			rv = sc_transmit_apdu(card, &apdu);
			if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
			{
				if ((card->flags & SC_CARD_FLAG_CONTACTLESS)
					&& (((rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) || (apdu.sw1 == 0x69 && (apdu.sw2 == 0x82 || apdu.sw2 == 0x88))) && !ignorePaceError)
					)
				{
					struct sc_path path;
					struct sc_file *save_current_df = NULL, *save_current_ef = NULL;

					if (card->cache.valid && card->cache.current_df) {
						sc_file_dup(&save_current_df, card->cache.current_df);
					}

					if (card->cache.valid && card->cache.current_ef) {
						sc_file_dup(&save_current_ef, card->cache.current_ef);
					}

					/* try to select MF */
					sc_format_path("3F00", &path);
					path.type = SC_PATH_TYPE_FILE_ID;
					rv = iasecc_select_file(card, &path, NULL);
					if (rv >= 0)
					{
						int pace_status = do_pace(card, NULL);
						if (pace_status < 0)
							sc_log(ctx, "PACE authentication failed");
						else
						{
							card->flags |= SC_CARD_FLAG_PACE_STATE_ACTIVE;
							card->flags &= ~(SC_CARD_FLAG_PACE_STATE_NOT_ACTIVE | SC_CARD_FLAG_PACE_STATE_UNKNOWN);

							/* restore current df and current ef*/
							if (save_current_df) {
								iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
							}

							if (save_current_ef) {
								iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
							}

							apdu.resp = rbuf;
							apdu.resplen = sizeof(rbuf);
							rv = sc_transmit_apdu(card, &apdu);
						}
					}
					else
					{
						/* try to restore current df and current ef*/
						if (save_current_df) {
							iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
						}

						if (save_current_ef) {
							iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
						}
					}

					if (save_current_df) {
						sc_file_free(save_current_df);
					}

					if (save_current_ef) {
						sc_file_free(save_current_ef);
					}
				}
			}

			LOG_TEST_RET(ctx, rv, "APDU transmit failed");
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
			if (rv == SC_ERROR_INCORRECT_PARAMETERS &&
					lpath.type == SC_PATH_TYPE_DF_NAME && apdu.p2 == 0x00)   {
				apdu.p2 = 0x0C;
				continue;
			}

			if (ii)   {
				/* 'SELECT AID' do not returned FCP. Try to emulate. */
				apdu.resplen = sizeof(rbuf);
				rv = iasecc_emulate_fcp(ctx, &apdu);
				LOG_TEST_RET(ctx, rv, "Failed to emulate DF FCP");
			}

			break;
		}

		/*
		 * Using of the cached DF and EF can cause problems in the multi-thread environment.
		 * FIXME: introduce config. option that invalidates this cache outside the locked card session,
		 *        (or invent something else)
		 */
		if (rv == SC_ERROR_FILE_NOT_FOUND && cache_valid && df_from_cache)   {
			sc_invalidate_cache(card);
			sc_log(ctx, "iasecc_select_file() file not found, retry without cached DF");
			if (file_out)   {
				sc_file_free(*file_out);
				*file_out = NULL;
			}
			rv = iasecc_select_file_pace(card, path, file_out, ignorePaceError);
			LOG_FUNC_RETURN(ctx, rv);
		}

		LOG_TEST_RET(ctx, rv, "iasecc_select_file() check SW failed");

		sc_log(ctx,
		       "iasecc_select_file() apdu.resp %"SC_FORMAT_LEN_SIZE_T"u",
		       apdu.resplen);
		if (apdu.resplen)   {
			sc_log(ctx, "apdu.resp %02X:%02X:%02X...", apdu.resp[0], apdu.resp[1], apdu.resp[2]);

			switch (apdu.resp[0]) {
			case 0x62:
			case 0x6F:
				file = sc_file_new();
				if (file == NULL)
					LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
				file->path = lpath;

				rv = iasecc_process_fci(card, file, apdu.resp, apdu.resplen);
				if (rv)
					LOG_FUNC_RETURN(ctx, rv);
				break;
			default:
				LOG_FUNC_RETURN(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED);
			}

			sc_log(ctx, "FileType %i", file->type);
			if (file->type == SC_FILE_TYPE_DF)   {
				if (card->cache.valid)
					sc_file_free(card->cache.current_df);
				card->cache.current_df = NULL;


				if (card->cache.valid)
					sc_file_free(card->cache.current_ef);
				card->cache.current_ef = NULL;

				sc_file_dup(&card->cache.current_df, file);
				card->cache.valid = 1;
			}
			else   {
				if (card->cache.valid)
					sc_file_free(card->cache.current_ef);

				card->cache.current_ef = NULL;

				sc_file_dup(&card->cache.current_ef, file);
			}

			if (file_out)   {
				sc_file_free(*file_out);
				*file_out = file;
			}
			else   {
				sc_file_free(file);
			}
		}
		else if (lpath.type == SC_PATH_TYPE_DF_NAME)   {
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;

			sc_file_free(card->cache.current_ef);
			card->cache.current_ef = NULL;

			card->cache.valid = 1;
		}
	} while(0);

	sc_print_cache(card);
	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_process_fci(struct sc_card *card, struct sc_file *file,
		 const unsigned char *buf, size_t buflen)
{
	struct sc_context *ctx = card->ctx;
	size_t taglen;
	int rv, ii, offs;
	const unsigned char *acls = NULL, *tag = NULL;
	unsigned char mask;
	unsigned char ops_DF[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_CREATE, 0xFF
	};
	unsigned char ops_EF[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};

	LOG_FUNC_CALLED(ctx);

	sc_log(ctx,
		"iasecc_process_fci called on data(%"SC_FORMAT_LEN_SIZE_T"u) %s",
		buflen, sc_dump_hex(buf, buflen));

	tag = sc_asn1_find_tag(ctx,  buf, buflen, 0x6F, &taglen);
	sc_log(ctx, "processing FCI: 0x6F tag %p", tag);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	tag = sc_asn1_find_tag(ctx,  buf, buflen, 0x62, &taglen);
	sc_log(ctx, "processing FCI: 0x62 tag %p", tag);
	if (tag != NULL) {
		sc_log(ctx, "  FCP length %"SC_FORMAT_LEN_SIZE_T"u", taglen);
		buf = tag;
		buflen = taglen;
	}

	rv = iso_ops->process_fci(card, file, buf, buflen);
	LOG_TEST_RET(ctx, rv, "ISO parse FCI failed");
/*
	Gemalto:  6F 19 80 02 02 ED 82 01 01 83 02 B0 01 88 00	8C 07 7B 17 17 17 17 17 00 8A 01 05 90 00
	Sagem:    6F 17 62 15 80 02 00 7D 82 01 01                   8C 02 01 00 83 02 2F 00 88 01 F0 8A 01 05 90 00
	Oberthur: 62 1B 80 02 05 DC 82 01 01 83 02 B0 01 88 00 A1 09 8C 07 7B 17 FF 17 17 17 00 8A 01 05 90 00
*/

	sc_log(ctx, "iasecc_process_fci() type %i; let's parse file ACLs", file->type);

	tag = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS, &taglen);
	if (tag)
		acls = sc_asn1_find_tag(ctx, tag, taglen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);
	else
		acls = sc_asn1_find_tag(ctx, buf, buflen, IASECC_DOCP_TAG_ACLS_CONTACT, &taglen);

	if (!acls)   {
		sc_log(ctx,
		       "ACLs not found in data(%"SC_FORMAT_LEN_SIZE_T"u) %s",
		       buflen, sc_dump_hex(buf, buflen));
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "ACLs tag missing");
	}

	sc_log(ctx, "ACLs(%"SC_FORMAT_LEN_SIZE_T"u) '%s'", taglen,
	       sc_dump_hex(acls, taglen));

	if (taglen >= 2)
	{
		mask = 0x40, offs = 1;
		for (ii = 0; ii < 7 && offs < taglen; ii++, mask /= 2) {
			unsigned char op = file->type == SC_FILE_TYPE_DF ? ops_DF[ii] : ops_EF[ii];

			if (!(mask & acls[0]))
				continue;

			sc_log(ctx, "ACLs mask 0x%X, offs %i, op 0x%X, acls[offs] 0x%X", mask, offs, op, acls[offs]);
			if (op == 0xFF) {
				;
			}
			else if (acls[offs] == 0) {
				sc_file_add_acl_entry(file, op, SC_AC_NONE, 0);
			}
			else if (acls[offs] == 0xFF) {
				sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
			}
			else if ((acls[offs] & IASECC_SCB_METHOD_MASK) == IASECC_SCB_METHOD_USER_AUTH) {
				sc_file_add_acl_entry(file, op, SC_AC_SEN, acls[offs] & IASECC_SCB_METHOD_MASK_REF);
			}
			else if (acls[offs] & IASECC_SCB_METHOD_MASK) {
				sc_file_add_acl_entry(file, op, SC_AC_SCB, acls[offs]);
			}
			else {
				sc_log(ctx, "Warning: non supported SCB method: %X", acls[offs]);
				sc_file_add_acl_entry(file, op, SC_AC_NEVER, 0);
			}

			offs++;
		}
	}
	LOG_FUNC_RETURN(ctx, 0);
}


static int
iasecc_fcp_encode(struct sc_card *card, struct sc_file *file, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buf[0x80], type;
	unsigned char  ops[7] = {
		SC_AC_OP_DELETE, 0xFF, SC_AC_OP_ACTIVATE, SC_AC_OP_DEACTIVATE, 0xFF, SC_AC_OP_UPDATE, SC_AC_OP_READ
	};
	unsigned char smbs[8];
	size_t ii, offs = 0, amb, mask, nn_smb;

	LOG_FUNC_CALLED(ctx);

	if (file->type == SC_FILE_TYPE_DF)
		type = IASECC_FCP_TYPE_DF;
	else 
		type = IASECC_FCP_TYPE_EF;

	buf[offs++] = IASECC_FCP_TAG_SIZE;
	buf[offs++] = 2;
	buf[offs++] = (file->size >> 8) & 0xFF;
	buf[offs++] = file->size & 0xFF;

	buf[offs++] = IASECC_FCP_TAG_TYPE;
	buf[offs++] = 1;
	buf[offs++] = type;

	buf[offs++] = IASECC_FCP_TAG_FID;
	buf[offs++] = 2;
	buf[offs++] = (file->id >> 8) & 0xFF;
	buf[offs++] = file->id & 0xFF;

	buf[offs++] = IASECC_FCP_TAG_SFID;
	buf[offs++] = 0;

	amb = 0, mask = 0x40, nn_smb = 0; 
	for (ii = 0; ii < sizeof(ops); ii++, mask >>= 1) {
		const struct sc_acl_entry *entry;
		
		if (ops[ii]==0xFF)
			continue;

		entry = sc_file_get_acl_entry(file, ops[ii]);
		if (!entry)
			continue;

		sc_log(ctx, "method %X; reference %X", entry->method, entry->key_ref);
		if (entry->method == SC_AC_NEVER)
			continue;
		else if (entry->method == SC_AC_NONE)
			smbs[nn_smb++] = 0x00;
		else if (entry->method == SC_AC_CHV)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_USER_AUTH;
		else if (entry->method == SC_AC_SEN)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_USER_AUTH;
		else if (entry->method == SC_AC_SCB)
			smbs[nn_smb++] = entry->key_ref;
		else if (entry->method == SC_AC_PRO)
			smbs[nn_smb++] = entry->key_ref | IASECC_SCB_METHOD_SM;
		else
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Non supported AC method");

		amb |= mask;
		sc_log(ctx,
		       "%"SC_FORMAT_LEN_SIZE_T"u: AMB %"SC_FORMAT_LEN_SIZE_T"X; nn_smb %"SC_FORMAT_LEN_SIZE_T"u",
		       ii, amb, nn_smb);
	}

	/* TODO: Encode contactless ACLs and life cycle status for all IAS/ECC cards */
	if (card->type == SC_CARD_TYPE_IASECC_SAGEM ||
			card->type == SC_CARD_TYPE_IASECC_AMOS )  {
		unsigned char status = 0;

		buf[offs++] = IASECC_FCP_TAG_ACLS;
		buf[offs++] = 2*(2 + 1 + nn_smb);

		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACT;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;

		/* Same ACLs for contactless */
		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACTLESS;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;

		if (file->status == SC_FILE_STATUS_ACTIVATED)
			status = 0x05;
		else if (file->status == SC_FILE_STATUS_CREATION)
			status = 0x01;

		if (status)   {
			buf[offs++] = 0x8A;
			buf[offs++] = 0x01;
			buf[offs++] = status;
		}
	}
	else   {
		buf[offs++] = IASECC_FCP_TAG_ACLS;
		buf[offs++] = 2 + 1 + nn_smb;

		buf[offs++] = IASECC_FCP_TAG_ACLS_CONTACT;
		buf[offs++] = nn_smb + 1;
		buf[offs++] = amb;
		memcpy(buf + offs, smbs, nn_smb);
		offs += nn_smb;
	}

	if (out)   {
		if (out_len < offs) 
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to encode FCP");
		memcpy(out, buf, offs); 
	}

	LOG_FUNC_RETURN(ctx, offs);
}


static int
iasecc_create_file(struct sc_card *card, struct sc_file *file)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	const struct sc_acl_entry *entry = NULL;
	unsigned char sbuf[0x100];
	size_t sbuf_len;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	if (file->type != SC_FILE_TYPE_WORKING_EF)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Creation of the file with of this type is not supported");

	sbuf_len = iasecc_fcp_encode(card, file, sbuf + 2, sizeof(sbuf)-2);
	LOG_TEST_RET(ctx, sbuf_len, "FCP encode error");

	sbuf[0] = IASECC_FCP_TAG;
	sbuf[1] = sbuf_len;

	if (card->cache.valid && card->cache.current_df)   {
		entry = sc_file_get_acl_entry(card->cache.current_df, SC_AC_OP_CREATE);
		if (!entry)
			LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "iasecc_create_file() 'CREATE' ACL not present");

		sc_log(ctx, "iasecc_create_file() 'CREATE' method/reference %X/%X", entry->method, entry->key_ref);
		sc_log(ctx, "iasecc_create_file() create data: '%s'", sc_dump_hex(sbuf, sbuf_len + 2));
		if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
                        rv = iasecc_sm_create_file(card, entry->key_ref & IASECC_SCB_METHOD_MASK_REF, sbuf, sbuf_len + 2);
                        LOG_TEST_RET(ctx, rv, "iasecc_create_file() SM create file error");

                        rv = iasecc_select_file(card, &file->path, NULL);
                        LOG_FUNC_RETURN(ctx, rv);

		}
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xE0, 0, 0);
	apdu.data = sbuf;
	apdu.datalen = sbuf_len + 2;
	apdu.lc = sbuf_len + 2;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_create_file() create file error");

	rv = iasecc_select_file(card, &file->path, NULL);
	LOG_TEST_RET(ctx, rv, "Cannot select newly created file");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_get_challenge(struct sc_card *card, u8 * rnd, size_t len)
{
	/* As IAS/ECC cannot handle other data length than 0x08 */
	u8 rbuf[8];
	size_t out_len;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	r = iso_ops->get_challenge(card, rbuf, sizeof rbuf);
	LOG_TEST_RET(card->ctx, r, "GET CHALLENGE cmd failed");

	if (len < (size_t) r) {
		out_len = len;
	} else {
		out_len = (size_t) r;
	}
	memcpy(rnd, rbuf, out_len);

	LOG_FUNC_RETURN(card->ctx, (int) out_len);
}


static int 
iasecc_logout(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct sc_path path;
	int rv;
	struct sc_file *save_current_df = NULL, *save_current_ef = NULL;

	LOG_FUNC_CALLED(ctx);
	if ((card->type != SC_CARD_TYPE_IASECC_LATVIA) && (!card->ef_atr || !card->ef_atr->aid.len))
		return SC_SUCCESS;

	if (card->cache.valid && card->cache.current_df)   {
		sc_file_dup(&save_current_df, card->cache.current_df);
		if (save_current_df == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
	}

	if (card->cache.valid && card->cache.current_ef)   {
		sc_file_dup(&save_current_ef, card->cache.current_ef);
		if (save_current_ef == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current EF file");
	}

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
	{		
		struct sc_apdu apdu;

		rv = iasecc_select_mf (card, NULL);
		sc_log(ctx, "Select MF: rv %i", rv);

		/* de-verify PINauth manually */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0xFF, 0x01);
		rv = sc_transmit_apdu(card, &apdu);
		if (rv >= 0)
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (rv < 0)
			sc_log(ctx, "failed to de-verify PINauth. r = %i", rv);
	}
	else
	{
		memset(&path, 0, sizeof(struct sc_path));
		path.type = SC_PATH_TYPE_DF_NAME;
		memcpy(path.value, card->ef_atr->aid.value, card->ef_atr->aid.len);
		path.len = card->ef_atr->aid.len;

		rv = iasecc_select_file_pace(card, &path, NULL, 1);
		sc_log(ctx, "Select ECC ROOT with the AID from EF.ATR: rv %i", rv);
	}

	if (save_current_df)   {
      int localRv;

		sc_log(ctx, "iasecc_logout() restore current DF");
		localRv = iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
		if (localRv < 0)
		{
			sc_log(ctx, "Cannot return to saved DF: rv %i", localRv);
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;
		}		

		sc_file_free(save_current_df);
	}

	if (save_current_ef)   {
      int localRv;

		sc_log(ctx, "iasecc_pin_logout() restore current EF");
		localRv = iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
		if (localRv < 0)
		{
			sc_log(ctx, "Cannot return to saved EF: rv %i", localRv);
			sc_file_free(card->cache.current_ef);
			card->cache.current_ef = NULL;
		}		

		sc_file_free(save_current_ef);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int 
iasecc_finish(struct sc_card *card)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *private_data = (struct iasecc_private_data *)card->drv_data;
	struct iasecc_se_info *se_info = private_data->se_info, *next;

	LOG_FUNC_CALLED(ctx);

	while (se_info)   {
		sc_file_free(se_info->df);
		next = se_info->next;
		free(se_info);
		se_info = next;
	}

#ifdef ENABLE_SM
	sc_sm_stop(card);
#endif

#ifdef ENABLE_OPENPACE
	iasecc_pace_data_free(private_data);
#endif

	free(card->drv_data);
	card->drv_data = NULL;

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_delete_file(struct sc_card *card, const struct sc_path *path)
{
	struct sc_context *ctx = card->ctx;
	const struct sc_acl_entry *entry = NULL;
	struct sc_apdu apdu;
	struct sc_file *file = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_print_cache(card);

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	rv = iasecc_select_file(card, path, &file);
	if (rv == SC_ERROR_FILE_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, rv, "Cannot select file to delete");

	entry = sc_file_get_acl_entry(file, SC_AC_OP_DELETE);
	if (!entry)
		LOG_TEST_RET(ctx, SC_ERROR_OBJECT_NOT_FOUND, "Cannot delete file: no 'DELETE' acl");

	sc_log(ctx, "DELETE method/reference %X/%X", entry->method, entry->key_ref);
	if (entry->method == SC_AC_SCB && (entry->key_ref & IASECC_SCB_METHOD_SM))   {
		unsigned char se_num = (entry->method == SC_AC_SCB) ? (entry->key_ref & IASECC_SCB_METHOD_MASK_REF) : 0;
		rv = iasecc_sm_delete_file(card, se_num, file->id);
	}
	else   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0xE4, 0x00, 0x00);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Delete file failed");

		if (card->cache.valid)
			sc_file_free(card->cache.current_ef);
		card->cache.current_ef = NULL;
	}

	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_check_sw(struct sc_card *card, unsigned int sw1, unsigned int sw2)
{
	if (sw1 == 0x62 && sw2 == 0x82)
		return SC_SUCCESS;

	return iso_ops->check_sw(card, sw1, sw2);
}

static unsigned iasecc_normalize_algorithm_reference(unsigned algo_ref)
{
	if (algo_ref > 255)
	{
		/* handle case of extended algorithm identifiers*/
		switch (algo_ref)
		{
		case 0xFF110100: algo_ref = 0x12; break;
		case 0xFF110800: algo_ref = 0x14; break;
		case 0xFF130800: algo_ref = 0x34; break;
		case 0xFF140100: algo_ref = 0x42; break;
		case 0xFF140800: algo_ref = 0x44; break;
		case 0xFF150800: algo_ref = 0x54; break;
		case 0xFF160800: algo_ref = 0x64; break;
		case 0xFF200800: algo_ref = 0x04; break;
		case 0xFF300400: algo_ref = 0x0B; break;
		case 0xFF300100: algo_ref = 0x1A; break;

		}
	}

	return algo_ref;
}

static unsigned
iasecc_hash_from_algorithm_reference(unsigned algo_ref)
{
	switch (algo_ref)
	{
	case 0x12:
	case 0x14:
		return 0x10; /* sha1*/
	case 0x42:
	case 0x44:
		return 0x40; /* sha256*/
	case 0x34:
		return 0x30; /* sha224*/
	case 0x54:
		return 0x50; /* sha384*/
	case 0x64:
		return 0x60; /* sha512*/
	default:
		return 0;
	}
}

static unsigned
iasecc_mechanism_from_algorithm_reference(unsigned algo_ref)
{
	switch (algo_ref)
	{
	case 0x12: return CKM_SHA1_RSA_PKCS;
	case 0x14: return CKM_ECDSA_SHA1;
	case 0x42: return CKM_SHA256_RSA_PKCS;
	case 0x44: return CKM_ECDSA_SHA256;
	case 0x34: return CKM_ECDSA_SHA224;
	case 0x54: return CKM_ECDSA_SHA384;
	case 0x64: return CKM_ECDSA_SHA512;
	default:
		return 0;
	}
}

static unsigned
iasecc_hash_ref_from_mechanism(unsigned int mech)
{
	switch (mech)
	{
	case CKM_SHA1_RSA_PKCS: return 0x10;
	case CKM_ECDSA_SHA1: return 0x10;
	case CKM_SHA256_RSA_PKCS: return 0x40;
	case CKM_ECDSA_SHA256: return 0x40;
	case CKM_ECDSA_SHA224: return 0x30;
	case CKM_ECDSA_SHA384: return 0x50;
	case CKM_ECDSA_SHA512: return 0x60;
	default:
		return 0;
	}
}

static unsigned
iasecc_get_algorithm(struct sc_context *ctx, const struct sc_security_env *env,
		unsigned operation, unsigned mechanism)
{
    const struct sc_supported_algo_info *info = NULL;
    int ii;
    
    if (!env)
        return 0;

    for (ii=0;ii<SC_MAX_SUPPORTED_ALGORITHMS && env->supported_algos[ii].reference; ii++)
        if ((env->supported_algos[ii].operations & operation) 
			&& (env->supported_algos[ii].mechanism == mechanism))
            break;

    if (ii < SC_MAX_SUPPORTED_ALGORITHMS && env->supported_algos[ii].reference)   {
        info = &env->supported_algos[ii];
        sc_log(ctx, "found IAS/ECC algorithm %X:%X:%X:%X",
		       	info->reference, info->mechanism, info->operations, info->algo_ref); 
    }
    else   {
        sc_log(ctx, "cannot find IAS/ECC algorithm (operation:%X,mechanism:%X)", operation, mechanism);
    }
    
    return info? iasecc_normalize_algorithm_reference(info->algo_ref) : 0;
}

static int
iasecc_se_cache_info(struct sc_card *card, struct iasecc_se_info *se)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *se_info = NULL, *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	se_info = calloc(1, sizeof(struct iasecc_se_info));
	if (!se_info)
		LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "SE info allocation error");
	memcpy(se_info, se, sizeof(struct iasecc_se_info));

	if (card->cache.valid && card->cache.current_df)   {
		sc_file_dup(&se_info->df, card->cache.current_df);
		if (se_info->df == NULL)   {
			free(se_info);
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
		}
	}

	rv = iasecc_docp_copy(ctx, &se->docp, &se_info->docp);
	if (rv < 0)   {
		free(se_info->df);
		free(se_info);
		LOG_TEST_RET(ctx, rv, "Cannot make copy of DOCP");
	}

	if (!prv->se_info)   {
		prv->se_info = se_info;
	}
	else    {
		for (si = prv->se_info; si->next; si = si->next)
			;
		si->next = se_info;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_se_get_info_from_cache(struct sc_card *card, struct iasecc_se_info *se)
{
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info *si = NULL;
	int rv;

	LOG_FUNC_CALLED(ctx);

	for(si = prv->se_info; si; si = si->next)   {
		if (si->reference != se->reference)
			continue;
		if (!(card->cache.valid && card->cache.current_df) && si->df)
			continue;
		if (card->cache.valid && card->cache.current_df && !si->df)
			continue;
		if (card->cache.valid && card->cache.current_df && si->df)
			if (memcmp(&card->cache.current_df->path, &si->df->path, sizeof(struct sc_path)))
				continue;
		break;
	}

	if (!si)
		return SC_ERROR_OBJECT_NOT_FOUND;

	memcpy(se, si, sizeof(struct iasecc_se_info));

	if (si->df)   {
		sc_file_dup(&se->df, si->df);
		if (se->df == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
	}

	rv = iasecc_docp_copy(ctx, &si->docp, &se->docp);
	LOG_TEST_RET(ctx, rv, "Cannot make copy of DOCP");

	LOG_FUNC_RETURN(ctx, rv);
}


int
iasecc_se_get_info(struct sc_card *card, struct iasecc_se_info *se)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char rbuf[0x100];
	unsigned char sbuf_iasecc[10] = {
		0x4D, 0x08, IASECC_SDO_TEMPLATE_TAG, 0x06, 
		IASECC_SDO_TAG_HEADER, IASECC_SDO_CLASS_SE | IASECC_OBJECT_REF_LOCAL, 
		se->reference & 0x3F, 
		0x02, IASECC_SDO_CLASS_SE, 0x80
	};
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (se->reference > IASECC_SE_REF_MAX)
                LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	rv = iasecc_se_get_info_from_cache(card, se);
	if (rv == SC_ERROR_OBJECT_NOT_FOUND)   {
		sc_log(ctx, "No SE#%X info in cache, try to use 'GET DATA'", se->reference);

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
		apdu.data = sbuf_iasecc;
		apdu.datalen = sizeof(sbuf_iasecc);
		apdu.lc = apdu.datalen;
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);
		apdu.le = sizeof(rbuf);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "get SE data  error");
	
		rv = iasecc_se_parse(card, apdu.resp, apdu.resplen, se);
		LOG_TEST_RET(ctx, rv, "cannot parse SE data");

		rv = iasecc_se_cache_info(card, se);
		LOG_TEST_RET(ctx, rv, "failed to put SE data into cache");
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int 
iasecc_set_security_env(struct sc_card *card,
		const struct sc_security_env *env, int se_num)   
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	unsigned algo_ref;
	struct sc_apdu apdu;
	unsigned sign_meth, sign_ref, auth_meth, auth_ref, aflags;
	unsigned char cse_crt_at[] = {
		0x84, 0x01, 0xFF, 
		0x80, 0x01, IASECC_ALGORITHM_RSA_PKCS
	};
	unsigned char cse_crt_dst[] = {
		0x84, 0x01, 0xFF, 
		0x80, 0x01, (IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1)
	};
	unsigned char cse_crt_ht[] = {
		0x80, 0x01, IASECC_ALGORITHM_SHA1
	};
	unsigned char cse_crt_ct[] = {
		0x84, 0x01, 0xFF, 
		0x80, 0x01, (IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1)
	};
	int rv, operation = env->operation;
	int ii, is_ecc = (env->algorithm_flags & SC_ALGORITHM_RSA_PADS)? 0 : 1;
	int external_sign_hash = 0;
	unsigned int key_compulsory_alg = 0;

	/* TODO: take algorithm references from 5032, not from header file. */
	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_set_security_env(card:%p) operation 0x%X; senv.algorithm 0x%X, senv.algorithm_ref 0x%X", 
			card, env->operation, env->algorithm, env->algorithm_ref);

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = is_ecc? IASECC_SDO_CLASS_EC_PRIVATE : IASECC_SDO_CLASS_RSA_PRIVATE;
	sdo.sdo_ref  = env->key_ref[0] & ~IASECC_OBJECT_REF_LOCAL;
	rv = iasecc_sdo_get_data(card, &sdo);
	if (is_ecc)
		LOG_TEST_RET(ctx, rv, "Cannot get EC PRIVATE SDO data");
	else
		LOG_TEST_RET(ctx, rv, "Cannot get RSA PRIVATE SDO data");


	for (ii = 0; ii < sdo.data.prv_key.compulsory.size; ii++)
		key_compulsory_alg = (key_compulsory_alg << 8) + sdo.data.prv_key.compulsory.value[ii];
	key_compulsory_alg = iasecc_normalize_algorithm_reference(key_compulsory_alg);

	sc_log(ctx, "key compulsory algorithm 0x%4X", key_compulsory_alg);

	/* To made by iasecc_sdo_convert_to_file() */
	prv->key_size = *(sdo.docp.size.value + 0) * 0x100 + *(sdo.docp.size.value + 1);
	sc_log(ctx, "prv->key_size 0x%"SC_FORMAT_LEN_SIZE_T"X", prv->key_size);

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_COMPUTE_SIGNATURE, &sign_meth, &sign_ref);
	LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_SIGN acl");

	rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_INTERNAL_AUTHENTICATE, &auth_meth, &auth_ref);
	LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_INT_AUTH acl");

	aflags = env->algorithm_flags;

	if (!(aflags & SC_ALGORITHM_RSA_PAD_PKCS1) && !is_ecc)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Only supported RSA signature with PKCS1 padding");

	if (operation == SC_SEC_OPERATION_SIGN) {
		if (!(aflags & (SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)) && !is_ecc) {
			if ((card->type == SC_CARD_TYPE_IASECC_LATVIA) && (auth_meth == SC_AC_NEVER))
			{
				/* case of Adobe P11 signature with sign-only key that support only CKM_SHAXXX_RSA_PKCS */
				sc_log(ctx, "CKM_RSA_PKCS asked but key support only signature. Allow signature and input should include digest info.");
			}
			else
			{
				sc_log(ctx, "CKM_RSA_PKCS asked -- use 'AUTHENTICATE' sign operation instead of 'SIGN'");
				operation = SC_SEC_OPERATION_AUTHENTICATE;
			}
		}
		else if ((sign_meth == SC_AC_NEVER) && is_ecc) {
			sc_log(ctx, "AUTH ECC key -- use 'AUTHENTICATE' sign operation instead of 'SIGN'");
			operation = SC_SEC_OPERATION_AUTHENTICATE;
		}
		else if (sign_meth == SC_AC_NEVER) {
			sc_log(ctx, "CKM_SHAXXX_RSA_PKCS asked -- perform hash in software and use 'AUTHENTICATE' sign operation instead of 'SIGN'");
			operation = SC_SEC_OPERATION_AUTHENTICATE;
		}
	}

	if (operation == SC_SEC_OPERATION_SIGN)   {
		prv->op_method = sign_meth;
		prv->op_ref = sign_ref;
	}
	else if (operation == SC_SEC_OPERATION_AUTHENTICATE)   {
		if (auth_meth == SC_AC_NEVER)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED /*SC_ERROR_NOT_ALLOWED*/, "INTERNAL_AUTHENTICATE is not allowed for this key");

		prv->op_method = auth_meth;
		prv->op_ref = auth_ref;
	}

	sc_log(ctx, "senv.algorithm 0x%X, senv.algorithm_ref 0x%X", env->algorithm, env->algorithm_ref);
	sc_log(ctx,
	       "se_num %i, operation 0x%X, algorithm 0x%X, algorithm_ref 0x%X, flags 0x%X; key size %"SC_FORMAT_LEN_SIZE_T"u",
	       se_num, operation, env->algorithm, env->algorithm_ref,
	       env->algorithm_flags, prv->key_size);
	switch (operation)  {
	case SC_SEC_OPERATION_SIGN:
		if (!(env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PKCS1) && !is_ecc)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_PKCS1 specified");

		if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)   {

			if (is_ecc)
			{
				unsigned int mechanism_to_use = CKM_ECDSA_SHA256;
				if (key_compulsory_alg)
				{
					if (key_compulsory_alg < 0x44) /* 0x44 = ECDSA_SHA256*/
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "key doesn't support ECDSA_SHA256");
					mechanism_to_use = iasecc_mechanism_from_algorithm_reference(key_compulsory_alg);
				}
				else
				{
					/* check if ECDSA-SHA256 supported by key, otherwise use SHA512 */					
					int ii;
					for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
					{
						if (!env->key_mechanisms[ii])
							break;
						if (env->key_mechanisms[ii] == CKM_ECDSA_SHA256)
						{
							mechanism_to_use = CKM_ECDSA_SHA256;
							break;
						}
						if ((env->key_mechanisms[ii] > mechanism_to_use) && (env->key_mechanisms[ii] <= CKM_ECDSA_SHA512))
							mechanism_to_use = env->key_mechanisms[ii];
					}
				}

				if (mechanism_to_use == CKM_ECDSA_SHA256)
					cse_crt_ht[2] = iasecc_hash_ref_from_mechanism(mechanism_to_use);
				else
					external_sign_hash = 1;

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, mechanism_to_use);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:ECDSA_SHA224");
				((struct sc_security_env *)env)->mechanism_in_use = mechanism_to_use;
			}
			else
			{
				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH, CKM_SHA256);
				if (!algo_ref)
				{
					if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
						algo_ref = 0x40;
					else
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports HASH:SHA256");
				}

				cse_crt_ht[2] = algo_ref; /* IASECC_ALGORITHM_SHA2 */

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA256_RSA_PKCS);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");
				((struct sc_security_env *)env)->mechanism_in_use = CKM_SHA256_RSA_PKCS;
			}

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA2 */
		}
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224)   {
			
			if (is_ecc)
			{
				unsigned int mechanism_to_use = CKM_ECDSA_SHA224;
				if (key_compulsory_alg)
				{
					if (key_compulsory_alg < 0x34) /* 0x44 = ECDSA_SHA224*/
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "key doesn't support ECDSA_SHA224");
					mechanism_to_use = iasecc_mechanism_from_algorithm_reference(key_compulsory_alg);
				}
				else
				{
					/* check if ECDSA-SHA224 supported by key, otherwise use SHA512 */
					int ii;
					for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
					{
						if (!env->key_mechanisms[ii])
							break;
						if (env->key_mechanisms[ii] == CKM_ECDSA_SHA224)
						{
							mechanism_to_use = CKM_ECDSA_SHA224;
							break;
						}
						if ((env->key_mechanisms[ii] > mechanism_to_use) && (env->key_mechanisms[ii] <= CKM_ECDSA_SHA512))
							mechanism_to_use = env->key_mechanisms[ii];
					}
				}

				if (mechanism_to_use == CKM_ECDSA_SHA224)
					cse_crt_ht[2] = iasecc_hash_ref_from_mechanism(mechanism_to_use);
				else
					external_sign_hash = 1;

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, mechanism_to_use);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:ECDSA_SHA224");
				((struct sc_security_env *)env)->mechanism_in_use = mechanism_to_use;
			}
			else
			{
				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH, CKM_SHA224);
				if (!algo_ref)
				{
					if (card->type != SC_CARD_TYPE_IASECC_LATVIA)
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports HASH:SHA1");
					else
						algo_ref = 0x30;
				}

				cse_crt_ht[2] = algo_ref;	/* IASECC_ALGORITHM_SHA1 */

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA224_RSA_PKCS);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");
				((struct sc_security_env *)env)->mechanism_in_use = CKM_SHA224_RSA_PKCS;
			}

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1 */
		}
		else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)   {
			if (is_ecc)
			{
				unsigned int mechanism_to_use = CKM_ECDSA_SHA1;
				if (key_compulsory_alg)
				{
					if (key_compulsory_alg < 0x14) /* 0x44 = ECDSA_SHA1*/
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "key doesn't support ECDSA_SHA1");
					mechanism_to_use = iasecc_mechanism_from_algorithm_reference(key_compulsory_alg);
				}
				else
				{
					/* check if ECDSA-SHA224 supported by key, otherwise use SHA512 */
					int ii;
					for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
					{
						if (!env->key_mechanisms[ii])
							break;
						if (env->key_mechanisms[ii] == CKM_ECDSA_SHA1)
						{
							mechanism_to_use = CKM_ECDSA_SHA1;
							break;
						}
						if ((env->key_mechanisms[ii] > mechanism_to_use) && (env->key_mechanisms[ii] <= CKM_ECDSA_SHA512))
							mechanism_to_use = env->key_mechanisms[ii];
					}
				}

				if (mechanism_to_use == CKM_ECDSA_SHA1)
					cse_crt_ht[2] = iasecc_hash_ref_from_mechanism(mechanism_to_use);
				else
					external_sign_hash = 1;

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, mechanism_to_use);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:ECDSA_SHA1");
				((struct sc_security_env *)env)->mechanism_in_use = mechanism_to_use;
			}
			else
			{
				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_HASH, CKM_SHA_1);
				if (!algo_ref)
				{
					if (card->type != SC_CARD_TYPE_IASECC_LATVIA)
						LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports HASH:SHA1");
					else
						algo_ref = 0x10;
				}
				cse_crt_ht[2] = algo_ref;	/* IASECC_ALGORITHM_SHA1 */

				algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE,  CKM_SHA1_RSA_PKCS);
				if (!algo_ref)
					LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:SHA1_RSA_PKCS");
				((struct sc_security_env *)env)->mechanism_in_use = CKM_SHA1_RSA_PKCS;
			}

			cse_crt_dst[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
			cse_crt_dst[5] = algo_ref;   /* IASECC_ALGORITHM_RSA_PKCS | IASECC_ALGORITHM_SHA1 */
		}
		else if (is_ecc && card->type == SC_CARD_TYPE_IASECC_LATVIA)   {
			/* RAW ECDSA requested */
			unsigned int mechanism_to_use = 0;
			if (key_compulsory_alg)
			{
				mechanism_to_use = iasecc_mechanism_from_algorithm_reference(key_compulsory_alg);
			}
			else
			{
				for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
				{
					if (!env->key_mechanisms[ii])
						break;
					if ((env->key_mechanisms[ii] > mechanism_to_use) && (env->key_mechanisms[ii] <= CKM_ECDSA_SHA512))
						mechanism_to_use = env->key_mechanisms[ii];
				}
			}

			if (((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384) && (mechanism_to_use < CKM_ECDSA_SHA384))
				|| ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) && (mechanism_to_use < CKM_ECDSA_SHA512))
				)
			{
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "key doesn't support the selected hash with ECDSA");
			}

			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, mechanism_to_use);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:ECDSA");
			((struct sc_security_env *)env)->mechanism_in_use = mechanism_to_use;

			cse_crt_dst[2] = env->key_ref[0];
			cse_crt_dst[5] = algo_ref;

			external_sign_hash = 1;
		}
		else if (!is_ecc && (card->type == SC_CARD_TYPE_IASECC_LATVIA))   {
			/* RSA PKCS requested. We support only SHA256 anyway*/
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_SHA256_RSA_PKCS);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "No supported key mechanism found to perform RSA PKCS signature");
			cse_crt_dst[2] = env->key_ref[0];
			cse_crt_dst[5] = algo_ref;

			((struct sc_security_env *)env)->mechanism_in_use = CKM_SHA256_RSA_PKCS;

			external_sign_hash = 1;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_HASH_SHA[1,256] specified");
		}

		if (!external_sign_hash)
		{
			sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_HT);
			apdu.data = cse_crt_ht;
			apdu.datalen = sizeof(cse_crt_ht);
			apdu.lc = sizeof(cse_crt_ht);

			rv = sc_transmit_apdu(card, &apdu);
			LOG_TEST_RET(ctx, rv, "APDU transmit failed");
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
			LOG_TEST_RET(ctx, rv, "MSE restore error");
		}

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_DST);
		apdu.data = cse_crt_dst;
		apdu.datalen = sizeof(cse_crt_dst);
		apdu.lc = sizeof(cse_crt_dst);
		break;
	case SC_SEC_OPERATION_AUTHENTICATE:
		if (is_ecc && (card->type == SC_CARD_TYPE_IASECC_LATVIA))
		{
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_ECDSA);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Card application do not supports SIGNATURE:ECDSA");
		}
		else
		{
			algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_COMPUTE_SIGNATURE, CKM_RSA_PKCS);
			if (!algo_ref)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Application do not supports SIGNATURE:RSA_PKCS");
		}

		cse_crt_at[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_at[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_AT);
		apdu.data = cse_crt_at;
		apdu.datalen = sizeof(cse_crt_at);
		apdu.lc = sizeof(cse_crt_at);
		break;
	case SC_SEC_OPERATION_DECIPHER:
		if (is_ecc)
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

		rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_DECRYPT, &prv->op_method, &prv->op_ref);
		LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_PSO_DECRYPT acl");

		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_DECIPHER,  CKM_RSA_PKCS);
		if (!algo_ref)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Application do not supports DECIPHER:RSA_PKCS");

		cse_crt_ct[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_ct[5] = algo_ref;	/* IASECC_ALGORITHM_RSA_PKCS_DECRYPT | IASECC_ALGORITHM_SHA1 */

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_CT);
		apdu.data = cse_crt_ct;
		apdu.datalen = sizeof(cse_crt_ct);
		apdu.lc = sizeof(cse_crt_ct);
		break;
	case SC_SEC_OPERATION_DERIVE:
		if (!is_ecc)
			LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

		rv = iasecc_sdo_convert_acl(card, &sdo, SC_AC_OP_PSO_DECRYPT, &prv->op_method, &prv->op_ref);
		LOG_TEST_RET(ctx, rv, "Cannot convert SC_AC_OP_PSO_DECRYPT acl");

		algo_ref = iasecc_get_algorithm(ctx, env, SC_PKCS15_ALGO_OP_DERIVE, CKM_ECDH1_DERIVE);
		if (!algo_ref)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Application do not supports DERIVE:ECDH");

		cse_crt_ct[2] = env->key_ref[0] | IASECC_OBJECT_REF_LOCAL;
		cse_crt_ct[5] = algo_ref;

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0x41, IASECC_CRT_TAG_CT);
		apdu.data = cse_crt_ct;
		apdu.datalen = sizeof(cse_crt_ct);
		apdu.lc = sizeof(cse_crt_ct);
		break;
	default:
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	if (card->type == SC_CARD_TYPE_IASECC_LATVIA && apdu.sw1 == 0x6A && apdu.sw2 == 0x80)
	{
		rv = SC_ERROR_NOT_SUPPORTED;
	}
	else
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_TEST_RET(ctx, rv, "MSE restore error");

	prv->security_env = *env;
	prv->security_env.operation = operation;

	LOG_FUNC_RETURN(ctx, 0);
}


static int
iasecc_chv_verify_pinpad(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned char buffer[0x100];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "CHV PINPAD PIN reference %i", pin_cmd->pin_reference);

	if (!card->reader || !card->reader->ops || !card->reader->ops->perform_verify)   {
		sc_log(ctx, "Reader not ready for PIN PAD");
		LOG_FUNC_RETURN(ctx, SC_ERROR_READER);
	}

	if ((card->flags & SC_CARD_FLAG_CONTACTLESS)
		&& !(card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)
		)
	{
		sc_log(ctx, "Can not use pin PAD in contacless mode without hardware PACE");
		LOG_FUNC_RETURN(ctx, SC_ERROR_READER);
	}

	if (!(pin_cmd->flags & SC_PIN_CMD_NEED_PADDING) && (pin_cmd->pin1.min_length != pin_cmd->pin1.max_length))   {
		sc_log(ctx, "Different values for PIN min and max lengths is not actually compatible with PinPAD.");
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, 
				"Different values for PIN min and max lengths is not actually compatible with PinPAD.");
	}

    if (pin_cmd->flags & SC_PIN_CMD_NEED_PADDING)
    {
        pin_cmd->pin1.len = pin_cmd->pin1.pad_length;
        memset(buffer, pin_cmd->pin1.pad_char, sizeof(buffer));
    }
    else
    {
		/* When PIN stored length available
		 *     P10 verify data contains full template of 'VERIFY PIN' APDU.
		 * Without PIN stored length
		 *     pin-pad has to set the Lc and fill PIN data itself.
		 *     Not all pin-pads support this case
		 */
		pin_cmd->pin1.len = pin_cmd->pin1.stored_length;
	    memset(buffer, 0xFF, sizeof(buffer));
    }

	pin_cmd->pin1.data = buffer;
	pin_cmd->pin1.length_offset = 5;

	pin_cmd->cmd = SC_PIN_CMD_VERIFY;
	pin_cmd->flags |= SC_PIN_CMD_USE_PINPAD;

	/*
	if (card->reader && card->reader->ops && card->reader->ops->load_message) {
		rv = card->reader->ops->load_message(card->reader, card->slot, 0, "Here we are!");
		sc_log(ctx, "Load message returned %i", rv);
	}
	*/

	rv = iso_ops->pin_cmd(card, pin_cmd, tries_left);
	sc_log(ctx, "rv %i", rv);

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
	{
		if ((card->flags & SC_CARD_FLAG_CONTACTLESS)
			&& (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)
			&& (rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)
			)
		{
			struct sc_path path;
			/* try to select MF */
			sc_format_path("3F00", &path);
			path.type = SC_PATH_TYPE_FILE_ID;
			int local_rv = iasecc_select_file(card, &path, NULL);
			if (local_rv >= 0)
			{
				int pace_status = do_pace(card, NULL);
				if (pace_status < 0)
					sc_log(ctx, "PACE authentication failed");
				else
				{
					rv = iso_ops->pin_cmd(card, pin_cmd, tries_left);
					sc_log(ctx, "rv %i", rv);


					if ((pin_cmd->pin_reference & IASECC_OBJECT_REF_LOCAL)
						&& (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)
						)
					{
						/* Select ADF again in case it got de-selected by another application */
						local_rv = iasecc_latvia_select_ADF_QSCD(card);
						if (local_rv >= 0)
						{
							rv = iso_ops->pin_cmd(card, pin_cmd, tries_left);
							sc_log(ctx, "rv %i", rv);
						}
					}
				}
			}
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_chv_verify(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_acl_entry acl = pin_cmd->pin1.acls[IASECC_ACLS_CHV_VERIFY];
	struct sc_apdu apdu;
	int rv;
    unsigned char pin_buff[SC_MAX_APDU_BUFFER_SIZE] = {0};

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify CHV PIN(ref:%i,len:%i,acl:%X:%X)", pin_cmd->pin_reference, pin_cmd->pin1.len,
			acl.method, acl.key_ref);

	if (acl.method & IASECC_SCB_METHOD_SM)   {
		rv = iasecc_sm_pin_verify(card, acl.key_ref, pin_cmd, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}

	if (pin_cmd->pin1.data && !pin_cmd->pin1.len)   {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0, pin_cmd->pin_reference);
	}
	else if (pin_cmd->pin1.data && pin_cmd->pin1.len)   {        
		size_t pin_len = pin_cmd->pin1.len;

		memcpy(pin_buff, pin_cmd->pin1.data, pin_cmd->pin1.len);

		if (pin_cmd->pin1.pad_length && pin_cmd->flags & SC_PIN_CMD_NEED_PADDING)   {
			memset(pin_buff + pin_cmd->pin1.len, pin_cmd->pin1.pad_char, pin_cmd->pin1.pad_length - pin_cmd->pin1.len);
			pin_len = pin_cmd->pin1.pad_length;
		}

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x20, 0, pin_cmd->pin_reference);
		apdu.data = pin_buff;
		apdu.datalen = pin_len;
		apdu.lc = pin_len;
	}
	else if ((card->reader->capabilities & SC_READER_CAP_PIN_PAD) && !pin_cmd->pin1.data && !pin_cmd->pin1.len)   {
		rv = iasecc_chv_verify_pinpad(card, pin_cmd, tries_left);
		sc_log(ctx, "Result of verifying CHV with PIN pad %i", rv);
		LOG_FUNC_RETURN(ctx, rv);
	}
	else   {
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}

	rv = sc_transmit_apdu(card, &apdu);

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
	{
		if ((rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) || (apdu.sw1 == 0x69 && apdu.sw2 == 0x82))
		{
			struct sc_path path;
			/* try to select MF */
			sc_format_path("3F00", &path);
			path.type = SC_PATH_TYPE_FILE_ID;
			int local_rv = iasecc_select_file(card, &path, NULL);
			if (local_rv >= 0)
			{
				int pace_status = 0;
				if ((card->flags & SC_CARD_FLAG_CONTACTLESS)
					&& (card->reader->capabilities & SC_READER_CAP_PACE_GENERIC)
					)
				{
					pace_status = do_pace(card, NULL);
				}
				if (pace_status < 0)
					sc_log(ctx, "PACE authentication failed");
				else
				{
					rv = sc_transmit_apdu(card, &apdu);
					sc_log(ctx, "rv %i", rv);


					if ((pin_cmd->pin_reference & IASECC_OBJECT_REF_LOCAL)
						&& (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)
						)
					{
						/* Select ADF again in case it got de-selected by another application */
						local_rv = iasecc_latvia_select_ADF_QSCD(card);
						if (local_rv >= 0)
						{
							rv = sc_transmit_apdu(card, &apdu);
							sc_log(ctx, "rv %i", rv);
						}
					}
				}
			}
		}

		if ((rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) || (apdu.sw1 == 0x69 && apdu.sw2 == 0x82))
		{
			sc_log(ctx, "Restoring context and trying again");
			// still have the issue: restore context and try again
			if (SC_SUCCESS == iasecc_restore_context(card))
			{
				rv = sc_transmit_apdu(card, &apdu);
				sc_log(ctx, "rv %i", rv);

				if ((pin_cmd->pin_reference & IASECC_OBJECT_REF_LOCAL)
					&& (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)
					)
				{
					/* Select ADF again in case it got de-selected by another application */
					int local_rv = iasecc_latvia_select_ADF_QSCD(card);
					if (local_rv >= 0)
					{
						rv = sc_transmit_apdu(card, &apdu);
						sc_log(ctx, "rv %i", rv);
					}
				}
			}
		}
	}

	LOG_TEST_RET(ctx, rv, "APDU transmit failed");

	if (tries_left && apdu.sw1 == 0x63 && (apdu.sw2 & 0xF0) == 0xC0)
		*tries_left = apdu.sw2 & 0x0F;

	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_se_at_to_chv_reference(struct sc_card *card, unsigned reference,
		unsigned *chv_reference)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info se;
	struct sc_crt crt;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "SE reference %i", reference);

	if (reference > IASECC_SE_REF_MAX) 
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	memset(&se, 0, sizeof(se));
	se.reference = reference;

	rv = iasecc_se_get_info(card, &se);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	memset(&crt, 0, sizeof(crt));
	crt.tag = IASECC_CRT_TAG_AT;
	crt.usage = IASECC_UQB_AT_USER_PASSWORD;

	rv = iasecc_se_get_crt(card, &se, &crt);
	LOG_TEST_RET(ctx, rv, "no authentication template for USER PASSWORD");

	if (chv_reference)
		*chv_reference = crt.refs[0];

	sc_file_free(se.df);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_is_verified(struct sc_card *card, struct sc_pin_cmd_data *pin_cmd_data,
		int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
        struct sc_acl_entry acl = pin_cmd_data->pin1.acls[IASECC_ACLS_CHV_VERIFY];
	int rv = SC_ERROR_SECURITY_STATUS_NOT_SATISFIED;

	LOG_FUNC_CALLED(ctx);

	if (pin_cmd_data->pin_type != SC_AC_CHV) 
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "PIN type is not supported for the verification");

	sc_log(ctx, "Verify ACL(method:%X;ref:%X)", acl.method, acl.key_ref);
	if (acl.method != IASECC_SCB_ALWAYS)
		LOG_FUNC_RETURN(ctx, SC_ERROR_SECURITY_STATUS_NOT_SATISFIED);

	pin_cmd = *pin_cmd_data;
	pin_cmd.pin1.data = (unsigned char *)"";
	pin_cmd.pin1.len = 0;
		
	rv = iasecc_chv_verify(card, &pin_cmd, tries_left);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_verify(struct sc_card *card, unsigned type, unsigned reference,
		const unsigned char *data, size_t data_len, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	unsigned chv_ref = reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Verify PIN(type:%X,ref:%i,data(len:%i,%p)", type, reference, data_len, data);

	if (type == SC_AC_AUT)   {
		rv =  iasecc_sm_external_authentication(card, reference, tries_left);
		LOG_FUNC_RETURN(ctx, rv);
	}
	else if (type == SC_AC_SCB)   {
		if (reference & IASECC_SCB_METHOD_USER_AUTH)   {
			type = SC_AC_SEN;
			reference = reference & IASECC_SCB_METHOD_MASK_REF;
		}
		else   {
			sc_log(ctx, "Do not try to verify non CHV PINs");
			LOG_FUNC_RETURN(ctx, SC_SUCCESS);
		}
	}

	if (type == SC_AC_SEN)   {
		rv = iasecc_se_at_to_chv_reference(card, reference,  &chv_ref);
		LOG_TEST_RET(ctx, rv, "SE AT to CHV reference error");
	}
		
	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = chv_ref;
	pin_cmd.cmd = SC_PIN_CMD_VERIFY;

	rv = iasecc_pin_get_policy(card, &pin_cmd);
	LOG_TEST_RET(ctx, rv, "Get 'PIN policy' error");

	if (SC_PIN_STATE_NOT_INITIALIZED == pin_cmd.pin1.logged_in)
	{
		LOG_TEST_RET(ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND, "PIN is not initialized");
	}

	pin_cmd.pin1.data = data;
	pin_cmd.pin1.len = data_len;

	rv = iasecc_pin_is_verified(card, &pin_cmd, tries_left);
	if (data && !data_len)
		LOG_FUNC_RETURN(ctx, rv);

	if (rv && rv != SC_ERROR_PIN_CODE_INCORRECT && rv != SC_ERROR_SECURITY_STATUS_NOT_SATISFIED)   {
		LOG_FUNC_RETURN(ctx, rv);
	}

	rv = iasecc_chv_verify(card, &pin_cmd, tries_left);
	LOG_TEST_RET(ctx, rv, "PIN CHV verification error");

	LOG_FUNC_RETURN(ctx, rv);
}

static int
iasecc_pin_logout(struct sc_card *card, unsigned type, unsigned reference, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	unsigned chv_ref = reference;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Logout PIN(type:%X,ref:%i", type, reference);

	if (card->type != SC_CARD_TYPE_IASECC_LATVIA || type != SC_AC_CHV)
		rv = SC_ERROR_NOT_SUPPORTED;
	else
	{		
		struct sc_file *save_current_df = NULL, *save_current_ef = NULL;
		struct sc_apdu apdu;

		if (card->cache.valid && card->cache.current_df) {
			sc_file_dup(&save_current_df, card->cache.current_df);
			if (save_current_df == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");
		}

		if (card->cache.valid && card->cache.current_ef) {
			sc_file_dup(&save_current_ef, card->cache.current_ef);
			if (save_current_ef == NULL)
				LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current EF file");
		}

		if (reference & IASECC_OBJECT_REF_LOCAL)
		{
			rv = iasecc_latvia_select_ADF_QSCD(card);
		}
		else
		{
			rv = iasecc_select_mf(card, NULL);
			sc_log(ctx, "Select MF: rv %i", rv);
		}

		/* de-verify PINauth manually */
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x20, 0xFF, (unsigned char) reference);
		rv = sc_transmit_apdu(card, &apdu);
		if (rv >= 0)
			rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		if (rv < 0)
			sc_log(ctx, "failed to de-verify PINauth. r = %i", rv);

		if (tries_left)
		{
			struct sc_pin_cmd_data pin_cmd;

			memset(&pin_cmd, 0, sizeof(pin_cmd));
			pin_cmd.pin_type = SC_AC_CHV;
			pin_cmd.pin_reference = reference;
			pin_cmd.cmd = SC_PIN_CMD_VERIFY;

			iasecc_pin_is_verified(card, &pin_cmd, tries_left);
		}

		if (save_current_df) {
			int localRv;

			sc_log(ctx, "iasecc_logout() restore current DF");
			localRv = iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
			if (localRv < 0)
			{
				sc_log(ctx, "Cannot return to saved DF: rv %i", localRv);
				sc_file_free(card->cache.current_df);
				card->cache.current_df = NULL;
			}

			sc_file_free(save_current_df);
		}

		if (save_current_ef) {
			int localRv;

			sc_log(ctx, "iasecc_pin_logout() restore current EF");
			localRv = iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
			if (localRv < 0)
			{
				sc_log(ctx, "Cannot return to saved EF: rv %i", localRv);
				sc_file_free(card->cache.current_ef);
				card->cache.current_ef = NULL;
			}

			sc_file_free(save_current_ef);
		}
	}

	LOG_FUNC_RETURN(ctx, rv);
}



static int
iasecc_chv_change_pinpad(struct sc_card *card, unsigned reference, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	unsigned char pin1_data[0x100], pin2_data[0x100];
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "CHV PINPAD PIN reference %i", reference);

	memset(pin1_data, 0xFF, sizeof(pin1_data));
	memset(pin2_data, 0xFF, sizeof(pin2_data));

	if (!card->reader || !card->reader->ops || !card->reader->ops->perform_verify)   {
		sc_log(ctx, "Reader not ready for PIN PAD");
		LOG_FUNC_RETURN(ctx, SC_ERROR_READER);
	}

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = reference;
	pin_cmd.cmd = SC_PIN_CMD_CHANGE;
	pin_cmd.flags |= SC_PIN_CMD_USE_PINPAD;

	rv = iasecc_pin_get_policy(card, &pin_cmd);
	LOG_TEST_RET(ctx, rv, "Get 'PIN policy' error");

	if (SC_PIN_STATE_NOT_INITIALIZED == pin_cmd.pin1.logged_in)
	{
		LOG_TEST_RET(ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND, "PIN is not initialized");
	}

    if (pin_cmd.flags & SC_PIN_CMD_NEED_PADDING)
    {
        pin_cmd.pin1.len = pin_cmd.pin1.pad_length;
        memset(pin1_data, pin_cmd.pin1.pad_char, sizeof(pin1_data));
    }
	/* Some pin-pads do not support mode with Lc=0.
	 * Give them a chance to work with some cards.
	 */
	else if ((pin_cmd.pin1.min_length == pin_cmd.pin1.stored_length) && (pin_cmd.pin1.max_length == pin_cmd.pin1.min_length))
		pin_cmd.pin1.len = pin_cmd.pin1.stored_length;
	else
		pin_cmd.pin1.len = 0;

	pin_cmd.pin1.length_offset = 5;
	pin_cmd.pin1.data = pin1_data;

	memcpy(&pin_cmd.pin2, &pin_cmd.pin1, sizeof(pin_cmd.pin1));
    if (pin_cmd.flags & SC_PIN_CMD_NEED_PADDING)
    {
        memset(pin2_data, pin_cmd.pin2.pad_char, sizeof(pin2_data));
    }
	pin_cmd.pin2.data = pin2_data;

	sc_log(ctx,
	       "PIN1 max/min/stored: %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u",
	       pin_cmd.pin1.max_length, pin_cmd.pin1.min_length,
	       pin_cmd.pin1.stored_length);
	sc_log(ctx,
	       "PIN2 max/min/stored: %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u",
	       pin_cmd.pin2.max_length, pin_cmd.pin2.min_length,
	       pin_cmd.pin2.stored_length);
	rv = iso_ops->pin_cmd(card, &pin_cmd, tries_left);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_chv_set_pinpad(struct sc_card *card, unsigned char reference)
{
    sc_apdu_t local_apdu, *apdu = NULL;
	struct sc_context *ctx = card->ctx;
	struct sc_pin_cmd_data pin_cmd;
	unsigned char pin_data[0x100];
    u8  sbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv, len = 0, pad = 0;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Set CHV PINPAD PIN reference %i", reference);

	memset(pin_data, 0xFF, sizeof(pin_data));

	if (!card->reader || !card->reader->ops || !card->reader->ops->perform_verify)   {
		sc_log(ctx, "Reader not ready for PIN PAD");
		LOG_FUNC_RETURN(ctx, SC_ERROR_READER);
	}

	memset(&pin_cmd, 0, sizeof(pin_cmd));
	pin_cmd.pin_type = SC_AC_CHV;
	pin_cmd.pin_reference = reference;
	pin_cmd.cmd = SC_PIN_CMD_UNBLOCK;
	pin_cmd.flags |= SC_PIN_CMD_USE_PINPAD | SC_PIN_CMD_IMPLICIT_CHANGE;

	rv = iasecc_pin_get_policy(card, &pin_cmd);
	LOG_TEST_RET(ctx, rv, "Get 'PIN policy' error");

	if ((card->type != SC_CARD_TYPE_IASECC_LATVIA) && !(pin_cmd.flags & SC_PIN_CMD_NEED_PADDING) && (pin_cmd.pin1.min_length != pin_cmd.pin1.max_length))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Different values for PIN min and max lengths is not allowed with PinPAD.");

	if (pin_cmd.pin1.min_length < 4)
		pin_cmd.pin1.min_length = 4;
    if (pin_cmd.flags & SC_PIN_CMD_NEED_PADDING)
    {
        pin_cmd.pin1.len = pin_cmd.pin1.pad_length;
        memset(pin_data, pin_cmd.pin1.pad_char, sizeof(pin_data));
        pad = 1;
    }
    else
    {
	    pin_cmd.pin1.len = pin_cmd.pin1.min_length;
    }

	pin_cmd.pin1.data = pin_data;

	memcpy(&pin_cmd.pin2, &pin_cmd.pin1, sizeof(pin_cmd.pin1));

	sc_log(ctx, "PIN1(max:%i,min:%i)", pin_cmd.pin1.max_length, pin_cmd.pin1.min_length);

    if ((len = sc_build_pin(sbuf, sizeof(sbuf), &pin_cmd.pin1, pad)) < 0)
	    return len;

    apdu = &local_apdu;
	sc_format_apdu(card, apdu, SC_APDU_CASE_3_SHORT,
				0x2C, 0x02, reference);
	apdu->lc = len;
	apdu->datalen = len;
	apdu->data = sbuf;
	apdu->resplen = 0;

    pin_cmd.apdu = apdu;

	if (card->reader
		&& card->reader->ops
		&& card->reader->ops->perform_verify) {
		rv = card->reader->ops->perform_verify(card->reader, &pin_cmd);
		/* sw1/sw2 filled in by reader driver */
		if (rv >= 0)
			rv = sc_check_sw(card, apdu->sw1, apdu->sw2);
	} else {
		sc_debug(card->ctx, SC_LOG_DEBUG_NORMAL,
			"Card reader driver does not support "
			"PIN entry through reader key pad");
		rv = SC_ERROR_NOT_SUPPORTED;
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_get_policy (struct sc_card *card, struct sc_pin_cmd_data *data)   
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *save_current_df = NULL, *save_current_ef = NULL;
	struct iasecc_sdo sdo;
	struct sc_path path;
	unsigned ii;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_get_policy(card:%p)", card);
  
	if (data->pin_type != SC_AC_CHV)   {
		sc_log(ctx, "To unblock PIN it's CHV reference should be presented");
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	}

	if (card->cache.valid && card->cache.current_df)   {
		sc_file_dup(&save_current_df, card->cache.current_df);
		if (save_current_df == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			sc_log(ctx, "Cannot duplicate current DF file");
			goto err;
		}
	}

	if (card->cache.valid && card->cache.current_ef)   {
		sc_file_dup(&save_current_ef, card->cache.current_ef);
		if (save_current_ef == NULL) {
			rv = SC_ERROR_OUT_OF_MEMORY;
			sc_log(ctx, "Cannot duplicate current EF file");
			goto err;
		}
	}

	if (!(data->pin_reference & IASECC_OBJECT_REF_LOCAL) && card->cache.valid && card->cache.current_df) {
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rv = iasecc_select_file(card, &path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Unable to select MF");
	}

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_CHV;

	sdo.sdo_ref = data->pin_reference & ~IASECC_OBJECT_REF_LOCAL;

	sc_log(ctx, "iasecc_pin_get_policy() reference %i", sdo.sdo_ref);

	rv = iasecc_sdo_get_data(card, &sdo);
	if ((SC_ERROR_DATA_OBJECT_NOT_FOUND == rv)
		&& !(data->pin_reference & IASECC_OBJECT_REF_LOCAL)
		&& (!card->cache.valid || !card->cache.current_df)
		)
	{
		/* try to select MF */
		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rv = iasecc_select_file(card, &path, NULL);
		LOG_TEST_GOTO_ERR(ctx, rv, "Unable to select MF");

		rv = iasecc_sdo_get_data(card, &sdo);
	}
	LOG_TEST_GOTO_ERR(ctx, rv, "Cannot get SDO PIN data");

	if (sdo.docp.acls_contact.size == 0) {
		rv = SC_ERROR_INVALID_DATA;
		sc_log(ctx, "Extremely strange ... there is no ACLs");
		goto err;
	}

	sc_log(ctx,
	       "iasecc_pin_get_policy() sdo.docp.size.size %"SC_FORMAT_LEN_SIZE_T"u",
	       sdo.docp.size.size);
	for (ii=0; ii<sizeof(sdo.docp.scbs); ii++)   {
		struct iasecc_se_info se;
		unsigned char scb = sdo.docp.scbs[ii];
		struct sc_acl_entry *acl = &data->pin1.acls[ii];
		int crt_num = 0;

		memset(&se, 0, sizeof(se));
		memset(&acl->crts, 0, sizeof(acl->crts));

		sc_log(ctx, "iasecc_pin_get_policy() set info acls: SCB 0x%X", scb);
		/* acl->raw_value = scb; */
		acl->method = scb & IASECC_SCB_METHOD_MASK;
		acl->key_ref = scb & IASECC_SCB_METHOD_MASK_REF;

		if (scb==0 || scb==0xFF)
			continue;

		if (se.reference != (int)acl->key_ref)   {
			memset(&se, 0, sizeof(se));

			se.reference = acl->key_ref;

			rv = iasecc_se_get_info(card, &se);
			LOG_TEST_GOTO_ERR(ctx, rv, "SDO get data error");
		}

		if (scb & IASECC_SCB_METHOD_USER_AUTH)   {
			rv = iasecc_se_get_crt_by_usage(card, &se,
					IASECC_CRT_TAG_AT, IASECC_UQB_AT_USER_PASSWORD, &acl->crts[crt_num]);
			LOG_TEST_GOTO_ERR(ctx, rv, "no authentication template for 'USER PASSWORD'");
			sc_log(ctx, "iasecc_pin_get_policy() scb:0x%X; sdo_ref:[%i,%i,...]",
					scb, acl->crts[crt_num].refs[0], acl->crts[crt_num].refs[1]);
			crt_num++;
		}

		if (scb & (IASECC_SCB_METHOD_SM | IASECC_SCB_METHOD_EXT_AUTH))   {
			sc_log(ctx, "'SM' and 'EXTERNAL AUTHENTICATION' protection methods are not supported: SCB:0x%X", scb);
			/* Set to 'NEVER' if all conditions are needed or
			 * there is no user authentication method allowed */
			if (!crt_num || (scb & IASECC_SCB_METHOD_NEED_ALL))
				acl->method = SC_AC_NEVER;
			continue;
		}

			sc_file_free(se.df);
	}

	if (sdo.data.chv.size_max.value)
		data->pin1.max_length = *sdo.data.chv.size_max.value;
	if (sdo.data.chv.size_min.value)
		data->pin1.min_length = *sdo.data.chv.size_min.value;
	if (sdo.docp.tries_maximum.value)
		data->pin1.max_tries = *sdo.docp.tries_maximum.value;
	if (sdo.docp.tries_remaining.value)
		data->pin1.tries_left = *sdo.docp.tries_remaining.value;
	if (sdo.docp.size.value)   {
		for (ii=0; ii<sdo.docp.size.size; ii++)
			data->pin1.stored_length = ((data->pin1.stored_length) << 8) + *(sdo.docp.size.value + ii);
	}

	data->pin1.encoding = SC_PIN_ENCODING_ASCII;
	data->pin1.offset = 5;
	data->pin1.logged_in = SC_PIN_STATE_UNKNOWN;

	if (card->type == SC_CARD_TYPE_IASECC_OBERTHUR || card->type == SC_CARD_TYPE_IASECC_LATVIA)    {
		data->pin1.pad_char = 0xFF;
		data->pin1.pad_length = data->pin1.max_length;
		data->pin2.pad_char = 0xFF;
		data->pin2.pad_length = data->pin2.max_length;

		data->flags |= SC_PIN_CMD_NEED_PADDING;
	}

	iasecc_sdo_free_fields(card, &sdo);

	sc_log(ctx,
	       "PIN policy: size max/min %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u, tries max/left %i/%i",
				data->pin1.max_length, data->pin1.min_length, 
				data->pin1.max_tries, data->pin1.tries_left);

	if (save_current_df)   {
		int localRv;
		sc_log(ctx, "iasecc_pin_get_policy() restore current DF");
		localRv = iasecc_select_file_pace(card, &save_current_df->path, NULL, 1);
		if (localRv < 0)
		{
			sc_log(ctx, "Cannot return to saved DF: rv %i", localRv);
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;
		}		

	}

	if (save_current_ef)   {
		int localRv;
		sc_log(ctx, "iasecc_pin_get_policy() restore current EF");
		localRv = iasecc_select_file_pace(card, &save_current_ef->path, NULL, 1);
		if (localRv < 0)
		{
			sc_log(ctx, "Cannot return to saved DF: rv %i", localRv);
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;
		}		
	}

err:
	sc_file_free(save_current_df);
	sc_file_free(save_current_ef);

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_keyset_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo_update update;
	struct iasecc_sdo sdo;
	unsigned scb;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change keyset(ref:%i,lengths:%i)", data->pin_reference, data->pin2.len);
	if (!data->pin2.data || data->pin2.len < 32)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Needs at least 32 bytes for a new keyset value");

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_KEYSET;
	sdo.sdo_ref  = data->pin_reference;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_RET(ctx, rv, "Cannot get keyset data");

	if (sdo.docp.acls_contact.size == 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Bewildered ... there are no ACLs");
	scb = sdo.docp.scbs[IASECC_ACLS_KEYSET_PUT_DATA];
	iasecc_sdo_free_fields(card, &sdo);

	sc_log(ctx, "SCB:0x%X", scb);
	if (!(scb & IASECC_SCB_METHOD_SM))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Other then protected by SM, the keyset change is not supported");

	memset(&update, 0, sizeof(update));
	update.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update.sdo_class = sdo.sdo_class;
	update.sdo_ref = sdo.sdo_ref;

	update.fields[0].parent_tag = IASECC_SDO_KEYSET_TAG;
	update.fields[0].tag = IASECC_SDO_KEYSET_TAG_MAC;
	/* FIXME is it safe to modify the const value here? */
	update.fields[0].value = (unsigned char *) data->pin2.data;
	update.fields[0].size = 16;

	update.fields[1].parent_tag = IASECC_SDO_KEYSET_TAG;
	update.fields[1].tag = IASECC_SDO_KEYSET_TAG_ENC;
	/* FIXME is it safe to modify the const value here? */
	update.fields[1].value = (unsigned char *) data->pin2.data + 16;
	update.fields[1].size = 16;

	rv = iasecc_sm_sdo_update(card, (scb & IASECC_SCB_METHOD_MASK_REF), &update);
	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_change(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned reference = data->pin_reference;
	unsigned char pin_data[0x100];
	unsigned char datalen = 0;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Change PIN(ref:%i,type:0x%X,lengths:%i/%i)", reference, data->pin_type, data->pin1.len, data->pin2.len);

	if ((card->reader->capabilities & SC_READER_CAP_PIN_PAD))   {
		if (!data->pin1.data && !data->pin1.len && !data->pin2.data && !data->pin2.len)   {
			rv = iasecc_chv_change_pinpad(card, reference, tries_left);
			sc_log(ctx, "iasecc_pin_cmd(SC_PIN_CMD_CHANGE) chv_change_pinpad returned %i", rv);
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	if (!data->pin1.data && data->pin1.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN1 arguments");

	if (!data->pin2.data && data->pin2.len)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid PIN2 arguments");

	if ((data->pin2.data) && (card->type == SC_CARD_TYPE_IASECC_LATVIA))
	{
		/* only digits are accepted for PIN */
		int i;
		unsigned char c;
		for (i = 0; i < data->pin2.len; i++)
		{
			c = data->pin2.data[i];
			if (c < '0' || c > '9')
				LOG_TEST_RET(ctx, SC_ERROR_KEYPAD_PIN_MISMATCH, "Invalid PIN2 value: it must contain only digits.");
		}
	}

	rv = iasecc_pin_verify(card, data->pin_type, reference, data->pin1.data, data->pin1.len, tries_left);
	sc_log(ctx, "iasecc_pin_cmd(SC_PIN_CMD_CHANGE) pin_verify returned %i", rv);
	LOG_TEST_RET(ctx, rv, "PIN verification error");

	if ((unsigned)(data->pin1.len + data->pin2.len) > sizeof(pin_data))
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small for the 'Change PIN' data");

	if (data->pin1.data) {
		memcpy(pin_data, data->pin1.data, data->pin1.len);
		datalen += data->pin1.len;
		if (data->pin1.pad_length && data->flags & SC_PIN_CMD_NEED_PADDING) {
			memset(pin_data + data->pin1.len, data->pin1.pad_char, data->pin1.pad_length - data->pin1.len);
			datalen += data->pin1.pad_length - data->pin1.len;
		}
	}
	if (data->pin2.data) {
		datalen += data->pin2.len;
		if (data->pin1.pad_length && data->flags & SC_PIN_CMD_NEED_PADDING) {
			memcpy(pin_data + data->pin1.pad_length, data->pin2.data, data->pin2.len);
			memset(pin_data + data->pin1.pad_length + data->pin2.len, data->pin1.pad_char, data->pin1.pad_length - data->pin2.len);
			datalen += data->pin1.pad_length - data->pin2.len;
		}
		else
			memcpy(pin_data + data->pin1.len, data->pin2.data, data->pin2.len);
	}

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x24, 0, reference);
	apdu.data = pin_data;
	apdu.datalen = datalen;
	apdu.lc = apdu.datalen;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "PIN cmd failed");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_reset(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	struct sc_file *save_current = NULL;
	struct iasecc_sdo sdo;
	struct sc_apdu apdu;
	unsigned reference, scb;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "Reset PIN(ref:%i,lengths:%i/%i)", data->pin_reference, data->pin1.len, data->pin2.len);

	if (data->pin_type != SC_AC_CHV)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Unblock procedure can be used only with the PINs of type CHV");
  
	reference = data->pin_reference;

	if (!(data->pin_reference & IASECC_OBJECT_REF_LOCAL) && card->cache.valid && card->cache.current_df)  {
		struct sc_path path;

		sc_file_dup(&save_current, card->cache.current_df);
		if (save_current == NULL)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Cannot duplicate current DF file");

		sc_format_path("3F00", &path);
		path.type = SC_PATH_TYPE_FILE_ID;
		rv = iasecc_select_file(card, &path, NULL);
		if (rv != SC_SUCCESS) {
			sc_file_free(save_current);
			sc_log(ctx, "Unable to select MF");
			LOG_FUNC_RETURN(ctx, rv);
		}
	}

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = IASECC_SDO_CLASS_CHV;
	sdo.sdo_ref = reference & ~IASECC_OBJECT_REF_LOCAL;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_RET(ctx, rv, "Cannot get PIN data");

	if (sdo.docp.acls_contact.size == 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Extremely strange ... there are no ACLs");

	scb = sdo.docp.scbs[IASECC_ACLS_CHV_RESET];
	do   {
		unsigned need_all = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;
		unsigned char se_num = scb & IASECC_SCB_METHOD_MASK_REF;

		if (scb & IASECC_SCB_METHOD_USER_AUTH)   {
			if (data->pin1.data && data->pin1.len)
			{
				sc_log(ctx, "Try to verify PUK code: pin1.data:%p, pin1.len:%i", data->pin1.data, data->pin1.len);
				rv = iasecc_pin_verify(card, SC_AC_CHV, data->so_pin_reference, data->pin1.data, data->pin1.len, tries_left);
				sc_log(ctx, "Verify PUK code returned %i", rv);
				if (rv < 0)
				{
					sc_unlock(card);
					LOG_TEST_RET(ctx, rv, "iasecc_pin_reset() PIN verification error");
				}
			}
			else if (data->pin1.data || data->pin1.len)
			{
				sc_unlock(card);
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");
			}
			else
			{
				struct sc_pin_cmd_data pin_cmd;
				memset(&pin_cmd, 0, sizeof(pin_cmd));
				pin_cmd.pin_type = SC_AC_CHV;
				pin_cmd.pin_reference = data->so_pin_reference;
				pin_cmd.cmd = SC_PIN_CMD_VERIFY;

				rv = iasecc_pin_is_verified(card, &pin_cmd, tries_left);
				if (rv < 0)
				{
					sc_unlock(card);
					LOG_TEST_RET(ctx, rv, "iasecc_pin_reset() SO PIN is not verified on the card");
				}
			}

			if (!need_all)
				break;
		}

		if (scb & IASECC_SCB_METHOD_SM)   {
			rv = iasecc_sm_pin_reset(card, se_num, data);
			LOG_FUNC_RETURN(ctx, rv);
		}

		if (scb & IASECC_SCB_METHOD_EXT_AUTH)   {
			rv =  iasecc_sm_external_authentication(card, reference, tries_left);
			LOG_TEST_RET(ctx, rv, "iasecc_pin_reset() external authentication error");
		}
	} while(0);

	iasecc_sdo_free_fields(card, &sdo);

	if (data->pin2.len)   {
		unsigned char pin_buff[SC_MAX_APDU_BUFFER_SIZE];
		sc_log(ctx, "Reset PIN %X and set new value", reference);

		if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
		{
			/* only digits are accepted for PIN */
			int i;
			unsigned char c;
			for (i = 0; i < data->pin2.len; i++)
			{
				c = data->pin2.data[i];
				if (c < '0' || c > '9')
					LOG_TEST_RET(ctx, SC_ERROR_KEYPAD_PIN_MISMATCH, "Invalid PIN2 value: it must contain only digits.");
			}
		}
		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2C, 0x02, reference);
		memcpy(pin_buff, data->pin2.data, data->pin2.len);
		apdu.datalen = data->pin2.len;

		if (data->pin2.pad_length && data->flags & SC_PIN_CMD_NEED_PADDING)   {
			memset(pin_buff + data->pin2.len, data->pin2.pad_char, data->pin2.pad_length - data->pin2.len);
			apdu.datalen = data->pin2.pad_length;
		}
		apdu.data = pin_buff;
		apdu.lc = apdu.datalen;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
      if (rv < 0)
      {
		LOG_TEST_RET(ctx, rv, "PIN cmd failed");
      }
	}
	else if (data->pin2.data) {
		sc_log(ctx, "Reset PIN %X and set new value", reference);
		sc_format_apdu(card, &apdu, SC_APDU_CASE_1, 0x2C, 3, reference);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "PIN cmd failed");
	}
	else   {
		sc_log(ctx, "Reset PIN %X and set new value with PIN-PAD", reference);

		rv = iasecc_chv_set_pinpad(card, reference);
		sc_log(ctx, "Set CHV with PIN pad returned %i", rv);
	}

	if (save_current)   {

		int local_rv = iasecc_select_file_pace(card, &save_current->path, NULL, 1);
		if (local_rv < 0)
		{
			sc_log(ctx, "Cannot return to saved DF: rv %i", local_rv);
			sc_file_free(card->cache.current_df);
			card->cache.current_df = NULL;
		}		

		sc_file_free(save_current);
	}

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_pin_cmd(struct sc_card *card, struct sc_pin_cmd_data *data, int *tries_left)
{
	struct sc_context *ctx = card->ctx;
	int rv;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx, "iasecc_pin_cmd() cmd 0x%X, PIN type 0x%X, PIN reference %i, PIN-1 %p:%i, PIN-2 %p:%i",
			data->cmd, data->pin_type, data->pin_reference,
		data->pin1.data, data->pin1.len, data->pin2.data, data->pin2.len);

	switch (data->cmd)   {
	case SC_PIN_CMD_VERIFY:
		rv = iasecc_pin_verify(card, data->pin_type, data->pin_reference, data->pin1.data, data->pin1.len, tries_left);
		break;
	case SC_PIN_CMD_CHANGE:
		if (data->pin_type == SC_AC_AUT)
			rv = iasecc_keyset_change(card, data, tries_left);
		else
			rv = iasecc_pin_change(card, data, tries_left);
		break;
	case SC_PIN_CMD_UNBLOCK:
		rv = iasecc_pin_reset(card, data, tries_left);
		break;
	case SC_PIN_CMD_GET_INFO:
		rv = iasecc_pin_get_policy(card, data);
		break;
	case SC_PIN_CMD_LOGOUT:
		rv = iasecc_pin_logout(card, data->pin_type, data->pin_reference, tries_left);
		break;
	default:
		sc_log(ctx, "Other pin commands not supported yet: 0x%X", data->cmd);
		rv = SC_ERROR_NOT_SUPPORTED;
	}


	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_get_serialnr(struct sc_card *card, struct sc_serial_number *serial)
{
	struct sc_context *ctx = card->ctx;
	struct sc_iin *iin = &card->serialnr.iin;
	struct sc_apdu apdu;
	unsigned char rbuf[0xC0];
	size_t ii, offs;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (card->serialnr.len) 
		goto end;

	memset(&card->serialnr, 0, sizeof(card->serialnr));

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
	{
		struct sc_path path;
		struct sc_file *file;
		int rv;
		unsigned char *buf = NULL;

		sc_format_path("3F00D003", &path);
		rv = sc_select_file(card, &path, &file);

		LOG_TEST_RET(ctx, rv, "Cannot select EF(SN) file");

		buf = malloc(file->size);
		if (buf)
		{
			rv = sc_read_binary(card, 0, buf, file->size, 0);
			if (rv >= 0)
			{
				card->serialnr.len = rv;
				memcpy(card->serialnr.value, buf, file->size);
				memset(iin, 0, sizeof(*iin));
			}

			free(buf);
		}
		else
			rv = SC_ERROR_OUT_OF_MEMORY;

		sc_file_free(file);

		if (rv == SC_ERROR_OUT_OF_MEMORY)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "Memory allocation error");
		else if (rv < 0)
			LOG_TEST_RET(ctx, rv, "Cannot read EF(SN) file");


		if (card->serialnr.len != 11 || card->serialnr.value[0] != 0x04 || card->serialnr.value[1] != 0x09)
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "serial number parse error");
		card->serialnr.len = 9;
		memmove(card->serialnr.value, &card->serialnr.value[2], 9);

		iin->mii = 9; // For assignment by nation standards body
		iin->country = 428; //Latvia
		iin->issuer_id = 1;
	}
	else
	{
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0xB0, 0x80 | IASECC_SFI_EF_SN, 0);
		apdu.le = sizeof(rbuf);
		apdu.resp = rbuf;
		apdu.resplen = sizeof(rbuf);

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Get 'serial number' data failed");

		if (rbuf[0] != ISO7812_PAN_SN_TAG)
			LOG_TEST_RET(ctx, SC_ERROR_UNKNOWN_DATA_RECEIVED, "serial number parse error");

		iin->mii = (rbuf[2] >> 4) & 0x0F;

		iin->country = 0;
		for (ii = 5; ii < 8; ii++) {
			iin->country *= 10;
			iin->country += (rbuf[ii / 2] >> ((ii & 0x01) ? 0 : 4)) & 0x0F;
		}

		iin->issuer_id = 0;
		for (ii = 8; ii < 10; ii++) {
			iin->issuer_id *= 10;
			iin->issuer_id += (rbuf[ii / 2] >> (ii & 0x01 ? 0 : 4)) & 0x0F;
		}

		offs = rbuf[1] > 8 ? rbuf[1] - 8 : 0;
		if (card->type == SC_CARD_TYPE_IASECC_SAGEM) {
			/* 5A 0A 92 50 00 20 10 10 25 00 01 3F */
			/*            00 02 01 01 02 50 00 13  */
			for (ii = 0; (ii < rbuf[1] - offs) && (ii + offs + 2 < sizeof(rbuf)); ii++)
				*(card->serialnr.value + ii) = ((rbuf[ii + offs + 1] & 0x0F) << 4)
				+ ((rbuf[ii + offs + 2] & 0xF0) >> 4);
			card->serialnr.len = ii;
		}
		else {
			for (ii = 0; ii < rbuf[1] - offs; ii++)
				*(card->serialnr.value + ii) = rbuf[ii + offs + 2];
			card->serialnr.len = ii;
		}
	}

	do  {
		char txt[0x200];

		for (ii=0;ii<card->serialnr.len;ii++)
			sprintf(txt + ii*2, "%02X", *(card->serialnr.value + ii));

		sc_log(ctx, "serial number '%s'; mii %i; country %i; issuer_id %li", txt, iin->mii, iin->country, iin->issuer_id);
	} while(0);

end:
	if (serial)
		memcpy(serial, &card->serialnr, sizeof(*serial));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_create(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char *data = NULL, sdo_class = sdo->sdo_class;
	struct iasecc_sdo_update update;
	struct iasecc_extended_tlv *field = NULL;
	int rv = SC_ERROR_NOT_SUPPORTED, data_len;

	LOG_FUNC_CALLED(ctx);
	if (sdo->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO data");

	sc_log(ctx, "iasecc_sdo_create(card:%p) %02X%02X%02X", card,
			IASECC_SDO_TAG_HEADER, sdo->sdo_class | 0x80, sdo->sdo_ref);

	data_len = iasecc_sdo_encode_create(ctx, sdo, &data);
	LOG_TEST_RET(ctx, data_len, "iasecc_sdo_create() cannot encode SDO create data");
	sc_log(ctx, "iasecc_sdo_create() create data(%i):%s", data_len, sc_dump_hex(data, data_len));

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.data = data;
	apdu.datalen = data_len;
	apdu.lc = data_len;
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "iasecc_sdo_create() SDO put data error");

	memset(&update, 0, sizeof(update));
	update.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update.sdo_class = sdo->sdo_class;
	update.sdo_ref = sdo->sdo_ref;

	if (sdo_class == IASECC_SDO_CLASS_RSA_PRIVATE)   {
		update.fields[0] = sdo->data.prv_key.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_PRVKEY_TAG;
		field = &sdo->data.prv_key.compulsory;
	}
	else if (sdo_class == IASECC_SDO_CLASS_RSA_PUBLIC)   { 
		update.fields[0] = sdo->data.pub_key.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_PUBKEY_TAG;
		field = &sdo->data.pub_key.compulsory;
	}
	else if (sdo_class == IASECC_SDO_CLASS_KEYSET)   { 
		update.fields[0] = sdo->data.keyset.compulsory;
		update.fields[0].parent_tag = IASECC_SDO_KEYSET_TAG;
		field = &sdo->data.keyset.compulsory;
	}

	if (update.fields[0].value && !update.fields[0].on_card)   {
		rv = iasecc_sdo_put_data(card, &update);
		LOG_TEST_RET(ctx, rv, "failed to update 'Compulsory usage' data");

		if (field)
			field->on_card = 1;
	}

	free(data);
	LOG_FUNC_RETURN(ctx, rv);
}

/* Oberthur's specific */
static int
iasecc_sdo_delete(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char data[6] = {
		0x70, 0x04, 0xBF, 0xFF, 0xFF, 0x00
	};
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (sdo->magic != SC_CARDCTL_IASECC_SDO_MAGIC)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO data");

	data[2] = IASECC_SDO_TAG_HEADER;
	data[3] = sdo->sdo_class | 0x80;
	data[4] = sdo->sdo_ref;
	sc_log(ctx, "delete SDO %02X%02X%02X", data[2], data[3], data[4]);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
	apdu.data = data;
	apdu.datalen = sizeof(data);
	apdu.lc = sizeof(data);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "delete SDO error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_put_data(struct sc_card *card, struct iasecc_sdo_update *update)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	int ii, rv;

	LOG_FUNC_CALLED(ctx);
	if (update->magic != SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Invalid SDO update data");

	for(ii=0; update->fields[ii].tag && ii < IASECC_SDO_TAGS_UPDATE_MAX; ii++)   {
		unsigned char *encoded = NULL;
		int encoded_len;

		encoded_len = iasecc_sdo_encode_update_field(ctx, update->sdo_class, update->sdo_ref,
							&update->fields[ii], &encoded);
		sc_log(ctx, "iasecc_sdo_put_data() encode[%i]; tag %X; encoded_len %i", ii, update->fields[ii].tag, encoded_len);
		LOG_TEST_RET(ctx, encoded_len, "Cannot encode update data");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0xDB, 0x3F, 0xFF);
		apdu.data = encoded;
		apdu.datalen = encoded_len;
		apdu.lc = encoded_len;
		apdu.flags |= SC_APDU_FLAGS_CHAINING;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "SDO put data error");

		free(encoded);
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_key_rsa_put_data(struct sc_card *card, struct iasecc_sdo_rsa_update *update)
{
	struct sc_context *ctx = card->ctx;
	unsigned char scb;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (update->sdo_prv_key)   {
		sc_log(ctx, "encode private rsa in %p", &update->update_prv);
		rv = iasecc_sdo_encode_rsa_update(card->ctx, update->sdo_prv_key, update->p15_rsa, &update->update_prv);
		LOG_TEST_RET(ctx, rv, "failed to encode update of RSA private key");
	}

	if (update->sdo_pub_key)   {
		sc_log(ctx, "encode public rsa in %p", &update->update_pub);
		if (card->type == SC_CARD_TYPE_IASECC_SAGEM)   {
			if (update->sdo_pub_key->data.pub_key.rsa.cha.value)   {
				free(update->sdo_pub_key->data.pub_key.rsa.cha.value);
				memset(&update->sdo_pub_key->data.pub_key.rsa.cha, 0, sizeof(update->sdo_pub_key->data.pub_key.rsa.cha));
			}
		}
		rv = iasecc_sdo_encode_rsa_update(card->ctx, update->sdo_pub_key, update->p15_rsa, &update->update_pub);
		LOG_TEST_RET(ctx, rv, "failed to encode update of RSA public key");
	}

	if (update->sdo_prv_key)   {
		sc_log(ctx, "reference of the private key to store: %X", update->sdo_prv_key->sdo_ref);

		if (update->sdo_prv_key->docp.acls_contact.size == 0)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "extremely strange ... there are no ACLs");

		scb = update->sdo_prv_key->docp.scbs[IASECC_ACLS_RSAKEY_PUT_DATA];
		sc_log(ctx, "'UPDATE PRIVATE RSA' scb 0x%X", scb);

		do   {
			unsigned all_conditions = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;

			if ((scb & IASECC_SCB_METHOD_USER_AUTH) && !all_conditions)
				break;

			if (scb & IASECC_SCB_METHOD_EXT_AUTH)
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

			if (scb & IASECC_SCB_METHOD_SM)   {
#ifdef ENABLE_SM
				rv = iasecc_sm_rsa_update(card, scb & IASECC_SCB_METHOD_MASK_REF, update);
				LOG_FUNC_RETURN(ctx, rv);
#else
				LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "built without support of Secure-Messaging");
#endif
			}
		} while(0);

		rv = iasecc_sdo_put_data(card, &update->update_prv);
		LOG_TEST_RET(ctx, rv, "failed to update of RSA private key");
	}

	if (update->sdo_pub_key)   {
		sc_log(ctx, "reference of the public key to store: %X", update->sdo_pub_key->sdo_ref);

		rv = iasecc_sdo_put_data(card, &update->update_pub);
		LOG_TEST_RET(ctx, rv, "failed to update of RSA public key");
	}

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int
iasecc_sdo_tag_from_class(unsigned sdo_class)
{
	switch (sdo_class & ~IASECC_OBJECT_REF_LOCAL)   {
	case IASECC_SDO_CLASS_CHV:
		return IASECC_SDO_CHV_TAG;
	case IASECC_SDO_CLASS_RSA_PRIVATE:
	case IASECC_SDO_CLASS_EC_PRIVATE:
		return IASECC_SDO_PRVKEY_TAG;
	case IASECC_SDO_CLASS_RSA_PUBLIC:
	case IASECC_SDO_CLASS_EC_PUBLIC:
		return IASECC_SDO_PUBKEY_TAG;
	case IASECC_SDO_CLASS_SE:
		return IASECC_SDO_CLASS_SE;
	case IASECC_SDO_CLASS_KEYSET:
		return IASECC_SDO_KEYSET_TAG;
	}

	return -1;
}


static int
iasecc_sdo_get_tagged_data(struct sc_card *card, int sdo_tag, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[0x100];
	size_t offs = sizeof(sbuf) - 1;
	unsigned char rbuf[0x400];
	int rv;

	LOG_FUNC_CALLED(ctx);

	sbuf[offs--] = 0x80;
	sbuf[offs--] = sdo_tag & 0xFF;
	if ((sdo_tag >> 8) & 0xFF)
		sbuf[offs--] = (sdo_tag >> 8) & 0xFF;
	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;

	sbuf[offs--] = sdo->sdo_ref & 0x9F;
	sbuf[offs--] = sdo->sdo_class | IASECC_OBJECT_REF_LOCAL;
	sbuf[offs--] = IASECC_SDO_TAG_HEADER;

	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;
	sbuf[offs--] = IASECC_SDO_TEMPLATE_TAG;

	sbuf[offs] = sizeof(sbuf) - offs - 1;
	offs--;
	sbuf[offs] = 0x4D;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0xCB, 0x3F, 0xFF);
	apdu.data = sbuf + offs;
	apdu.datalen = sizeof(sbuf) - offs;
	apdu.lc = sizeof(sbuf) - offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

	rv = sc_transmit_apdu(card, &apdu);

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
	{
		if ((card->flags & SC_CARD_FLAG_CONTACTLESS)
			&& (((rv == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) || (apdu.sw1 == 0x69 && apdu.sw2 == 0x82 && sdo_tag != IASECC_SDO_PUBKEY_TAG)))
			)
		{
			/* try to select MF */
			struct sc_path path;
			sc_format_path("3F00", &path);
			path.type = SC_PATH_TYPE_FILE_ID;
			int local_rv = iasecc_select_file(card, &path, NULL);
			if (local_rv >= 0)
			{
				int pace_status = do_pace(card, NULL);
				if (pace_status < 0)
					sc_log(ctx, "PACE authentication failed");
				else
				{
					card->flags |= SC_CARD_FLAG_PACE_STATE_ACTIVE;
					card->flags &= ~(SC_CARD_FLAG_PACE_STATE_NOT_ACTIVE | SC_CARD_FLAG_PACE_STATE_UNKNOWN);

					apdu.resp = rbuf;
					apdu.resplen = sizeof(rbuf);
					apdu.le = 0x100;
					rv = sc_transmit_apdu(card, &apdu);
				}
			}
		}
	}

	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	rv = iasecc_sdo_parse(card, apdu.resp, apdu.resplen, sdo);
	LOG_TEST_RET(ctx, rv, "cannot parse SDO data");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_get_data(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	int rv, sdo_tag;

	LOG_FUNC_CALLED(ctx);

	sdo_tag = iasecc_sdo_tag_from_class(sdo->sdo_class);

	rv = iasecc_sdo_get_tagged_data(card, sdo_tag, sdo);
	if (rv == SC_ERROR_INS_NOT_SUPPORTED)
	{
		if (SC_SUCCESS == iasecc_restore_context (card))
			rv = iasecc_sdo_get_tagged_data(card, sdo_tag, sdo);		
	}
	/* When there is no public data 'GET DATA' returns error */
	if (rv != SC_ERROR_INCORRECT_PARAMETERS)
		LOG_TEST_RET(ctx, rv, "cannot parse ECC SDO data");

	rv = iasecc_sdo_get_tagged_data(card, IASECC_DOCP_TAG, sdo);
	LOG_TEST_RET(ctx, rv, "cannot parse ECC DOCP data");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_sdo_generate(struct sc_card *card, struct iasecc_sdo *sdo)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo_update update_pubkey;
	struct sc_apdu apdu;
	unsigned char scb, sbuf[5], rbuf[0x400], exponent[3] = {0x01, 0x00, 0x01};
	int offs = 0, rv = SC_ERROR_NOT_SUPPORTED;

	LOG_FUNC_CALLED(ctx);

	if (sdo->sdo_class != IASECC_SDO_CLASS_RSA_PRIVATE)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "For a moment, only RSA_PRIVATE class can be accepted for the SDO generation");

	if (sdo->docp.acls_contact.size == 0)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Bewildered ... there are no ACLs");

	scb = sdo->docp.scbs[IASECC_ACLS_RSAKEY_GENERATE];
	sc_log(ctx, "'generate RSA key' SCB 0x%X", scb);
	do   {
		unsigned all_conditions = scb & IASECC_SCB_METHOD_NEED_ALL ? 1 : 0;

		if (scb & IASECC_SCB_METHOD_USER_AUTH)
			if (!all_conditions)
				break;

		if (scb & IASECC_SCB_METHOD_EXT_AUTH)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

		if (scb & IASECC_SCB_METHOD_SM)   {
			rv = iasecc_sm_rsa_generate(card, scb & IASECC_SCB_METHOD_MASK_REF, sdo);
                        LOG_FUNC_RETURN(ctx, rv);
		}
	} while(0);

	memset(&update_pubkey, 0, sizeof(update_pubkey));
	update_pubkey.magic = SC_CARDCTL_IASECC_SDO_MAGIC_PUT_DATA;
	update_pubkey.sdo_class = IASECC_SDO_CLASS_RSA_PUBLIC;
	update_pubkey.sdo_ref = sdo->sdo_ref;

	update_pubkey.fields[0].parent_tag = IASECC_SDO_PUBKEY_TAG;
	update_pubkey.fields[0].tag = IASECC_SDO_PUBKEY_TAG_E;
	update_pubkey.fields[0].value = exponent;
	update_pubkey.fields[0].size = sizeof(exponent);

	rv = iasecc_sdo_put_data(card, &update_pubkey);
	LOG_TEST_RET(ctx, rv, "iasecc_sdo_generate() update SDO public key failed");

	offs = 0;
	sbuf[offs++] = IASECC_SDO_TEMPLATE_TAG;
	sbuf[offs++] = 0x03;
	sbuf[offs++] = IASECC_SDO_TAG_HEADER;
	sbuf[offs++] = IASECC_SDO_CLASS_RSA_PRIVATE | IASECC_OBJECT_REF_LOCAL;
	sbuf[offs++] = sdo->sdo_ref & ~IASECC_OBJECT_REF_LOCAL;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x47, 0x00, 0x00);
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;

	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "SDO get data error");

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_get_chv_reference_from_se(struct sc_card *card, int *se_reference)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_se_info se;
	struct sc_crt crt;
	int rv;

	LOG_FUNC_CALLED(ctx);

	if (!se_reference)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid arguments");

	memset(&se, 0, sizeof(se));
	se.reference = *se_reference;

	rv = iasecc_se_get_info(card, &se);
	LOG_TEST_RET(ctx, rv, "get SE info error");

	memset(&crt, 0, sizeof(crt));
	crt.tag = IASECC_CRT_TAG_AT;
	crt.usage = IASECC_UQB_AT_USER_PASSWORD;

	rv = iasecc_se_get_crt(card, &se, &crt);
	LOG_TEST_RET(ctx, rv, "Cannot get 'USER PASSWORD' authentication template");

	sc_file_free(se.df);
	LOG_FUNC_RETURN(ctx, crt.refs[0]);
}


static int
iasecc_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = (struct iasecc_sdo *) ptr;

	switch (cmd) {
	case SC_CARDCTL_GET_SERIALNR:
		return iasecc_get_serialnr(card, (struct sc_serial_number *)ptr);
	case SC_CARDCTL_IASECC_SDO_CREATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_CREATE: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_create(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_DELETE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_DELETE: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_delete(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_PUT_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_put_data(card, (struct iasecc_sdo_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_KEY_RSA_PUT_DATA");
		return iasecc_sdo_key_rsa_put_data(card, (struct iasecc_sdo_rsa_update *) ptr);
	case SC_CARDCTL_IASECC_SDO_GET_DATA:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_get_data(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_IASECC_SDO_GENERATE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_SDO_GET_DATA: sdo_class %X", sdo->sdo_class);
		return iasecc_sdo_generate(card, (struct iasecc_sdo *) ptr);
	case SC_CARDCTL_GET_SE_INFO:
		sc_log(ctx, "CMD SC_CARDCTL_GET_SE_INFO: sdo_class %X", sdo->sdo_class);
		return iasecc_se_get_info(card, (struct iasecc_se_info *) ptr);		
	case SC_CARDCTL_GET_CHV_REFERENCE_IN_SE:
		sc_log(ctx, "CMD SC_CARDCTL_GET_CHV_REFERENCE_IN_SE");
		return iasecc_get_chv_reference_from_se(card, (int *)ptr); 
	case SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE:
		sc_log(ctx, "CMD SC_CARDCTL_IASECC_GET_FREE_KEY_REFERENCE");
		return iasecc_get_free_reference(card, (struct iasecc_ctl_get_free_reference *)ptr); 
	}
	return SC_ERROR_NOT_SUPPORTED;
}


static int 
iasecc_decipher(struct sc_card *card, 
		const unsigned char *in, size_t in_len,
		unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct sc_apdu apdu;
	unsigned char sbuf[0x200];
	unsigned char resp[SC_MAX_APDU_BUFFER_SIZE];
	size_t offs;
	int rv;
	struct iasecc_private_data *prv;
	struct sc_security_env *env;

	LOG_FUNC_CALLED(ctx);
	sc_log(card->ctx,
	       "crgram_len %"SC_FORMAT_LEN_SIZE_T"u;  outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len, out_len);
	if (!out || !out_len || in_len > SC_MAX_APDU_BUFFER_SIZE) 
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	prv = (struct iasecc_private_data *) card->drv_data;
	env = &prv->security_env;
	
	offs = 0;
	sbuf[offs++] = (env->operation == SC_SEC_OPERATION_DERIVE)? 0x00 : 0x81;
	memcpy(sbuf + offs, in, in_len);
	offs += in_len;

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x80, 0x86);
	apdu.flags |= SC_APDU_FLAGS_CHAINING;
	apdu.data = sbuf;
	apdu.datalen = offs;
	apdu.lc = offs;
	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = 256;
	
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Card returned error");

	if (out_len > apdu.resplen)
		out_len = apdu.resplen;
	
	memcpy(out, apdu.resp, out_len);
	rv = out_len;

	LOG_FUNC_RETURN(ctx, rv);
}


static int
iasecc_qsign_data_sha1(struct sc_context *ctx, const unsigned char *in, size_t in_len,
				struct iasecc_qsign_data *out)
{
	SHA_CTX sha;
	SHA_LONG pre_hash_Nl, *hh[5] = {
		&sha.h0, &sha.h1, &sha.h2, &sha.h3, &sha.h4
	};
	int jj, ii;
	int hh_size = sizeof(SHA_LONG), hh_num = SHA_DIGEST_LENGTH / sizeof(SHA_LONG);

	LOG_FUNC_CALLED(ctx);

	if (!in || !in_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx,
	       "sc_pkcs15_get_qsign_data() input data length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	SHA1_Init(&sha);
	SHA1_Update(&sha, in, in_len);

	for (jj=0; jj<hh_num; jj++) 
		for(ii=0; ii<hh_size; ii++) 
			out->pre_hash[jj*hh_size + ii] = ((*hh[jj] >> 8*(hh_size-1-ii)) & 0xFF);
	out->pre_hash_size = SHA_DIGEST_LENGTH;
	sc_log(ctx, "Pre SHA1:%s", sc_dump_hex(out->pre_hash, out->pre_hash_size));

	pre_hash_Nl = sha.Nl - (sha.Nl % (sizeof(sha.data) * 8));
	for (ii=0; ii<hh_size; ii++)   {
		out->counter[ii] = (sha.Nh >> 8*(hh_size-1-ii)) &0xFF;
		out->counter[hh_size+ii] = (pre_hash_Nl >> 8*(hh_size-1-ii)) &0xFF;
	}
	for (ii=0, out->counter_long=0; ii<(int)sizeof(out->counter); ii++)
		out->counter_long = out->counter_long*0x100 + out->counter[ii];
	sc_log(ctx, "Pre counter(%li):%s", out->counter_long, sc_dump_hex(out->counter, sizeof(out->counter)));

	if (sha.num)   {
		memcpy(out->last_block, in + in_len - sha.num, sha.num);
		out->last_block_size = sha.num;
		sc_log(ctx, "Last block(%"SC_FORMAT_LEN_SIZE_T"u):%s",
		       out->last_block_size,
		       sc_dump_hex(out->last_block, out->last_block_size));
	}

	SHA1_Final(out->hash, &sha);
	out->hash_size = SHA_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


#if OPENSSL_VERSION_NUMBER >= 0x00908000L
static int
iasecc_qsign_data_sha224(struct sc_context *ctx, const unsigned char *in, size_t in_len,
				struct iasecc_qsign_data *out)
{
	SHA256_CTX sha224;
	SHA_LONG pre_hash_Nl;
	int jj, ii;
	int hh_size = sizeof(SHA_LONG), hh_num = SHA256_DIGEST_LENGTH / sizeof(SHA_LONG);

	LOG_FUNC_CALLED(ctx);
	if (!in || !in_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "sc_pkcs15_get_qsign_data() input data length %i", in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	SHA224_Init(&sha224);
	SHA224_Update(&sha224, in, in_len);

	for (jj=0; jj<hh_num; jj++)
		for(ii=0; ii<hh_size; ii++)
			out->pre_hash[jj*hh_size + ii] = ((sha224.h[jj] >> 8*(hh_size-1-ii)) & 0xFF);
	out->pre_hash_size = SHA224_DIGEST_LENGTH;
	sc_log(ctx, "Pre hash:%s", sc_dump_hex(out->pre_hash, out->pre_hash_size));

	pre_hash_Nl = sha224.Nl - (sha224.Nl % (sizeof(sha224.data) * 8));
	for (ii=0; ii<hh_size; ii++)   {
		out->counter[ii] = (sha224.Nh >> 8*(hh_size-1-ii)) &0xFF;
		out->counter[hh_size+ii] = (pre_hash_Nl >> 8*(hh_size-1-ii)) &0xFF;
	}
	for (ii=0, out->counter_long=0; ii<(int)sizeof(out->counter); ii++)
		out->counter_long = out->counter_long*0x100 + out->counter[ii];
	sc_log(ctx, "Pre counter(%li):%s", out->counter_long, sc_dump_hex(out->counter, sizeof(out->counter)));

	if (sha224.num)   {
		memcpy(out->last_block, in + in_len - sha224.num, sha224.num);
		out->last_block_size = sha224.num;
		sc_log(ctx, "Last block(%i):%s", out->last_block_size, sc_dump_hex(out->last_block, out->last_block_size));
	}

	SHA256_Final(out->hash, &sha224);
	out->hash_size = SHA224_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int
iasecc_qsign_data_sha256(struct sc_context *ctx, const unsigned char *in, size_t in_len,
				struct iasecc_qsign_data *out)
{
	SHA256_CTX sha256;
	SHA_LONG pre_hash_Nl;
	int jj, ii;
	int hh_size = sizeof(SHA_LONG), hh_num = SHA256_DIGEST_LENGTH / sizeof(SHA_LONG);

	LOG_FUNC_CALLED(ctx);
	if (!in || !in_len || !out)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);
	
	sc_log(ctx,
	       "sc_pkcs15_get_qsign_data() input data length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	memset(out, 0, sizeof(struct iasecc_qsign_data));

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, in, in_len);

	for (jj=0; jj<hh_num; jj++) 
		for(ii=0; ii<hh_size; ii++) 
			out->pre_hash[jj*hh_size + ii] = ((sha256.h[jj] >> 8*(hh_size-1-ii)) & 0xFF);
	out->pre_hash_size = SHA256_DIGEST_LENGTH;
	sc_log(ctx, "Pre hash:%s", sc_dump_hex(out->pre_hash, out->pre_hash_size));

	pre_hash_Nl = sha256.Nl - (sha256.Nl % (sizeof(sha256.data) * 8));
	for (ii=0; ii<hh_size; ii++)   {
		out->counter[ii] = (sha256.Nh >> 8*(hh_size-1-ii)) &0xFF;
		out->counter[hh_size+ii] = (pre_hash_Nl >> 8*(hh_size-1-ii)) &0xFF;
	}
	for (ii=0, out->counter_long=0; ii<(int)sizeof(out->counter); ii++)
		out->counter_long = out->counter_long*0x100 + out->counter[ii];
	sc_log(ctx, "Pre counter(%li):%s", out->counter_long, sc_dump_hex(out->counter, sizeof(out->counter)));

	if (sha256.num)   {
		memcpy(out->last_block, in + in_len - sha256.num, sha256.num);
		out->last_block_size = sha256.num;
		sc_log(ctx, "Last block(%"SC_FORMAT_LEN_SIZE_T"u):%s",
		       out->last_block_size,
		       sc_dump_hex(out->last_block, out->last_block_size));
	}

	SHA256_Final(out->hash, &sha256);
	out->hash_size = SHA256_DIGEST_LENGTH;
	sc_log(ctx, "Expected digest %s\n", sc_dump_hex(out->hash, out->hash_size));

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}
#endif


static int 
iasecc_compute_signature_dst(struct sc_card *card, 
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct iasecc_qsign_data qsign_data;
	struct sc_apdu apdu;
	size_t offs = 0, hash_len = 0;
	unsigned char sbuf[SC_MAX_APDU_BUFFER_SIZE];
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE];
	int rv = SC_SUCCESS;
	unsigned int algorithm = 0;
	int is_ecc = (env->algorithm_flags & SC_ALGORITHM_RSA_PADS)? 0 : 1;
	int external_hash = 0;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "iasecc_compute_signature_dst() input length %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len);
	if (env->operation != SC_SEC_OPERATION_SIGN)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_SIGN");
	else if (!is_ecc && (!(prv->key_size & 0x1E0) || (prv->key_size & ~0x1E0)))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key size for SC_SEC_OPERATION_SIGN");

	memset(&qsign_data, 0, sizeof(qsign_data));

	if (!is_ecc && !(env->algorithm_flags & (SC_ALGORITHM_RSA_HASHES & ~SC_ALGORITHM_RSA_HASH_NONE)))
	{
		/* detect if the input contains hash OID prefix */
		rv = sc_pkcs1_strip_digest_info_prefix(&algorithm, in, in_len, NULL, NULL);
		if (rv >= 0)
		{
			if (card->type == SC_CARD_TYPE_IASECC_LATVIA)
			{
			if (algorithm != SC_ALGORITHM_RSA_HASH_SHA256)
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_HASH_SHA256 algorithm");

			qsign_data.hash_size = sizeof(qsign_data.hash);
			rv = sc_pkcs1_strip_digest_info_prefix(&algorithm, in, in_len, qsign_data.hash, &qsign_data.hash_size);
			if (rv < 0)
			{
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid hash value after OID prefix");
			}

			external_hash = 1;
		}
		else
			{
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Off-card hash not supported.");
			}
		}
		else
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid input: need digest info with hash OID");
	}
	else if (is_ecc && !(env->algorithm_flags & (SC_ALGORITHM_ECDSA_HASHES)))
	{		
		size_t maxHashSize = 0;

		switch (env->mechanism_in_use)
		{
			case CKM_ECDSA_SHA1:
				maxHashSize = 20;
				break;
			case CKM_ECDSA_SHA224:
				maxHashSize = 28;
				break;
			case CKM_ECDSA_SHA256:
				maxHashSize = 32;
				break;
			case CKM_ECDSA_SHA384:
				maxHashSize = 48;
				break;
			case CKM_ECDSA_SHA512:
				maxHashSize = 64;
				break;
			default:
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign any hash");
				break;
		}

		if (in_len > maxHashSize)
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Off-card hash is too big for the selected key");

		memcpy(&qsign_data.hash[maxHashSize - in_len], in, in_len);

		qsign_data.hash_size = maxHashSize;
		external_hash = 1;
	}
	else
	{
		if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) && (!is_ecc || (env->mechanism_in_use == CKM_ECDSA_SHA1))) {
			rv = iasecc_qsign_data_sha1(card->ctx, in, in_len, &qsign_data);
		}
		else if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224) && (!is_ecc || (env->mechanism_in_use == CKM_ECDSA_SHA224))) {
			rv = iasecc_qsign_data_sha224(card->ctx, in, in_len, &qsign_data);
		}
		else if ((env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256) && (!is_ecc || (env->mechanism_in_use == CKM_ECDSA_SHA256))){
			rv = iasecc_qsign_data_sha256(card->ctx, in, in_len, &qsign_data);
		}
		else if (is_ecc) {
			size_t maxHashSize = 0;

			switch (env->mechanism_in_use)
			{
			case CKM_ECDSA_SHA1:
				maxHashSize = 20;
				break;
			case CKM_ECDSA_SHA224:
				maxHashSize = 28;
				break;
			case CKM_ECDSA_SHA256:
				maxHashSize = 32;
				break;
			case CKM_ECDSA_SHA384:
				maxHashSize = 48;
				break;
			case CKM_ECDSA_SHA512:
				maxHashSize = 64;
				break;
			default:
				LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign any hash");
				break;
			}

			if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)
			{
				if (maxHashSize >= 20)
					SHA1(in, in_len, &qsign_data.hash[maxHashSize - 20]);
				else
					LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign SHA1 hash");
			}
			else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA224)
			{
				if (maxHashSize >= 28)
					SHA224(in, in_len, &qsign_data.hash[maxHashSize - 28]);
				else
					LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign SHA224 hash");
			}
			else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA256)
			{
				if (maxHashSize >= 32)
					SHA256(in, in_len, &qsign_data.hash[maxHashSize - 32]);
				else
					LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign SHA256 hash");
			}
			else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA384)
			{
				if (maxHashSize >= 48)
					SHA384(in, in_len, &qsign_data.hash[maxHashSize - 48]);
				else
					LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign SHA384 hash");
			}
			else
			{
				if (maxHashSize >= 64)
					SHA512(in, in_len, &qsign_data.hash[maxHashSize - 64]);
				else
					LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Selected key can't sign SHA512 hash");
			}
			qsign_data.hash_size = maxHashSize;
			external_hash = 1;
		}
		else if (is_ecc && env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA512) {

			SHA512(in, in_len, qsign_data.hash);
			qsign_data.hash_size = 64;
			external_hash = 1;
		}
		else
			LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Need RSA_HASH_SHA1, RSA_HASH_SHA224 or RSA_HASH_SHA256 algorithm");

		LOG_TEST_RET(ctx, rv, "Cannot get QSign data");
	}
	sc_log(ctx,
	       "iasecc_compute_signature_dst() hash_len %"SC_FORMAT_LEN_SIZE_T"u; key_size %"SC_FORMAT_LEN_SIZE_T"u",
	       hash_len, prv->key_size);

	memset(sbuf, 0, sizeof(sbuf));

	if (card->type == SC_CARD_TYPE_IASECC_LATVIA && external_hash)
	{
		memcpy (sbuf, qsign_data.hash, qsign_data.hash_size);

		sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x2A, 0x9E, 0x9A);
		apdu.data = sbuf;
		apdu.datalen = qsign_data.hash_size;
		apdu.lc = qsign_data.hash_size;
		apdu.resp = rbuf;
		apdu.resplen = is_ecc? sizeof(rbuf) : prv->key_size;
		apdu.le = is_ecc? 2*prv->key_size : prv->key_size;
	}
	else
	{
		sbuf[offs++] = 0x90;
		if (qsign_data.counter_long) {
			sbuf[offs++] = qsign_data.hash_size + 8;
			memcpy(sbuf + offs, qsign_data.pre_hash, qsign_data.pre_hash_size);
			offs += qsign_data.pre_hash_size;
			memcpy(sbuf + offs, qsign_data.counter, sizeof(qsign_data.counter));
			offs += sizeof(qsign_data.counter);
		}
		else {
			sbuf[offs++] = 0;
		}

		sbuf[offs++] = 0x80;
		sbuf[offs++] = qsign_data.last_block_size;
		memcpy(sbuf + offs, qsign_data.last_block, qsign_data.last_block_size);
		offs += qsign_data.last_block_size;

		sc_log(ctx, "iasecc_compute_signature_dst() offs %i; OP(meth:%X,ref:%X)", offs, prv->op_method, prv->op_ref);
		if (prv->op_method == SC_AC_SCB && (prv->op_ref & IASECC_SCB_METHOD_SM))
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Not yet");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x2A, 0x90, 0xA0);
		apdu.data = sbuf;
		apdu.datalen = offs;
		apdu.lc = offs;

		rv = sc_transmit_apdu(card, &apdu);
		LOG_TEST_RET(ctx, rv, "APDU transmit failed");
		rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
		LOG_TEST_RET(ctx, rv, "Compute signature failed");

		sc_log(ctx, "iasecc_compute_signature_dst() partial hash OK");

		sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x2A, 0x9E, 0x9A);
		apdu.resp = rbuf;
		apdu.resplen = is_ecc ? sizeof(rbuf) : prv->key_size;
		apdu.le = is_ecc ? 2 * prv->key_size : prv->key_size;
	}
	
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	sc_log(ctx,
	       "iasecc_compute_signature_dst() DST resplen %"SC_FORMAT_LEN_SIZE_T"u",
	       apdu.resplen);
	if (apdu.resplen > out_len) 
		LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Result buffer too small for the DST signature");
	else
	memcpy(out, apdu.resp, apdu.resplen);

	LOG_FUNC_RETURN(ctx, apdu.resplen);
}


static int 
iasecc_compute_signature_at(struct sc_card *card, 
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_private_data *prv = (struct iasecc_private_data *) card->drv_data;
	struct sc_security_env *env = &prv->security_env;
	struct sc_apdu apdu;
	size_t offs = 0, sz = 0;
	unsigned char rbuf[SC_MAX_APDU_BUFFER_SIZE + 30];
	int rv;
	unsigned char digest[128] = {0};
	size_t hash_size = 0;
	unsigned char digestInfo[83]; /* enough to help hash + digest info OID*/
	size_t digestInfoSize = 0;
	unsigned int algorithm = 0;
	int is_ecc = (env->algorithm_flags & SC_ALGORITHM_RSA_PADS)? 0 : 1;

	LOG_FUNC_CALLED(ctx);
	if (env->operation != SC_SEC_OPERATION_AUTHENTICATE)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "It's not SC_SEC_OPERATION_AUTHENTICATE");

   if (is_ecc)
	{
		/* use filed size */
		size_t maxHashSize = prv->key_size;

		if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA1)   {
			SHA_CTX sha;
			SHA1_Init (&sha);
			SHA1_Update (&sha, in, in_len);
			SHA1_Final (&digest[maxHashSize - 20], &sha);
		}
		else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA224) {
			SHA256_CTX sha2;
			SHA224_Init(&sha2);
			SHA224_Update(&sha2, in, in_len);
			if (maxHashSize >= 28)
				SHA224_Final(&digest[maxHashSize - 28], &sha2);
			else
				SHA224_Final(digest, &sha2);
		}
		else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA256) {
			SHA256_CTX sha2;
			SHA256_Init(&sha2);
			SHA256_Update(&sha2, in, in_len);
			if (maxHashSize >= 32)
				SHA256_Final(&digest[maxHashSize - 32], &sha2);
			else
				SHA256_Final(digest, &sha2);
		}
		else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA384) {
			SHA512_CTX sha2;
			SHA384_Init(&sha2);
			SHA384_Update(&sha2, in, in_len);
			if (maxHashSize >= 48)
				SHA384_Final(&digest[maxHashSize - 48], &sha2);
			else
				SHA384_Final(digest, &sha2);
		}
		else if (env->algorithm_flags & SC_ALGORITHM_ECDSA_HASH_SHA512) {
			SHA512_CTX sha2;
			SHA512_Init(&sha2);
			SHA512_Update(&sha2, in, in_len);
			if (maxHashSize >= 64)
				SHA512_Final(&digest[maxHashSize - 64], &sha2);
			else
				SHA512_Final(digest, &sha2);
		}
		else
		{
			if (maxHashSize >= in_len)
				memcpy(&digest[maxHashSize - in_len], in, in_len);
			else
				memcpy(digest, in, maxHashSize);
		}

		hash_size = maxHashSize;
	}
   else if (env->algorithm_flags & ((SC_ALGORITHM_RSA_HASH_SHA1 | SC_ALGORITHM_RSA_HASH_SHA224 | SC_ALGORITHM_RSA_HASH_SHA256 | SC_ALGORITHM_RSA_HASH_SHA384 | SC_ALGORITHM_RSA_HASH_SHA512)))
   {
	   unsigned int mechanism_in_use;
	   if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
	   {
		   SHA_CTX sha;
		   SHA1_Init(&sha);
		   SHA1_Update(&sha, in, in_len);
		   SHA1_Final(digest, &sha);
		   mechanism_in_use = SC_ALGORITHM_RSA_HASH_SHA1;
		   hash_size = 20;
	   }
	   else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA224)
	   {
		   SHA256_CTX sha2;
		   SHA224_Init(&sha2);
		   SHA224_Update(&sha2, in, in_len);
		   SHA224_Final(digest, &sha2);
		   mechanism_in_use = SC_ALGORITHM_RSA_HASH_SHA224;
		   hash_size = 28;
	   }
	   else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA256)
	   {
		   SHA256_CTX sha2;
		   SHA256_Init(&sha2);
		   SHA256_Update(&sha2, in, in_len);
		   SHA256_Final(digest, &sha2);
		   mechanism_in_use = SC_ALGORITHM_RSA_HASH_SHA256;
		   hash_size = 32;
	   }
	   else if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA384)
	   {
		   SHA512_CTX sha2;
		   SHA384_Init(&sha2);
		   SHA384_Update(&sha2, in, in_len);
		   SHA384_Final(digest, &sha2);
		   mechanism_in_use = SC_ALGORITHM_RSA_HASH_SHA384;
		   hash_size = 48;
	   }
	   else
	   {
		   SHA512_CTX sha2;
		   SHA512_Init(&sha2);
		   SHA512_Update(&sha2, in, in_len);
		   SHA512_Final(digest, &sha2);
		   mechanism_in_use = SC_ALGORITHM_RSA_HASH_SHA512;
		   hash_size = 64;
	   }

	   digestInfoSize = sizeof(digestInfo);
	   if (sc_pkcs1_add_digest_info_prefix(mechanism_in_use, digest, hash_size, digestInfo, &digestInfoSize) < 0)
	   {
		   LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "Unexpected error while adding digest info prefix to hash");
	   }

	   in = digestInfo;
	   in_len = digestInfoSize;
   }

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4_SHORT, 0x88, 0x00, 0x00);
	if (is_ecc)
	{
		apdu.datalen = hash_size;
		apdu.data = digest;
		apdu.lc = hash_size;
		apdu.le = 2 * prv->key_size;
	}
	else
	{
		apdu.datalen = in_len;
		apdu.data = in;
		apdu.lc = in_len;
		apdu.le = prv->key_size;
	}
	apdu.resp = rbuf;
	apdu.resplen = sizeof(rbuf);
	apdu.le = 0x100;
	
	rv = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(ctx, rv, "APDU transmit failed");
	rv = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(ctx, rv, "Compute signature failed");

	do   {
		if (offs + apdu.resplen > out_len)
			LOG_TEST_RET(ctx, SC_ERROR_BUFFER_TOO_SMALL, "Buffer too small to return signature");
		
		memcpy(out + offs, rbuf, apdu.resplen);
		offs += apdu.resplen;
		
		if (apdu.sw1 == 0x90 && apdu.sw2 == 0x00)
			break;

		if (apdu.sw1 == 0x61)   {
			sz = apdu.sw2 == 0x00 ? 0x100 : apdu.sw2;
			rv = iso_ops->get_response(card, &sz, rbuf);
			LOG_TEST_RET(ctx, rv, "Get response error");

			apdu.resplen = rv;
		}
		else   {
			LOG_TEST_RET(ctx, SC_ERROR_INTERNAL, "Impossible error: SW1 is not 0x90 neither 0x61");
		}
		
	} while(rv > 0);

	LOG_FUNC_RETURN(ctx, offs);
}


static int 
iasecc_compute_signature(struct sc_card *card, 
		const unsigned char *in, size_t in_len, unsigned char *out, size_t out_len)
{
	struct sc_context *ctx;
	struct iasecc_private_data *prv;
	struct sc_security_env *env;

	if (!card || !in || !out)
		return SC_ERROR_INVALID_ARGUMENTS;

	ctx = card->ctx;
	prv = (struct iasecc_private_data *) card->drv_data;
	env = &prv->security_env;

	LOG_FUNC_CALLED(ctx);
	sc_log(ctx,
	       "inlen %"SC_FORMAT_LEN_SIZE_T"u, outlen %"SC_FORMAT_LEN_SIZE_T"u",
	       in_len, out_len);

	if (env->operation == SC_SEC_OPERATION_SIGN)
		return iasecc_compute_signature_dst(card, in, in_len, out,  out_len);
	else if (env->operation == SC_SEC_OPERATION_AUTHENTICATE)
		return iasecc_compute_signature_at(card, in, in_len, out,  out_len);

	LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
}


static int
iasecc_read_public_key(struct sc_card *card, unsigned type,
		struct sc_path *key_path, unsigned ref, unsigned size,
			unsigned char **out, size_t *out_len)
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo sdo;
	struct sc_pkcs15_bignum bn[2];
	struct sc_pkcs15_pubkey_rsa rsa_key;
	int rv;

	LOG_FUNC_CALLED(ctx);
	if (type != SC_ALGORITHM_RSA && type != SC_ALGORITHM_EC)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);

	sc_log(ctx, "read public kay(ref:%i;size:%i)", ref, size);

	memset(&sdo, 0, sizeof(sdo));
	sdo.sdo_class = (type == SC_ALGORITHM_RSA)? IASECC_SDO_CLASS_RSA_PUBLIC : IASECC_SDO_CLASS_EC_PUBLIC;
	sdo.sdo_ref  = ref & ~IASECC_OBJECT_REF_LOCAL;

	rv = iasecc_sdo_get_data(card, &sdo);
	LOG_TEST_RET(ctx, rv, "failed to read public key: cannot get RSA SDO data");

	if (out)
		*out = NULL;
	if (out_len)
		*out_len = 0;

	if (type == SC_ALGORITHM_RSA)
	{
		bn[0].data = (unsigned char *)malloc(sdo.data.pub_key.rsa.n.size);
		if (!bn[0].data)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "failed to read public key: cannot allocate modulus");
		bn[0].len = sdo.data.pub_key.rsa.n.size;
		memcpy(bn[0].data, sdo.data.pub_key.rsa.n.value, sdo.data.pub_key.rsa.n.size);

		bn[1].data = (unsigned char *)malloc(sdo.data.pub_key.rsa.e.size);
		if (!bn[1].data)
			LOG_TEST_RET(ctx, SC_ERROR_OUT_OF_MEMORY, "failed to read public key: cannot allocate exponent");
		bn[1].len = sdo.data.pub_key.rsa.e.size;
		memcpy(bn[1].data, sdo.data.pub_key.rsa.e.value, sdo.data.pub_key.rsa.e.size);

		rsa_key.modulus = bn[0];
		rsa_key.exponent = bn[1];

		rv = sc_pkcs15_encode_pubkey_rsa(ctx, &rsa_key, out, out_len);
		LOG_TEST_RET(ctx, rv, "failed to read public key: cannot encode RSA public key");
	}

	if (out && out_len)
	sc_log(ctx, "encoded public key: %s", sc_dump_hex(*out, *out_len));

	if (bn[0].data)
		free(bn[0].data);
	if (bn[1].data)
		free(bn[1].data);

	iasecc_sdo_free_fields(card, &sdo);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static int 
iasecc_get_free_reference(struct sc_card *card, struct iasecc_ctl_get_free_reference *ctl_data) 
{
	struct sc_context *ctx = card->ctx;
	struct iasecc_sdo *sdo = NULL;
	int idx, rv;

	LOG_FUNC_CALLED(ctx);

	if ((ctl_data->key_size % 0x40) || ctl_data->index < 1 || (ctl_data->index > IASECC_OBJECT_REF_MAX))
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	sc_log(ctx, "get reference for key(index:%i,usage:%X,access:%X)", ctl_data->index, ctl_data->usage, ctl_data->access);
	/* TODO: when looking for the slot for the signature keys, check also PSO_SIGNATURE ACL */
	for (idx = ctl_data->index; idx <= IASECC_OBJECT_REF_MAX; idx++)   {
		unsigned char sdo_tag[3] = {
			IASECC_SDO_TAG_HEADER, IASECC_OBJECT_REF_LOCAL | IASECC_SDO_CLASS_RSA_PRIVATE, idx
		};
		size_t sz;

		if (sdo)
			iasecc_sdo_free(card, sdo);

		rv = iasecc_sdo_allocate_and_parse(card, sdo_tag, 3, &sdo);
		LOG_TEST_RET(ctx, rv, "cannot parse SDO data");

		rv = iasecc_sdo_get_data(card, sdo);
		if (rv == SC_ERROR_DATA_OBJECT_NOT_FOUND)   {
			iasecc_sdo_free(card, sdo);

			sc_log(ctx, "found empty key slot %i", idx);
			break;
		} else if (rv != SC_SUCCESS) {
			iasecc_sdo_free(card, sdo);

			sc_log(ctx, "get new key reference failed");
			LOG_FUNC_RETURN(ctx, rv);
		}

		sz = *(sdo->docp.size.value + 0) * 0x100 + *(sdo->docp.size.value + 1);
		sc_log(ctx,
		       "SDO(idx:%i) size %"SC_FORMAT_LEN_SIZE_T"u; key_size %"SC_FORMAT_LEN_SIZE_T"u",
		       idx, sz, ctl_data->key_size);

		if (sz != ctl_data->key_size / 8)   {
			sc_log(ctx,
			       "key index %i ignored: different key sizes %"SC_FORMAT_LEN_SIZE_T"u/%"SC_FORMAT_LEN_SIZE_T"u",
			       idx, sz, ctl_data->key_size / 8);
			continue;
		}

		if (sdo->docp.non_repudiation.value)   {
			sc_log(ctx, "non repudiation flag %X", sdo->docp.non_repudiation.value[0]);
			if ((ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && !(*sdo->docp.non_repudiation.value))   {
				sc_log(ctx, "key index %i ignored: need non repudiation", idx);
				continue;
			}

			if (!(ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && *sdo->docp.non_repudiation.value)   {
				sc_log(ctx, "key index %i ignored: don't need non-repudiation", idx);
				continue;
			}
		}

		if (ctl_data->access & SC_PKCS15_PRKEY_ACCESS_LOCAL)   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_GENERATE] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: GENERATE KEY not allowed", idx);
				continue;
			}
		}
		else   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PUT_DATA] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PUT DATA not allowed", idx);
				continue;
			}
		}

		if ((ctl_data->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION) && (ctl_data->usage & SC_PKCS15_PRKEY_USAGE_SIGN))   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PSO_SIGN] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PSO SIGN not allowed", idx);
				continue;
			}
		}
		else if (ctl_data->usage & SC_PKCS15_PRKEY_USAGE_SIGN)   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_INTERNAL_AUTH] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: INTERNAL AUTHENTICATE not allowed", idx);
				continue;
			}
		}

		if (ctl_data->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT | SC_PKCS15_PRKEY_USAGE_UNWRAP))   {
			if (sdo->docp.scbs[IASECC_ACLS_RSAKEY_PSO_DECIPHER] == IASECC_SCB_NEVER)   {
				sc_log(ctx, "key index %i ignored: PSO DECIPHER not allowed", idx);
				continue;
			}
		}

		break;
	}

	ctl_data->index = idx;

	if (idx > IASECC_OBJECT_REF_MAX)
		LOG_FUNC_RETURN(ctx, SC_ERROR_DATA_OBJECT_NOT_FOUND);

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}


static struct sc_card_driver *
sc_get_driver(void)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

	if (!iso_ops)
		iso_ops = iso_drv->ops;

	iasecc_ops = *iso_ops;

	iasecc_ops.match_card = iasecc_match_card;
	iasecc_ops.init = iasecc_init;
	iasecc_ops.finish = iasecc_finish;
	iasecc_ops.read_binary = iasecc_read_binary;
	/*	write_binary: ISO7816 implementation works	*/
	/*	update_binary: ISO7816 implementation works	*/
	iasecc_ops.erase_binary = iasecc_erase_binary;
	/*	resize_binary	*/
	/* 	read_record: Untested	*/
	/*	write_record: Untested	*/
	/*	append_record: Untested	*/
	/*	update_record: Untested	*/
	iasecc_ops.select_file = iasecc_select_file;
	/*	get_response: Untested	*/
	iasecc_ops.get_challenge = iasecc_get_challenge;
	iasecc_ops.logout = iasecc_logout;
	/*	restore_security_env	*/
	iasecc_ops.set_security_env = iasecc_set_security_env;
	iasecc_ops.decipher = iasecc_decipher;
	iasecc_ops.compute_signature = iasecc_compute_signature;
	iasecc_ops.create_file = iasecc_create_file;
	iasecc_ops.delete_file = iasecc_delete_file;
	/*	list_files	*/
	iasecc_ops.check_sw = iasecc_check_sw;
	iasecc_ops.card_ctl = iasecc_card_ctl;
	iasecc_ops.process_fci = iasecc_process_fci;
	/*	construct_fci: Not needed	*/
	iasecc_ops.pin_cmd = iasecc_pin_cmd;
	/*	get_data: Not implemented	*/
	/*	put_data: Not implemented	*/
	/*	delete_record: Not implemented	*/

	iasecc_ops.read_public_key = iasecc_read_public_key;

	return &iasecc_drv;
}

struct sc_card_driver *
sc_get_iasecc_driver(void)
{
	return sc_get_driver();
}

#else

/* we need to define the functions below to export them */
#include "errors.h"

int
iasecc_se_get_info()
{
	return SC_ERROR_NOT_SUPPORTED;
}

#endif /* ENABLE_OPENSSL */
