/*
 *  Copyright (c) 2004 Apple Computer, Inc. All Rights Reserved.
 *
 *  @APPLE_LICENSE_HEADER_START@
 *
 *  This file contains Original Code and/or Modifications of Original Code
 *  as defined in and that are subject to the Apple Public Source License
 *  Version 2.0 (the 'License'). You may not use this file except in
 *  compliance with the License. Please obtain a copy of the License at
 *  http://www.opensource.apple.com/apsl/ and read it before using this
 *  file.
 *
 *  The Original Code and all software distributed under the License are
 *  distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 *  EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 *  INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 *  Please see the License for the specific language governing rights and
 *  limitations under the License.
 *
 *  @APPLE_LICENSE_HEADER_END@
 */

#include "OpenSCToken.h"

#include "Adornment.h"
#include "AttributeCoder.h"

#include "libopensc/opensc.h"
#include "scconf/scconf.h"
#include "libopensc/log.h"
#include "OpenSCRecord.h"
#include "OpenSCSchema.h"
#include <security_cdsa_client/aclclient.h>
#include <CommonCrypto/CommonDigest.h>

#include <map>
#include <vector>
#include <sstream>
#include <iomanip>

/*#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#include <openssl/opensslconf.h>
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00907000L
#include <openssl/conf.h>
#endif
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000L
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#endif
#include <openssl/bn.h>
#include <openssl/err.h>*/

using CssmClient::AclFactory;

OpenSCToken::OpenSCToken() : mLocked(false)
{
	mTokenContext = this;
	mScCtx = NULL;
	mScCard = NULL;
	mSession.open();
	mPinCount = 1;
	mCurrentPIN = -1;
	for (int i = 0; i < MAX_P15_ADF; i++)
		mScP15Cards[i] = NULL;
}


OpenSCToken::~OpenSCToken()
{
	delete mSchema;
}


void OpenSCToken::didDisconnect()
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::didDisconnect()\n");
	PCSC::Card::didDisconnect();
}


void OpenSCToken::didEnd()
{
	return;
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::didEnd()\n");
	PCSC::Card::didEnd();
}

int OpenSCToken::get_objects(unsigned int type,
	struct sc_pkcs15_object **enum_objs, int ret_count)
{
	int rv, ii, obj_num = 0;
	for (ii = 0; ii < MAX_P15_ADF && (obj_num < ret_count); ii++)
	{
		if (!mScP15Cards[ii])
			break;
		rv = sc_pkcs15_get_objects(mScP15Cards[ii], type, enum_objs + obj_num, ret_count - obj_num);
		if (rv < 0) {
			return rv;
		}
		obj_num += rv;
	}

	return obj_num;
}


void OpenSCToken::changePIN(int pinNum,
const unsigned char *oldPin, size_t oldPinLength,
const unsigned char *newPin, size_t newPinLength)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::changePIN(%d)\n", pinNum);
	if (pinNum != 1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	if( _changePIN( pinNum, oldPin, oldPinLength, newPin, newPinLength ) ) {
		mCurrentPIN = pinNum;
		mLocked = false;
	}
	else {
		CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
	}

}


bool OpenSCToken:: _changePIN( int pinNum,
const unsigned char *oldPin, size_t oldPinLength,
const unsigned char *newPin, size_t newPinLength )
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::_changePIN(), PIN num is: %d\n", pinNum);

	int r, i, rv;
	struct sc_pkcs15_object *objs[32];

	// pinNum -> AuthID
	const sc_pkcs15_id_t *auth_id = getIdFromPinMap(pinNum);
	if (auth_id == NULL) {
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  ERR: getIdFromPinMap(): no AuthID found for pinNum %d\n", pinNum);
		CssmError::throwMe(CSSM_ERRCODE_INVALID_DATA);
	}

	// AuthID -> pin object  +  change pin
	r = get_objects(SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(pin_id=%s): %d\n", sc_pkcs15_print_id(auth_id),  r);
	if (r >= 0) {
		for (i = 0; i < r; i++) {
			sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) objs[i]->data;
			if (sc_pkcs15_compare_id(auth_id, &auth_info->auth_id)) {

				rv = sc_pkcs15_change_pin( objs[i]->p15card, objs[i], oldPin, oldPinLength, newPin, newPinLength );
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  In OpenSCToken::sc_pkcs15_change_pin returned %d for pin %d\n", rv, pinNum );
				if (rv==0)
					return true;
				else
					return false;
			}
		}
	}
	return false;
}


uint32_t OpenSCToken::pinStatus(int pinNum)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus for pinNum (%d)\n", pinNum);
    
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus for pinNum (%d)\n", pinNum);
    
    int r, i, rv;
    struct sc_pkcs15_object *objs[32];
    
    // pinNum -> AuthID
    const sc_pkcs15_id_t *auth_id = getIdFromPinMap(pinNum);
    if (auth_id == NULL) {
        sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL,
                 "  ERR: getIdFromPinMap(): no AuthID found for pinNum %d\n", pinNum);
        CssmError::throwMe(CSSM_ERRCODE_INVALID_DATA);
    }
    
    // AuthID -> pin object  +  change pin
    r = get_objects(SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(pin_id=%s): %d\n",
             sc_pkcs15_print_id(auth_id),  r);
    if (r >= 0) {
        for (i = 0; i < r; i++) {
            sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) objs[i]->data;
            if (sc_pkcs15_compare_id(auth_id, &auth_info->auth_id)) {
                
                rv = sc_pkcs15_get_pin_info( objs[i]->p15card, objs[i] );
                sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL,
                         "  In OpenSCToken::sc_pkcs15_get_pin_info returned %d for pin %d\n",
                         rv, pinNum );
                if (rv==0) {
                    struct sc_pkcs15_auth_info *pin_info = (struct sc_pkcs15_auth_info *) objs[i]->data;
                    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL,
                             "  In OpenSCToken::pinStatus() pin_info->logged_in = %d\n",
                             pin_info->logged_in );
                    switch (pin_info->logged_in) {
                        case SC_PIN_STATE_LOGGED_IN:
                            sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus Verified");
                            mLocked = false; // TODO: make sure it is OK (ulb)
                            return 0x9000;
                        case SC_PIN_STATE_LOGGED_OUT:
                            unverifyPIN(-1); // push pin status
                            sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus setting mLocked to true, called unverifyPIN()...");
                            sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus Logged out");
                            return 0x6300;
                        default:
                            // SC_PIN_CMD_GET_INFO is not implemented
                            sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus weird, pin_info->logged_in = %d", pin_info->logged_in);
                            break;
                    }
                    break;
                } else
                    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus weird, rv = %d", rv);
                break;
            }
        }
    }

    // SC_PIN_CMD_GET_INFO yielded an error or is not implemented
    // fall back to the old mechanism, which does not affect mLocked value
	if (pinNum == mCurrentPIN && !isLocked()) {
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus Verified");
		return 0x9000;
	}
   	else {
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::pinStatus blocked");
		return 0x6300;
	}
}


// does the token look as 'locked' for keychain ?
bool OpenSCToken::isLocked()
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::isLocked()\n");
	return mLocked;
}


void OpenSCToken::verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::verifyPIN(%d)\n", pinNum);
	int pNumber = pinNum;
	
	if (mScP15Cards[0] == NULL)
		CssmError::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);

        // If the user entered no PIN in the (OS) provided prompt; pinLength is
        // zero; but *pin points to the empty string; rather than being NULL.
        //
        // In the specific case that there is a PIN pad reader connected we
        // detect this; and used it to trigger a read of the PIN on the
        // PIN pad (which requires both pin == NULL and pinLength == 0).
        //
        if (mScP15Cards[0]->card->reader->capabilities & SC_READER_CAP_PIN_PAD
#ifdef SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH
				|| mScP15Cards[0]->card->caps & SC_CARD_CAP_PROTECTED_AUTHENTICATION_PATH
#endif
				) {
               if (pinLength == 0 || (pinLength == 1 && pin[0] == '\0')) {
                       sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "Defer PIN entry to the reader keypad.");
                       pin = NULL;
                       pinLength = 0;
               } else {
                       // We are not blocking key entry from the keyboard. As it is too late at
                       // this point - the user has already entered the PIN on the desktop its
                       // its keyboard. Longer term we could start honouring the flag
                       // CSSM_ACL_SUBJECT_TYPE_PROTECTED_PASSWORD.
                       //
                       sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "Warning: the reader keypad is not used; PIN entered on keyboard.");
               }
        };
	
	if (mCurrentPIN != -1) {
		pNumber = mCurrentPIN;
		mCurrentPIN = -1;
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  Activating workaround for PIN #%d\n", pNumber);
	}
	if (_verifyPIN(pNumber, pin, pinLength)) {
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  PIN verified\n");
		mCurrentPIN = pNumber;
		mLocked = false;
	}
	else {
		CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
	}

	// Start a new transaction which we never get rid of until someone calls
	// unverifyPIN()
}


bool OpenSCToken::_verifyPIN(int pinNum, const uint8_t *pin, size_t pinLength)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::_verifyPIN(), PIN num is: %d\n", pinNum);

	int r, i, rv;
	struct sc_pkcs15_object *objs[32];

	// pinNum -> AuthID
	const sc_pkcs15_id_t *auth_id = getIdFromPinMap(pinNum);
	if (auth_id == NULL) {
		sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  ERR: getIdFromPinMap(): no AuthID found for pinNum %d\n", pinNum);
		CssmError::throwMe(CSSM_ERRCODE_INVALID_DATA);
	}

	// AuthID -> pin object  +  verify pin
	r = get_objects(SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(pin_id=%s): %d\n", sc_pkcs15_print_id(auth_id),  r);
	if (r >= 0) {
		for (i = 0; i < r; i++) {
			sc_pkcs15_auth_info_t *pin_info = (sc_pkcs15_auth_info_t *) objs[i]->data;
			if (sc_pkcs15_compare_id(auth_id, &pin_info->auth_id)) {
				rv = sc_pkcs15_verify_pin(objs[i]->p15card, objs[i], pin, pinLength);
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  In OpenSCToken::verify returned %d for pin %d\n", rv, pinNum);
				if (rv==0)
					return true;
				else
					return false;
			}
		}
	}
	return false;
}


void OpenSCToken::unverifyPIN(int pinNum)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::unverifyPIN(%d)\n", pinNum);

	if (pinNum != -1)
		CssmError::throwMe(CSSM_ERRCODE_SAMPLE_VALUE_NOT_SUPPORTED);

	mCurrentPIN = pinNum;
	mLocked = true;
}

int OpenSCToken::opensc_bind(struct sc_app_info *app_info)
{
	struct sc_aid *aid = app_info ? &app_info->aid : NULL;
	int rc, idx;

	for (idx = 0; idx < 4; idx++)
		if (!mScP15Cards[idx])
			break;
	if (idx == 4)
		return SC_ERROR_NOT_ENOUGH_MEMORY;

	rc = sc_pkcs15_bind(mScCard, aid, &(mScP15Cards[idx]));

	return rc;
}


// We must recognize the token and create a (machine readable UID) if we can.
// A score of 0 means we can't handle the card; if multiple tokends can handle
//  the card then the one that returns the highest score is returned.
uint32 OpenSCToken::probe(SecTokendProbeFlags flags,
char tokenUid[TOKEND_MAX_UID])
{
	uint32 score = Tokend::ISO7816Token::probe(flags, tokenUid);

	// FIXME bool doDisconnect = true; /*!(flags & kSecTokendProbeKeepToken); */

	// Init OpenSC
	int r = sc_establish_context(&mScCtx, "tokend");
	if (r == 0) {
		// Which reader to use
		unsigned int idx;
		sc_reader_t *reader = NULL;

		const SCARD_READERSTATE &readerState = *(*startupReaderInfo)();
		for (idx = 0; idx < sc_ctx_get_reader_count(mScCtx); idx++) {

			reader = sc_ctx_get_reader(mScCtx, idx);
			if (!reader)
				return 0;

			if (strcmp(readerState.szReader, reader->name) == 0)
				break;
		}

		// Connect to the card
		if (idx < sc_ctx_get_reader_count(mScCtx)) {
			r = sc_connect_card(reader, &mScCard);
			sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_connect_card(): %d\n", r);
			if (r < 0) {
				sc_release_context(mScCtx);
				mScCtx = NULL;
			}
			else {
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  card: %s\n", mScCard->name);
                struct sc_app_info *app_generic;
                
                app_generic = sc_pkcs15_get_application_by_type(mScCard, "generic");
                if (app_generic)
                {
                    r = opensc_bind(app_generic);
                }

                if (r >= 0)
                {
                    for (int j = 0; j < mScCard->app_count; j++) {
                        struct sc_app_info *app_info = mScCard->app[j];
                        if (app_generic && app_generic == mScCard->app[j])
                            continue;

                        r = opensc_bind(app_info);
                        if (r != SC_SUCCESS) {
                            if (j == 0 && !app_generic)
                                break;
                            continue;
                        }
                    }
                }
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_bind(): %d\n", r);
				if (r == 0) {
					// get the score
					scconf_block *conf_block = NULL;
					conf_block = sc_get_conf_block(mScCtx, "framework", "tokend", 1);
					score = 300;
					if (conf_block != NULL) {
						score = scconf_get_int(conf_block, "score", score);
						sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  Get Score from config file: %d\n", score);
					}

					// Create a tokenUid - obscure the label somewhat as it is under
					// control of the card issuer; and could contain naughtyness.
					//
					unsigned char md[CC_SHA1_DIGEST_LENGTH];
					CC_SHA1_CTX ctx;
					CC_SHA1_Init(&ctx);
					CC_SHA1_Update(&ctx, mScP15Cards[0]->tokeninfo->label,
						strlen(mScP15Cards[0]->tokeninfo->label));
					CC_SHA1_Update(&ctx, mScP15Cards[0]->tokeninfo->serial_number,
						strlen(mScP15Cards[0]->tokeninfo->serial_number));
					CC_SHA1_Final(md, &ctx);

					std::ostringstream out;
					for (std::size_t i=0; i < MIN(TOKEND_MAX_UID/2,CC_SHA1_DIGEST_LENGTH); i++) {
						out << std::setfill('0') << std::setw(2) << std::hex << (short) md[i];
					}
					strlcpy(tokenUid,out.str().c_str(),TOKEND_MAX_UID);

					sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "    score = %d, tokenUid = \"%s\"\n", score, tokenUid);
				}
				sc_unlock(mScCard);
                
                if (r < 0)
                {
                    sc_disconnect_card(mScCard);
                    sc_release_context(mScCtx);
                    mScCtx = NULL;
                    mScCard = NULL;
                }
			}
		}
		else
			sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  err: reader \"%s\" not found by OpenSC\n", readerState.szReader);
	}

	return score;
}


void OpenSCToken::establish(const CSSM_GUID *guid, uint32 subserviceId,
SecTokendEstablishFlags flags, const char *cacheDirectory,
const char *workDirectory, char mdsDirectory[PATH_MAX],
char printName[PATH_MAX])
{
    bool useECC = false; // if we detect that this token has ECC keys, we create ECC-based schema
    // By default the created schema will be RSA
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::establish() -> we had the highest score\n");
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "      printName we received: \"%s\"\n", printName);
    
    if (mScP15Cards[0] == NULL)
        PCSC::Error::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);
    
    Tokend::ISO7816Token::establish(guid, subserviceId, flags,
                                    cacheDirectory, workDirectory, mdsDirectory, printName);
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  About to create schema\n");
    mSchema = new OpenSCSchema();
    mSchema->create();
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  Schema created, about to call populate()\n");
    
    populate();
    
    if (printName[0] != 0x0) { // i.e. if we succeeded filling it with something useful
        char *newName = (char *)malloc(PATH_MAX);
        memset(newName, 0, PATH_MAX);
        ::strlcpy(newName, printName, PATH_MAX);
        if (mScP15Cards[0]->tokeninfo->label != NULL)
            free(mScP15Cards[0]->tokeninfo->label);
        mScP15Cards[0]->tokeninfo->label = newName;
    } else {
        if (mScP15Cards[0]->tokeninfo->label)
            strcpy(printName, mScP15Cards[0]->tokeninfo->label);
        else
            strcpy(printName,"OpenSC Token");
    }
    
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  OpenSCToken::establish() final printName: %s\n", printName);
    sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  returning from OpenSCToken::establish()\n");
}


//
// Database-level ACLs
//
void OpenSCToken::getOwner(AclOwnerPrototype &owner)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::getOwner()\n");
	// we don't really know (right now), so claim we're owned by PIN #1
	if (!mAclOwner) {
		mAclOwner.allocator(Allocator::standard());
		mAclOwner = AclFactory::PinSubject(Allocator::standard(), 1);
	}
	owner = mAclOwner;
}


void OpenSCToken::getAcl(const char *tag, uint32 &count, AclEntryInfo *&acls)
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::getAcl() tag is: %s\n", tag);

	if (unsigned pin = pinFromAclTag(tag, "?")) {
		static AutoAclEntryInfoList acl;
        sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::getAcl() pin from tag is: %d\n", pin);
		acl.clear();
		acl.allocator(Allocator::standard());
		uint32_t status = this->pinStatus(pin);
		if (status == 0x9000)
			acl.addPinState(pin, CSSM_ACL_PREAUTH_TRACKING_AUTHORIZED);
		else
			// FIXME add support for propagating the number of retries via
			//acl.addPinState(pin, 0, RETRIES);
			acl.addPinState(pin, CSSM_ACL_PREAUTH_TRACKING_UNKNOWN);
		count = acl.size();
		acls = acl.entries();
		return;
	}

	// get pin list, then for each pin in the future
	if (!mAclEntries) {
		mAclEntries.allocator(Allocator::standard());
		// Anyone can read the attributes and data of any record on this token
		// (it's further limited by the object itself).
		mAclEntries.add(CssmClient::AclFactory::AnySubject(
			mAclEntries.allocator()),
			AclAuthorizationSet(CSSM_ACL_AUTHORIZATION_DB_READ, 0));

		mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 1);
		mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 1);
        mAclEntries.addPin(AclFactory::PWSubject(mAclEntries.allocator()), 2);
		mAclEntries.addPin(AclFactory::PromptPWSubject(mAclEntries.allocator(), CssmData()), 2);
	}
	count = mAclEntries.size();
	acls = mAclEntries.entries();
}


void  OpenSCToken::addToPinMap(const sc_pkcs15_id_t *id)
{
	if (getRefFromPinMap(id) != -1)
		// already added
		return;

	mPinMap.insert(make_pair(mPinCount++, id));
}


int OpenSCToken::getRefFromPinMap(const sc_pkcs15_id_t *id)
{
	map<int, const sc_pkcs15_id_t *>::const_iterator it;

	for (it = mPinMap.begin(); it != mPinMap.end(); it++) {
		if (sc_pkcs15_compare_id(id, it->second))
			return it->first;
	}
	// id not found
	return -1;
}


const sc_pkcs15_id_t * OpenSCToken::getIdFromPinMap(int pinNum)
{
	map<int, const sc_pkcs15_id_t *>::const_iterator it;

	for (it = mPinMap.begin(); it != mPinMap.end(); it++) {
		if (pinNum == it->first)
			return it->second;
	}
	// pinNum not found
	return NULL;
}


#pragma mark ---------------- OpenSC Specific --------------

void OpenSCToken::populate()
{
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCToken::populate()\n");

	// We work with certificates and private keys only
	Tokend::Relation &certRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_X509_CERTIFICATE);
	Tokend::Relation &privateKeyRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_PRIVATE_KEY);
	//Tokend::Relation &dataRelation = mSchema->findRelation(CSSM_DL_DB_RECORD_GENERIC);

	int r, i, j;
	const char *id;
	struct sc_pkcs15_object *objs[32];

	// Map from ID to certs.
	typedef std::map<sc_pkcs15_id_t *, RefPointer<Tokend::Record> > IdRecordMap;
	IdRecordMap mCertificates;

	// Map from ID to a count.
	// This is needed to check if a given RSA key was created with "--split-key" and act accordingly.
	typedef std::map<string, size_t> KeyCountMap;
	KeyCountMap mKeys;
	
	// Locate certificates
	//FIXME - max objects constant ?
	r = get_objects(SC_PKCS15_TYPE_CERT_X509, objs, 32);
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(TYPE_CERT_X509): %d\n", r);
	if (r >= 0) {
		for (i = 0; i < r; i++) {
			struct sc_pkcs15_cert_info *cert_info = (struct sc_pkcs15_cert_info *) objs[i]->data;
			//  get the actual record
            OpenSCCertificateRecord* certRecord = new OpenSCCertificateRecord(this, objs[i]);
            sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "    - %s (ID=%s)\n", objs[i]->label, sc_pkcs15_print_id(&cert_info->id));
            Tokend::Attribute* attr = certRecord->getDataAttribute((Tokend::TokenContext *) this);
            if (attr)
            {
                RefPointer<Tokend::Record> record(certRecord);
                // put it into certificates map
                // put into map
                mCertificates.insert(std::pair<sc_pkcs15_id_t *, RefPointer<Tokend::Record> >(&cert_info->id, record));
                // mark as certificate
                certRelation.insertRecord(record);
            }
            else
            {
                delete attr;
                delete certRecord;
                sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "      => Skipped because invalid\n");
            }
		}
	}

	// Locate private keys
	r = get_objects(SC_PKCS15_TYPE_PRKEY, objs, 32);
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(TYPE_PRKEY): %d\n", r);
	if (r >= 0) {
		
		// Count the occurences of the private key ids
		for (i = 0; i < r; i++) {
			sc_pkcs15_prkey_info_t *prkey_info = (sc_pkcs15_prkey_info_t *) objs[i]->data;
			id = sc_pkcs15_print_id(&prkey_info->id);
			mKeys[id]++;
		}
				
		// Add the keys
		for (i = 0; i < r; i++) {
			
			RefPointer<Tokend::Record> record;
            OpenSCKeyRecord* keyRecord = NULL;
			sc_pkcs15_prkey_info_t *prkey_info = (sc_pkcs15_prkey_info_t *) objs[i]->data;
			id = sc_pkcs15_print_id(&prkey_info->id);
			
			// regular key
			if (mKeys[id] == 1) {
				keyRecord = new OpenSCKeyRecord(this, objs[i], privateKeyRelation.metaRecord());
				
			// split key
			} else if (mKeys[id] == 2) {
				// find the other "half" of this key
				for (j = i + 1; j < r; j++) { 
					sc_pkcs15_prkey_info_t *sibling_info = (sc_pkcs15_prkey_info_t *) objs[j]->data;
					if (sc_pkcs15_compare_id(&sibling_info->id, &prkey_info->id)) {
						keyRecord = new OpenSCKeyRecord(this, objs[i], objs[j], privateKeyRelation.metaRecord());
						mKeys[id] = 0;
						break;
					}
				}
				
				// if we didn't find the key, abort
				if (j >= r)
					PCSC::Error::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);
			} else
				continue;
			
			// put it into prkey map
			sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "    - %s (ID=%s)\n", objs[i]->label, sc_pkcs15_print_id(&prkey_info->id));
			

			// do the bind between the key and a cert
			IdRecordMap::const_iterator it;
			for (it = mCertificates.begin(); it != mCertificates.end(); it++) {
				if (sc_pkcs15_compare_id(it->first, &prkey_info->id))
					break;
			}
			if (it == mCertificates.end())
            {
                delete keyRecord;
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "        no certificate found for this key.Skipped\n");
            }
			else {
                record = keyRecord;
                privateKeyRelation.insertRecord(record);
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "        linked this key to cert \"%s\"\n", it->second->description());
				record->setAdornment(mSchema->publicKeyHashCoder().certificateKey(),
					new Tokend::LinkedRecordAdornment(it->second));
			}

		}
	}

	// Get the PIN(s) and put their ID in the mPinMap. This way we get
	// a unique int as a reference to each PIN (ID), this has to be
	// returned in the OpenSCKeyRecord::getAcl() method.
	r = get_objects(SC_PKCS15_TYPE_AUTH_PIN, objs, 32);
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_get_objects(TYPE_AUTH_PIN): %d\n", r);
	if (r>0) {
		for (i = 0; i < r; i++) {
			sc_pkcs15_auth_info_t *pin_info = (sc_pkcs15_auth_info_t *) objs[i]->data;
			if ((pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN) ||
			(pin_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_UNBLOCKING_PIN)) {
				sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "    ignored non-user pin with ID=%s\n", sc_pkcs15_print_id(&pin_info->auth_id));
				continue;
			}
			addToPinMap(&pin_info->auth_id);
			sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "    added pin with ID=%s to the pinmap\n", sc_pkcs15_print_id(&pin_info->auth_id));
		}
	}
	sc_debug(mScCtx, SC_LOG_DEBUG_NORMAL, "  returning from OpenSCToken::populate()\n");
}
