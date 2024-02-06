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

#include "OpenSCKeyHandle.h"

#include "OpenSCRecord.h"
#include "OpenSCToken.h"

#include <security_utilities/debugging.h>
#include <security_utilities/utilities.h>
#include <security_cdsa_utilities/cssmerrors.h>
#include <Security/cssmerr.h>
#include <Security/cssmapple.h>

#include "libopensc/log.h"
/************************** OpenSCKeyHandle ************************/

OpenSCKeyHandle::OpenSCKeyHandle(OpenSCToken &OpenSCToken,
const Tokend::MetaRecord &metaRecord, OpenSCKeyRecord &cacKey) :
Tokend::KeyHandle(metaRecord, &cacKey),
mToken(OpenSCToken), mKey(cacKey)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle:: OpenSCKeyHandle()\n");
}


OpenSCKeyHandle::~OpenSCKeyHandle()
{
}


void OpenSCKeyHandle::getKeySize(CSSM_KEY_SIZE &keySize)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::getKeySize()\n", keySize);
	secdebug("crypto", "getKeySize");
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);/*
    size_t len = mKey.sizeInBits();
	keySize.LogicalKeySizeInBits = len;
	keySize.EffectiveKeySizeInBits = len;
    sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  returned %d\n", (uint32) len);*/
}


uint32 OpenSCKeyHandle::getOutputSize(const Context &context,
uint32 inputSize, bool encrypting)
{
    uint32 outputSize = 0;
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::geOutputSize()\n");
	secdebug("crypto", "getOutputSize");
    CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
    return 0;
	/*if (encrypting)
		CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
    if (mKey.isRSA())
        outputSize = (uint32) ((mKey.sizeInBits() + 7) / 8);
    else
        outputSize = (uint32) 2 * ((mKey.sizeInBits() + 7) / 8);
    
    sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  returned %d\n", outputSize);
    return outputSize;*/
}


void OpenSCKeyHandle::generateSignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, CssmData &signature)
{
	// for sc_pkcs15_compute_signature()
	unsigned int flags = 0;
    int rv = 0;
    unsigned char *outputData = NULL;
    bool bIsRsa = (mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_RSA);
    bool bIsEcc = (mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_EC);

	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::generateSignature()\n");

	if (context.type() == CSSM_ALGCLASS_SIGNATURE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  type == CSSM_ALGCLASS_SIGNATURE\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown type: 0x%0x, exiting\n", context.type());
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);
	}

	if (context.algorithm() == CSSM_ALGID_RSA) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  algorithm == CSSM_ALGID_RSA\n");
	}
	else if (context.algorithm() == CSSM_ALGID_ECDSA) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  algorithm == CSSM_ALGID_ECDSA\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown algorithm: 0x%0x, exiting\n", context.algorithm());
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
	}

	if (signOnly == CSSM_ALGID_SHA1) {

		if (input.Length != 20)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);

		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA1, length is 20\n");
	}
	else if (signOnly == CSSM_ALGID_SHA256) {
        
		if (input.Length != 32)
        {
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  SHA256 specified but length is %d\n", input.Length);
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		}

		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA256, length is 32\n");
	}
	else if (signOnly == CSSM_ALGID_SHA384) {
        
		if (input.Length != 46)
        {
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  SHA384 specified but length is %d\n", input.Length);
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		}

		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA384, length is 48\n");
	}
	else if (signOnly == CSSM_ALGID_SHA512) {
        
		if (input.Length != 64)
        {
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  SHA512 specified but length is %d\n", input.Length);
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);
		}
 
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using SHA512, length is 64\n");
	}
	else if (signOnly == CSSM_ALGID_MD5) {
		if (input.Length != 16)
			CssmError::throwMe(CSSMERR_CSP_BLOCK_SIZE_MISMATCH);

		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Using MD5, length is 16\n");

	}
	else if (signOnly == CSSM_ALGID_NONE) {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO digest (perhaps for SSL authentication)\n");
	}
	else {
		sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown signOnly value: 0x%0x, exiting\n", signOnly);
		CssmError::throwMe(CSSMERR_CSP_INVALID_DIGEST_ALGORITHM);
	}
    
    
    // Consistency validation - necessary for MS Outlook 2011 that seems
    // to ask for RSA signatures with EC keys.
    if ((context.algorithm() == CSSM_ALGID_ECDSA &&
         mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_RSA) ||
        (context.algorithm() == CSSM_ALGID_RSA &&
         mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_EC))
    {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL,
                 "  Illegal combination of key type %s and requested algorithm %s\n",
                 (const char *)(mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_RSA?
                                "PRKEY_RSA" : "PRKEY_EC"),
                 (const char *)(context.algorithm() == CSSM_ALGID_ECDSA? "EDCSA" : "RSA")
                 );
        
        if (context.algorithm() == CSSM_ALGID_ECDSA &&
             mKey.signKey()->type == SC_PKCS15_TYPE_PRKEY_RSA)
            CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);
    }
    
    // Get padding, but default to pkcs1 style padding for RSA
    uint32 padding = context.getInt(CSSM_ATTRIBUTE_PADDING);
    if (padding == CSSM_PADDING_PKCS1) {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Input: PKCS#1 padding\n");
    }
    else if (padding == CSSM_PADDING_NONE) {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Input: NO padding\n");
    }
    else {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Input: Unknown padding 0x%0x, exiting\n", padding);
    }
    
    if (bIsRsa) {
        if (signOnly == CSSM_ALGID_NONE)
            // For SSL authentication padding must be NONE
            padding = CSSM_PADDING_NONE;
        else
            padding = CSSM_PADDING_PKCS1;
    }
    else if (bIsEcc) {
        padding = CSSM_PADDING_NONE;
    }
    
    if (padding == CSSM_PADDING_PKCS1) {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  PKCS#1 padding\n");
        flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
    }
    else if (padding == CSSM_PADDING_NONE) {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  NO padding\n");
        flags &= ~SC_ALGORITHM_RSA_PAD_PKCS1; // Make sure it isn't set
    }
    else {
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Unknown padding 0x%0x, exiting\n", padding);
        CssmError::throwMe(CSSMERR_CSP_INVALID_ATTR_PADDING);
    }

    if (bIsRsa) {

        size_t keyLength = (mKey.sizeInBits() + 7) / 8;
        
        flags |= SC_ALGORITHM_RSA_HASH_NONE;
        if (padding == CSSM_PADDING_NONE && (input.Length < keyLength))
            flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
        // @@@ Switch to using tokend allocators
        outputData =
            reinterpret_cast<unsigned char *>(malloc(keyLength));
        if (outputData == NULL)
            CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Signing buffers: inlen=%d, outlen=%d\n",input.Length, keyLength);
        // Call OpenSC to do the actual signing
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_compute_signature(): rv = %d\n", rv);
        if ((flags & SC_ALGORITHM_RSA_PAD_PKCS1) && ((signOnly == CSSM_ALGID_MD5) || (signOnly == CSSM_ALGID_SHA1) || (signOnly == CSSM_ALGID_SHA256) || (signOnly == CSSM_ALGID_SHA384) || (signOnly == CSSM_ALGID_SHA512)))
        {
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "Using standard PKCS#1 signature\n");

            
            static unsigned char MD5_HEADER[18] = {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10};
            static unsigned char SHA_1_HEADER[15] = {0x30, 0x21, 0x30 ,0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
            static unsigned char SHA_256_HEADER[19] = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
            static unsigned char SHA_384_HEADER[19] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
            static unsigned char SHA_512_HEADER[19] = {0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
            
            size_t inputDataOffset = (signOnly == CSSM_ALGID_SHA1)? 15: (signOnly == CSSM_ALGID_MD5)? 18: 19;
            size_t paddedInputLength = input.Length + inputDataOffset;
            unsigned char *paddedInputData = reinterpret_cast<unsigned char *>(malloc(paddedInputLength));
            if (paddedInputData == NULL)
            {
                free(outputData);
                CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);
            }

            switch (signOnly) {
                case CSSM_ALGID_MD5:
                    memcpy (paddedInputData,MD5_HEADER,18);
                    break;
                    case CSSM_ALGID_SHA1:
                    memcpy (paddedInputData,SHA_1_HEADER,15);
                    break;
                    case CSSM_ALGID_SHA256:
                    memcpy (paddedInputData,SHA_256_HEADER,19);
                    break;
                    case CSSM_ALGID_SHA384:
                    memcpy (paddedInputData,SHA_384_HEADER,19);
                    break;
                    case CSSM_ALGID_SHA512:
                    memcpy (paddedInputData,SHA_512_HEADER,19);
                    break;
                default:
                    break;
            }
            memcpy (paddedInputData + inputDataOffset, input.Data, input.Length);
            
            rv = sc_pkcs15_compute_signature(mKey.signKey()->p15card, mKey.signKey(), flags, paddedInputData, paddedInputLength, outputData, keyLength);
            free(paddedInputData);
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_compute_signature(): rv = %d\n", rv);
        }
        else
        {
            rv = sc_pkcs15_compute_signature(mKey.signKey()->p15card, mKey.signKey(), flags, input.Data, input.Length, outputData, keyLength);
        }
    }
    else {
        size_t sigLength = 2 * ((mKey.sizeInBits() + 7) / 8);
        // @@@ Switch to using tokend allocators
        outputData =
            reinterpret_cast<unsigned char *>(malloc(sigLength));
        if (outputData == NULL)
            CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);
        
        flags = SC_ALGORITHM_ECDSA_HASH_NONE | SC_ALGORITHM_ECDSA_RAW;

        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  Signing buffers: inlen=%d, outlen=%d\n",input.Length, sigLength);
        // Call OpenSC to do the actual signing
        rv = sc_pkcs15_compute_signature(mKey.signKey()->p15card,
            mKey.signKey(), flags, input.Data, input.Length, outputData, sigLength);
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_compute_signature(): rv = %d\n", rv);
    }

	if (rv < 0) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}
    
    if (bIsRsa)
    {
        // For RSA just pass along the return of sc_pkcs15_compute_signature()
        signature.Data = outputData;
        signature.Length = rv;
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL,
                 "  Completed RSA signature, len=%d\n", rv);
    } else {
        // For ECDSA wrap the result of compute_signature() as ASN.1 SEQUENCE
        unsigned char *seq;
        size_t seqlen;
        if (sc_asn1_sig_value_rs_to_sequence(mToken.mScCtx,
                                             outputData, rv,
                                             &seq, &seqlen))
        {
            sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL,
                     "Failed to convert signature to ASN1 sequence format.\n");
            free(outputData);
            CssmError::throwMe(CSSMERR_CSP_INVALID_OUTPUT_VECTOR);
        }
        free(outputData);
        signature.Data = reinterpret_cast<unsigned char *>(malloc(seqlen));
        if (signature.Data == NULL)
            CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);
        signature.Length = seqlen;
        memcpy(signature.Data, seq, seqlen);
        free(seq);
        sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL,
                 "  Converted ECDSA signature to ASN.1 SEQUENCE: seqlen=%d\n",
                 seqlen);
    }
}


void OpenSCKeyHandle::verifySignature(const Context &context,
CSSM_ALGORITHMS signOnly, const CssmData &input, const CssmData &signature)
{
	secdebug("crypto", "verifySignature");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::generateMac(const Context &context,
const CssmData &input, CssmData &output)
{
	secdebug("crypto", "generateMac");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::verifyMac(const Context &context,
const CssmData &input, const CssmData &compare)
{
	secdebug("crypto", "verifyMac");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::encrypt(const Context &context,
const CssmData &clear, CssmData &cipher)
{
	secdebug("crypto", "encrypt");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


void OpenSCKeyHandle::decrypt(const Context &context,
const CssmData &cipher, CssmData &clear)
{
	secdebug("crypto", "decrypt alg: %lu", (long unsigned int) context.algorithm());
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "In OpenSCKeyHandle::decrypt(ciphertext length = %d)\n", cipher.Length);

	if (context.type() != CSSM_ALGCLASS_ASYMMETRIC)
		CssmError::throwMe(CSSMERR_CSP_INVALID_CONTEXT);

	if (context.algorithm() != CSSM_ALGID_RSA)
		CssmError::throwMe(CSSMERR_CSP_INVALID_ALGORITHM);

	// @@@ Switch to using tokend allocators
	unsigned char *outputData =
		reinterpret_cast<unsigned char *>(malloc(cipher.Length));
	if (outputData == NULL)
		CssmError::throwMe(CSSMERR_CSP_MEMORY_ERROR);

	// Call OpenSC to do the actual decryption
	int rv = sc_pkcs15_decipher(mKey.decryptKey()->p15card,
		mKey.decryptKey(), SC_ALGORITHM_RSA_PAD_PKCS1,
		cipher.Data, cipher.Length, outputData, cipher.Length);
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  sc_pkcs15_decipher(): rv = %d\n", rv);
	if (rv < 0) {
		free(outputData);
		CssmError::throwMe(CSSMERR_CSP_FUNCTION_FAILED);
	}
	clear.Data = outputData;
	clear.Length = rv;

	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "  decrypt(): returning with %d decrypted bytes\n", clear.Length);
}


void OpenSCKeyHandle::exportKey(const Context &context,
const AccessCredentials *cred, CssmKey &wrappedKey)
{
	sc_debug(mToken.mScCtx, SC_LOG_DEBUG_NORMAL, "exportKey");
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
}


/********************** OpenSCKeyHandleFactory *********************/

OpenSCKeyHandleFactory::~OpenSCKeyHandleFactory()
{
}


Tokend::KeyHandle *OpenSCKeyHandleFactory::keyHandle(
Tokend::TokenContext *tokenContext, const Tokend::MetaRecord &metaRecord,
Tokend::Record &record) const
{
	OpenSCKeyRecord &key = dynamic_cast<OpenSCKeyRecord &>(record);
	OpenSCToken &openSCToken = static_cast<OpenSCToken &>(*tokenContext);
	return new OpenSCKeyHandle(openSCToken, metaRecord, key);
}
