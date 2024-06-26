/*
 * pkcs15-sec.c: PKCS#15 cryptography functions
 *
 * Copyright (C) 2001, 2002  Juha Yrjölä <juha.yrjola@iki.fi>
 * Copyright (C) 2007        Nils Larsch <nils@larsch.net>
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

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "internal.h"
#include "pkcs15.h"

static int select_key_file(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_prkey_info *prkey,
		sc_security_env_t *senv)
{
	sc_context_t *ctx = p15card->card->ctx;
	sc_path_t path, file_id;
	int r;

	LOG_FUNC_CALLED(ctx);

	memset(&path, 0, sizeof(sc_path_t));
	memset(&file_id, 0, sizeof(sc_path_t));

	/* TODO: Why file_app may be NULL -- at least 3F00 has to be present?
	 * Check validity of the following assumption. */
	/* For pkcs15-emulated cards, the file_app may be NULL,
	 * in that case we always assume an absolute path */
	if (!prkey->path.len && prkey->path.aid.len) {
		/* Private key is a SDO allocated in application DF */
		path = prkey->path;
	}
	else if (prkey->path.len == 2 && p15card->file_app != NULL) {
		/* Path is relative to app. DF */
		path = p15card->file_app->path;
		file_id = prkey->path;
		sc_append_path(&path, &file_id);
		senv->file_ref = file_id;
		senv->flags |= SC_SEC_ENV_FILE_REF_PRESENT;
	}
	else if (prkey->path.len > 2) {
		path = prkey->path;
		memcpy(file_id.value, prkey->path.value + prkey->path.len - 2, 2);
		file_id.len = 2;
		file_id.type = SC_PATH_TYPE_FILE_ID;
		senv->file_ref = file_id;
		senv->flags |= SC_SEC_ENV_FILE_REF_PRESENT;
	}
	else {
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "invalid private key path");
	}

	r = sc_select_file(p15card->card, &path, NULL);
	LOG_TEST_RET(ctx, r, "sc_select_file() failed");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

static int use_key(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_object *obj,
		sc_security_env_t *senv,
		int (*card_command)(sc_card_t *card,
			 const u8 * in, size_t inlen,
			 u8 * out, size_t outlen),
		const u8 * in, size_t inlen, u8 * out, size_t outlen)
{
	int r = SC_SUCCESS;
	int revalidated_cached_pin = 0;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;

	r = sc_lock(p15card->card);
	LOG_TEST_RET(p15card->card->ctx, r, "sc_lock() failed");

	do {
		if (prkey->path.len != 0 || prkey->path.aid.len != 0) {
			r = select_key_file(p15card, prkey, senv);
			if (r < 0) {
				sc_log(p15card->card->ctx,
						"Unable to select private key file");
			}
		}
		if (r == SC_SUCCESS)
			r = sc_set_security_env(p15card->card, senv, 0);

		if (r == SC_SUCCESS)
			r = card_command(p15card->card, in, inlen, out, outlen);

		if (revalidated_cached_pin)
			/* only re-validate once */
			break;
		if (r == SC_ERROR_SECURITY_STATUS_NOT_SATISFIED) {
			r = sc_pkcs15_pincache_revalidate(p15card, obj);
			if (r < 0)
				break;
			revalidated_cached_pin = 1;
		}
	} while (revalidated_cached_pin);

	sc_unlock(p15card->card);

	return r;
}

static int format_senv(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_object *obj,
		sc_security_env_t *senv_out, sc_algorithm_info_t **alg_info_out)
{
	sc_context_t *ctx = p15card->card->ctx;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	int ii, jj;

	memset(senv_out, 0, sizeof(*senv_out));

	/* Card driver should have the access to supported algorithms from 'tokenInfo'. So that
	 * it can get value of card specific 'AlgorithmInfo::algRef'. */
	memcpy(senv_out->supported_algos, &p15card->tokeninfo->supported_algos, sizeof(senv_out->supported_algos));

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PRKEY)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "This is not a private key");

	for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
	{
		if (prkey->algo_refs[ii] == 0)
			break;
		for (jj = 0; jj < SC_MAX_SUPPORTED_ALGORITHMS; jj++)
		{
			if (prkey->algo_refs[ii] == senv_out->supported_algos[jj].reference)
			{
				senv_out->key_mechanisms[ii] = senv_out->supported_algos[jj].mechanism;
				break;
			}
		}

		if (jj == SC_MAX_SUPPORTED_ALGORITHMS)
			break;
	}	

	/* If the key is not native, we can't operate with it. */
	if (!prkey->native)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "This key is not native, cannot operate with it");

	switch (obj->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			*alg_info_out = sc_card_find_rsa_alg(p15card->card, prkey->modulus_length);
			if (*alg_info_out == NULL) {
				sc_log(ctx,
				       "Card does not support RSA with key length %"SC_FORMAT_LEN_SIZE_T"u",
				       prkey->modulus_length);
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}
			senv_out->algorithm = SC_ALGORITHM_RSA;
			break;

		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
			*alg_info_out = sc_card_find_gostr3410_alg(p15card->card, prkey->modulus_length);
			if (*alg_info_out == NULL) {
				sc_log(ctx,
				       "Card does not support GOSTR3410 with key length %"SC_FORMAT_LEN_SIZE_T"u",
				       prkey->modulus_length);
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}
			senv_out->algorithm = SC_ALGORITHM_GOSTR3410;
			break;

		case SC_PKCS15_TYPE_PRKEY_EC:
			*alg_info_out = sc_card_find_ec_alg(p15card->card, prkey->field_length, NULL);
			if (*alg_info_out == NULL) {
				sc_log(ctx,
				       "Card does not support EC with field_size %"SC_FORMAT_LEN_SIZE_T"u",
				       prkey->field_length);
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}
			senv_out->algorithm = SC_ALGORITHM_EC;

			senv_out->flags |= SC_SEC_ENV_ALG_REF_PRESENT;
			senv_out->algorithm_ref = prkey->field_length;
			break;
			/* add other crypto types here */
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Key type not supported");
	}
	senv_out->flags |= SC_SEC_ENV_ALG_PRESENT;

	senv_out->key_length = (*alg_info_out)->key_length;
	senv_out->non_repudiation = (prkey->usage & SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)? 1 : 0;

	/* optional keyReference attribute (the default value is -1) */
	if (prkey->key_reference >= 0) {
		senv_out->key_ref_len = 1;
		senv_out->key_ref[0] = prkey->key_reference & 0xFF;
		senv_out->flags |= SC_SEC_ENV_KEY_REF_PRESENT;
	}

	return SC_SUCCESS;
}
 
int sc_pkcs15_decipher(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_object *obj,
		unsigned long flags,
		const u8 * in, size_t inlen, u8 *out, size_t outlen)
{
	sc_context_t *ctx = p15card->card->ctx;
	int r;
	sc_algorithm_info_t *alg_info = NULL;
	sc_security_env_t senv;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	unsigned long pad_flags = 0, sec_flags = 0;

	LOG_FUNC_CALLED(ctx);
	
	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_DECRYPT|SC_PKCS15_PRKEY_USAGE_UNWRAP)))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "This key cannot be used for decryption");

	r = format_senv(p15card, obj, &senv, &alg_info);
	LOG_TEST_RET(ctx, r, "Could not initialize security environment");
	senv.operation = SC_SEC_OPERATION_DECIPHER;

	r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
	LOG_TEST_RET(ctx, r, "cannot encode security operation flags");
	senv.algorithm_flags = sec_flags;

	r = use_key(p15card, obj, &senv, sc_decipher, in, inlen, out,
			outlen);
	LOG_TEST_RET(ctx, r, "use_key() failed");

	/* Strip any padding */
	if (pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		size_t s = r;
		r = sc_pkcs1_strip_02_padding(ctx, out, s, out, &s);
		LOG_TEST_RET(ctx, r, "Invalid PKCS#1 padding");
	}

	LOG_FUNC_RETURN(ctx, r);
}

/* derive one key from another. RSA can use decipher, so this is for only ECDH
 * Since the value may be returned, and the call is expected to provide
 * the buffer, we used the PKCS#11 convention of outlen == 0 and out == NULL
 * to indicate that this is a request for the size.
 * In that case r = 0, and *poutlen = expected size
 */
int sc_pkcs15_derive(struct sc_pkcs15_card *p15card,
		const struct sc_pkcs15_object *obj,
		unsigned long flags,
		const u8 * in, size_t inlen, u8 *out,
		unsigned long *poutlen)
{
	sc_context_t *ctx = p15card->card->ctx;
	int r;
	sc_algorithm_info_t *alg_info = NULL;
	sc_security_env_t senv;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	unsigned long pad_flags = 0, sec_flags = 0;

	LOG_FUNC_CALLED(ctx);

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_DERIVE)))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "This key cannot be used for derivation");

	switch (obj->type) {
		case SC_PKCS15_TYPE_PRKEY_EC:
			if (out == NULL || *poutlen < (prkey->field_length + 7) / 8) {
				*poutlen = (prkey->field_length + 7) / 8;
				r = 0; /* say no data to return */
				LOG_FUNC_RETURN(ctx, r);
			}
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED,"Key type not supported");
	}

	r = format_senv(p15card, obj, &senv, &alg_info);
	LOG_TEST_RET(ctx, r, "Could not initialize security environment");
	senv.operation = SC_SEC_OPERATION_DERIVE;

	r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
	LOG_TEST_RET(ctx, r, "cannot encode security operation flags");
	senv.algorithm_flags = sec_flags;

	r = use_key(p15card, obj, &senv, sc_decipher, in, inlen, out,
			*poutlen);
	LOG_TEST_RET(ctx, r, "use_key() failed");

	/* Strip any padding */
	if (pad_flags & SC_ALGORITHM_RSA_PAD_PKCS1) {
		size_t s = r;
		r = sc_pkcs1_strip_02_padding(ctx, out, s, out, &s);
		LOG_TEST_RET(ctx, r, "Invalid PKCS#1 padding");
	}

	/* If card stores derived key on card, then no data is returned
	 * and the key must be used on the card. */
	*poutlen = r;
	LOG_FUNC_RETURN(ctx, r);
}

/* copied from pkcs15-cardos.c */
#define USAGE_ANY_SIGN          (SC_PKCS15_PRKEY_USAGE_SIGN|\
                                 SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)
#define USAGE_ANY_DECIPHER      (SC_PKCS15_PRKEY_USAGE_DECRYPT|\
                                 SC_PKCS15_PRKEY_USAGE_UNWRAP)

int sc_pkcs15_compute_signature(struct sc_pkcs15_card *p15card,
				const struct sc_pkcs15_object *obj,
				unsigned long flags, const u8 *in, size_t inlen,
				u8 *out, size_t outlen)
{
	sc_context_t *ctx = p15card->card->ctx;
	int r;
	sc_security_env_t senv;
	sc_algorithm_info_t *alg_info;
	const struct sc_pkcs15_prkey_info *prkey = (const struct sc_pkcs15_prkey_info *) obj->data;
	u8 buf[1024], *tmp;
	size_t modlen;
	unsigned long pad_flags = 0, sec_flags = 0;

	LOG_FUNC_CALLED(ctx);

	if (!(prkey->usage & (SC_PKCS15_PRKEY_USAGE_SIGN|SC_PKCS15_PRKEY_USAGE_SIGNRECOVER|
					SC_PKCS15_PRKEY_USAGE_NONREPUDIATION)))
		LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "This key cannot be used for signing");

	r = format_senv(p15card, obj, &senv, &alg_info);
	LOG_TEST_RET(ctx, r, "Could not initialize security environment");
	senv.operation = SC_SEC_OPERATION_SIGN;

	switch (obj->type) {
		case SC_PKCS15_TYPE_PRKEY_RSA:
			modlen = prkey->modulus_length / 8;
			break;
		case SC_PKCS15_TYPE_PRKEY_GOSTR3410:
			modlen = (prkey->modulus_length + 7) / 8 * 2;
			break;
		case SC_PKCS15_TYPE_PRKEY_EC:
			modlen = ((prkey->field_length +7) / 8) * 2;  /* 2*nLen */ 
			break;
		default:
			LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "Key type not supported");
	}

	/* Probably never happens, but better make sure */
	if (inlen > sizeof(buf) || outlen < modlen)
		LOG_FUNC_RETURN(ctx, SC_ERROR_BUFFER_TOO_SMALL);

	memcpy(buf, in, inlen);

	/* revert data to sign when signing with the GOST key.
	 * TODO: can it be confirmed by the GOST standard?
	 * TODO: tested with RuTokenECP, has to be validated for RuToken. */
	if (obj->type == SC_PKCS15_TYPE_PRKEY_GOSTR3410)   {
		r = sc_mem_reverse(buf, inlen);
		LOG_TEST_RET(ctx, r, "Reverse memory error");
	}

	tmp = buf;

	/* flags: the requested algo
	 * algo_info->flags: what is supported by the card
	 * senv.algorithm_flags: what the card will have to do */

	/* if the card has SC_ALGORITHM_NEED_USAGE set, and the
	 * key is for signing and decryption, we need to emulate signing */
	/* TODO: -DEE assume only RSA keys will ever use _NEED_USAGE */

	sc_log(ctx, "supported algorithm flags 0x%X, private key usage 0x%X", alg_info->flags, prkey->usage);
	if ((alg_info->flags & SC_ALGORITHM_NEED_USAGE) &&
		((prkey->usage & USAGE_ANY_SIGN) &&
		(prkey->usage & USAGE_ANY_DECIPHER)) ) {
		size_t tmplen = sizeof(buf);
		if (flags & SC_ALGORITHM_RSA_RAW) {
			r = sc_pkcs15_decipher(p15card, obj,flags, in, inlen, out, outlen);
			LOG_FUNC_RETURN(ctx, r);
		}
		if (modlen > tmplen)
			LOG_TEST_RET(ctx, SC_ERROR_NOT_ALLOWED, "Buffer too small, needs recompile!");

		r = sc_pkcs1_encode(ctx, flags, in, inlen, buf, &tmplen, modlen);

		/* no padding needed - already done */
		flags &= ~SC_ALGORITHM_RSA_PADS;
		/* instead use raw rsa */
		flags |= SC_ALGORITHM_RSA_RAW;

		LOG_TEST_RET(ctx, r, "Unable to add padding");

		r = sc_pkcs15_decipher(p15card, obj,flags, buf, modlen, out, outlen);
		LOG_FUNC_RETURN(ctx, r);
	}


	/* If the card doesn't support the requested algorithm, we normally add the
	 * padding here in software and ask the card to do a raw signature.  There's
	 * one exception to that, where we might be able to get the signature to
	 * succeed by stripping padding if the card only offers higher-level
	 * signature operations.  The only thing we can strip is the DigestInfo
	 * block from PKCS1 padding. */
	if ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE)) &&
	    !(alg_info->flags & SC_ALGORITHM_RSA_RAW) &&
	    !(alg_info->flags & (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE))) {
		unsigned int algo;
		size_t tmplen = sizeof(buf);

		r = sc_pkcs1_strip_digest_info_prefix(&algo, tmp, inlen, tmp, &tmplen);
		if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE) {
			sc_mem_clear(buf, sizeof(buf));
			LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_DATA);
		}
		flags &= ~SC_ALGORITHM_RSA_HASH_NONE;
		flags |= algo;
		inlen = tmplen;
	}
    
	/* If the card doesn't support RAW RSA, check if we can use PKCS#1 instead */
	if ((senv.algorithm == SC_ALGORITHM_RSA) && (flags == (SC_ALGORITHM_RSA_HASH_NONE)) && !(alg_info->flags & (SC_ALGORITHM_RSA_RAW))) {
		size_t tmplen = sizeof(buf);
        
		r = sc_pkcs1_strip_01_padding(ctx, tmp, inlen, tmp, &tmplen);
		if (r == SC_SUCCESS) {
            flags |= SC_ALGORITHM_RSA_PAD_PKCS1;
            inlen = tmplen;
		}
	}

	/* if RSA_PKCS requested but the key support only SHAX_RSA_PKCS, see if
	 * we can strip input to match SHAX_RSA_PKCS mechanism */
	if ((flags == (SC_ALGORITHM_RSA_PAD_PKCS1 | SC_ALGORITHM_RSA_HASH_NONE))
		&& (senv.algorithm == SC_ALGORITHM_RSA)
		)
	{
		int rsa_pkcs_supported = 0, ii;
		for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
		{
			if (senv.key_mechanisms[ii] == 0)
				break;
			if (senv.key_mechanisms[ii] == CKM_RSA_PKCS)
			{
				rsa_pkcs_supported = 1;
				break;
			}
		}

		if (!rsa_pkcs_supported)
		{
			unsigned int algo;
			size_t tmplen = sizeof(buf);
			int algo_supported = 0;

			r = sc_pkcs1_strip_digest_info_prefix(&algo, tmp, inlen, NULL, &tmplen);
			if (r != SC_SUCCESS || algo == SC_ALGORITHM_RSA_HASH_NONE) {
				sc_mem_clear(buf, sizeof(buf));
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}

			for (ii = 0; ii < SC_MAX_SUPPORTED_ALGORITHMS; ii++)
			{
				if (senv.key_mechanisms[ii] == 0)
					break;
				if (	((senv.key_mechanisms[ii] == CKM_SHA1_RSA_PKCS) && (algo == SC_ALGORITHM_RSA_HASH_SHA1))
					||	((senv.key_mechanisms[ii] == CKM_SHA256_RSA_PKCS) && (algo == SC_ALGORITHM_RSA_HASH_SHA256))
					||	((senv.key_mechanisms[ii] == CKM_SHA384_RSA_PKCS) && (algo == SC_ALGORITHM_RSA_HASH_SHA384))
					||	((senv.key_mechanisms[ii] == CKM_SHA512_RSA_PKCS) && (algo == SC_ALGORITHM_RSA_HASH_SHA512))
					||	((senv.key_mechanisms[ii] == CKM_SHA224_RSA_PKCS) && (algo == SC_ALGORITHM_RSA_HASH_SHA224))
					)
				{
					algo_supported = 1;
					break;
				}
			}

			if (!algo_supported)
			{
				sc_mem_clear(buf, sizeof(buf));
				LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
			}
		}
	}

	r = sc_get_encoding_flags(ctx, flags, alg_info->flags, &pad_flags, &sec_flags);
	if (r != SC_SUCCESS) {
		sc_mem_clear(buf, sizeof(buf));
		LOG_FUNC_RETURN(ctx, r);
	}
	senv.algorithm_flags = sec_flags;

	sc_log(ctx, "DEE flags:0x%8.8lx alg_info->flags:0x%8.8x pad:0x%8.8lx sec:0x%8.8lx",
		flags, alg_info->flags, pad_flags, sec_flags);

	/* add the padding bytes (if necessary) */
	if (pad_flags != 0) {
		size_t tmplen = sizeof(buf);

		r = sc_pkcs1_encode(ctx, pad_flags, tmp, inlen, tmp, &tmplen, modlen);
		SC_TEST_RET(ctx, SC_LOG_DEBUG_NORMAL, r, "Unable to add padding");
		inlen = tmplen;
	}
	else if ( senv.algorithm == SC_ALGORITHM_RSA &&
	          (flags & SC_ALGORITHM_RSA_PADS) == SC_ALGORITHM_RSA_PAD_NONE) {
		/* Add zero-padding if input is shorter than the modulus */
		if (inlen < modlen) {
			if (modlen > sizeof(buf))
				return SC_ERROR_BUFFER_TOO_SMALL;
			memmove(tmp+modlen-inlen, tmp, inlen);
			memset(tmp, 0, modlen-inlen);
		}
		inlen = modlen;
	}
	/* PKCS#11 MECHANISMS V2.30: 6.3.1 EC Signatures
	 * If the length of the hash value is larger than the bit length of n, only
	 * the leftmost bits of the hash up to the length of n will be used. Any
	 * truncation is done by the token.
	 */
	else if (senv.algorithm == SC_ALGORITHM_EC &&
			(flags & SC_ALGORITHM_ECDSA_HASH_NONE) != 0) {
		inlen = MIN(inlen, (prkey->field_length+7)/8);
	}


	r = use_key(p15card, obj, &senv, sc_compute_signature, tmp, inlen,
			out, outlen);
	LOG_TEST_RET(ctx, r, "use_key() failed");

	/* Some cards may return RSA signature as integer without leading zero bytes */
	/* Already know outlen >= modlen and r >= 0 */
	if (obj->type == SC_PKCS15_TYPE_PRKEY_RSA && (unsigned)r < modlen) {
		memmove(out + modlen - r, out, r);
		memset(out, 0, modlen - r);
		r = modlen;
	}

	sc_mem_clear(buf, sizeof(buf));

	LOG_FUNC_RETURN(ctx, r);
}
