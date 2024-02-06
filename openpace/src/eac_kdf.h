/*
 * Copyright (c) 2010-2012 Frank Morgner and Dominik Oepen
 *
 * This file is part of OpenPACE.
 *
 * OpenPACE is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * OpenPACE is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * OpenPACE.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file eac_kdf.h
 * @brief Interface to key derivation functions
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_KDF_H_
#define PACE_KDF_H_

#include <eac/pace.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <stdint.h>

/**
 * @defgroup kdf            Key Derivation Functions
 * @{ ************************************************************************/

/**
 * @brief General key derivation function according to TR-3110 F.3.1
 *
 * @param[in] key Shared secret
 * @param[in] nonce (optional)
 * @param[in] counter Formatted in big endian
 * @param[in] ctx
 *
 * @return derivated key or NULL if an error occurred
 */
BUF_MEM *
kdf(const BUF_MEM *key, const BUF_MEM *nonce, const uint32_t counter,
        const KA_CTX *ctx, EVP_MD_CTX *md_ctx);
#define KDF_ENC_COUNTER 1
#define KDF_MAC_COUNTER 2
#define KDF_PI_COUNTER  3
/**
 * @brief Key derivation function to derive encryption key
 *
 * @see kdf()
 */
BUF_MEM *
kdf_enc(const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx);
/**
 * @brief Key derivation function to derive authentication key
 *
 * @see kdf()
 */
BUF_MEM *
kdf_mac(const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx);
/**
 * @brief Key derivation function from a password pi
 *
 * @see kdf()
 */
BUF_MEM *
kdf_pi(const PACE_SEC *pi, const BUF_MEM *nonce, const KA_CTX *ctx, EVP_MD_CTX *md_ctx);
/** @} ***********************************************************************/

#endif /*PACE_KDF_H_*/
