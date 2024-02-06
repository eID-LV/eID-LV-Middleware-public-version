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
 * @file eac_asn1.h
 * @brief Interface to ASN.1 structures related to PACE
 *
 * @author Frank Morgner <frankmorgner@gmail.com>
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef PACE_ASN1_H_
#define PACE_ASN1_H_

#include <eac/eac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/**
 * @brief Encodes public key data objects of the domain parameters in ASN.1
 * (see TR-3110 D.3.2 and D.3.3)
 *
 * @return ASN.1 encoded public key data objects or NULL if an error occurred
 */
BUF_MEM *
asn1_pubkey(int protocol, EVP_PKEY *key, BN_CTX *bn_ctx, enum eac_tr_version tr_version);

#endif /* PACE_ASN1_H_ */
