/*
 * Copyright (c) 2012 Dominik Oepen
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
 * @file eac_err.h
 * @brief Error handling macros
 *
 * @author Dominik Oepen <oepen@informatik.hu-berlin.de>
 */

#ifndef EAC_ERR_H
#define EAC_ERR_H

#include <errno.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

#ifdef DEBUG
#define debug(M, ...)  fprintf(stderr, "DEBUG %s:%d: " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug(M, ...)
#endif

/* TODO: Make sure that ERR_load_crypto_strings() has been called */
#define ossl_errors() ERR_print_errors_fp(stderr)
#define log_err(M, ...) {fprintf(stderr, "[ERROR] (%s:%d ) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__); ossl_errors();}
#define check(A, M, ...) {if(!(A)) { log_err(M, ##__VA_ARGS__); goto err; }}
#define check_return(A, M, ...) {if(!(A)) { log_err(M, ##__VA_ARGS__); errno=0; return NULL;}}


#endif
