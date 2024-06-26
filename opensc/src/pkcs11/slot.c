/*
 * slot.c: reader, smart card and slot related management functions
 *
 * Copyright (C) 2002  Timo Teräs <timo.teras@iki.fi>
 * Copyright (C) 2009 Martin Paljak <martin@martinpaljak.net>
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

#include "config.h"
#include "libopensc/opensc.h"

#include <string.h>
#include <stdlib.h>

#include "sc-pkcs11.h"

static struct sc_pkcs11_framework_ops *frameworks[] = {
	&framework_pkcs15,
#ifdef USE_PKCS15_INIT
	/* This should be the last framework, because it
	 * will assume the card is blank and try to initialize it */
	&framework_pkcs15init,
#endif
	NULL
};

static struct sc_pkcs11_slot * reader_get_slot(sc_reader_t *reader)
{
	unsigned int i;

	/* Locate a slot related to the reader */
	for (i = 0; i<list_size(&virtual_slots); i++) {
		sc_pkcs11_slot_t *slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		if (slot->reader == reader)
			return slot;
	}
	return NULL;
}

static void init_slot_info(CK_SLOT_INFO_PTR pInfo, sc_reader_t *reader)
{
	if (reader) {
		strcpy_bp(pInfo->slotDescription, reader->name, 64);
		strcpy_bp(pInfo->manufacturerID, reader->vendor, 32);
		pInfo->hardwareVersion.major = reader->version_major;
		pInfo->hardwareVersion.minor = reader->version_minor;
	} else {
		strcpy_bp(pInfo->slotDescription, "Virtual hotplug slot", 64);
		strcpy_bp(pInfo->manufacturerID, OPENSC_VS_FF_COMPANY_NAME, 32);
		pInfo->hardwareVersion.major = OPENSC_VERSION_MAJOR;
		pInfo->hardwareVersion.minor = OPENSC_VERSION_MINOR;
	}
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
	pInfo->firmwareVersion.major = 0;
	pInfo->firmwareVersion.minor = 0;
}

/* simclist helpers to locate interesting objects by ID */
static int object_list_seeker(const void *el, const void *key)
{
	const struct sc_pkcs11_object *object = (struct sc_pkcs11_object *)el;

	if ((el == NULL) || (key == NULL))
		return 0;
	if (object->handle == *(CK_OBJECT_HANDLE*)key)
		return 1;
	return 0;
}
								
CK_RV create_slot(sc_reader_t *reader)
{
	/* find unused virtual hotplug slots */
	struct sc_pkcs11_slot *slot = reader_get_slot(NULL);

	/* create a new slot if no empty slot is available */
	if (!slot) {
		if (list_size(&virtual_slots) >= sc_pkcs11_conf.max_virtual_slots)
			return CKR_FUNCTION_FAILED;

		slot = (struct sc_pkcs11_slot *)calloc(1, sizeof(struct sc_pkcs11_slot));
		if (!slot)
			return CKR_HOST_MEMORY;

		list_append(&virtual_slots, slot);
		if (0 != list_init(&slot->objects)) {
			return CKR_HOST_MEMORY;
		}
		list_attributes_seeker(&slot->objects, object_list_seeker);

		if (0 != list_init(&slot->logins)) {
			return CKR_HOST_MEMORY;
		}
	} else {
		/* reuse the old list of logins/objects since they should be empty */
		list_t logins = slot->logins;
		list_t objects = slot->objects;

		memset(slot, 0, sizeof *slot);

		slot->logins = logins;
		slot->objects = objects;
	}

	slot->login_user = -1;
	slot->id = (CK_SLOT_ID) list_locate(&virtual_slots, slot);
	init_slot_info(&slot->slot_info, reader);
	sc_log(context, "Initializing slot with id 0x%lx", slot->id);

	if (reader != NULL) {
		slot->reader = reader;
		strcpy_bp(slot->slot_info.manufacturerID, reader->vendor, 32);
		strcpy_bp(slot->slot_info.slotDescription, reader->name, 64);
		slot->slot_info.hardwareVersion.major = reader->version_major;
		slot->slot_info.hardwareVersion.minor = reader->version_minor;
	}

	return CKR_OK;
}

void empty_slot(struct sc_pkcs11_slot *slot)
{
	if (slot) {
		if (slot->flags & SC_PKCS11_SLOT_FLAG_SEEN) {
			/* Keep the slot visible to the application. The slot's state has
			 * already been reset by `slot_token_removed()`, lists have been
			 * emptied. We replace the reader with a virtual hotplug slot. */
			slot->reader = NULL;
			init_slot_info(&slot->slot_info, NULL);
		} else {
			list_destroy(&slot->objects);
			list_destroy(&slot->logins);
			list_delete(&virtual_slots, slot);
			free(slot);
		}
	}
}


/* create slots associated with a reader, called whenever a reader is seen. */
CK_RV initialize_reader(sc_reader_t *reader)
{
	unsigned int i;
	CK_RV rv;

	for (i = 0; i < sc_pkcs11_conf.slots_per_card; i++) {
		rv = create_slot(reader);
		if (rv != CKR_OK)
			return rv;
	}

	sc_log(context, "Initialize reader '%s': detect SC card presence", reader->name);
	if (sc_detect_card_presence(reader))   {
		sc_log(context, "Initialize reader '%s': detect PKCS11 card presence", reader->name);
		card_detect(reader);
	}

	sc_log(context, "Reader '%s' initialized", reader->name);
	return CKR_OK;
}


CK_RV card_removed(sc_reader_t * reader)
{
	unsigned int i;
	struct sc_pkcs11_card *p11card = NULL;
	/* Mark all slots as "token not present" */
	sc_log(context, "%s: card removed", reader->name);


	for (i=0; i < list_size(&virtual_slots); i++) {
		sc_pkcs11_slot_t *slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		if (slot->reader == reader) {
			/* Save the "card" object */
			if (slot->p11card)
				p11card = slot->p11card;
			slot_token_removed(slot->id);
		}
	}

	if (p11card) {
		p11card->framework->unbind(p11card);
		sc_disconnect_card(p11card->card);
		for (i=0; i < p11card->nmechanisms; ++i) {
			if (p11card->mechanisms[i]->free_mech_data) {
				p11card->mechanisms[i]->free_mech_data(p11card->mechanisms[i]->mech_data);
			}
			free(p11card->mechanisms[i]);
		}
		free(p11card->mechanisms);
		free(p11card);
	}
	
	return CKR_OK;
}


CK_RV card_detect(sc_reader_t *reader)
{
	struct sc_pkcs11_card *p11card = NULL;
	int free_p11card = 0;
	int rc;
	CK_RV rv;
	unsigned int i, releaseTransaction = 0;
	int j;

	sc_log(context, "%s: Detecting smart card", reader->name);
	/* Check if someone inserted a card */
again:
	rc = sc_detect_card_presence(reader);
	if (rc < 0) {
		sc_log(context, "%s: failed, %s", reader->name, sc_strerror(rc));
		if (rc == SC_ERROR_NO_READERS_FOUND || rc == SC_ERROR_READER_DETACHED)
		{
			card_removed(reader);	/* Release all resources */
			return CKR_SLOT_ID_INVALID;
		}
		return sc_to_cryptoki_error(rc, NULL);
	}
	if (rc == 0) {
		sc_log(context, "%s: card absent", reader->name);
		card_removed(reader);	/* Release all resources */
		return CKR_TOKEN_NOT_PRESENT;
	}

	/* If the card was changed, disconnect the current one */
	if (rc & SC_READER_CARD_CHANGED) {
		sc_log(context, "%s: Card changed", reader->name);
		/* The following should never happen - but if it
		 * does we'll be stuck in an endless loop.
		 * So better be fussy. 
		if (!retry--)
			return CKR_TOKEN_NOT_PRESENT; */
		card_removed(reader);
		goto again;
	}

	/* Locate a slot related to the reader */
	for (i=0; i<list_size(&virtual_slots); i++) {
		sc_pkcs11_slot_t *slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		if (slot->reader == reader) {
			p11card = slot->p11card;
			break;
		}
	}

	/* Detect the card if it's not known already */
	if (p11card == NULL) {
		sc_log(context, "%s: First seen the card ", reader->name);
		p11card = (struct sc_pkcs11_card *)calloc(1, sizeof(struct sc_pkcs11_card));
		if (!p11card)
			return CKR_HOST_MEMORY;
		free_p11card = 1;
		p11card->reader = reader;
	}

	if (p11card->card == NULL) {
		sc_log(context, "%s: Connecting ... ", reader->name);
		rc = sc_connect_card(reader, &p11card->card);
		if (rc != SC_SUCCESS) {
			sc_log(context, "%s: SC connect card error %i", reader->name, rc);
			rv = sc_to_cryptoki_error(rc, NULL);
			goto fail;
		}
        
		/* check if we are really connected since sc_connect_card succeeds if
		 * another process has an exclusive connection (SC_ERROR_READER_LOCKED error while connecting)
		 */
		if (reader->active_protocol)
			releaseTransaction = 1;
		/* escape commands are only guaranteed to be working with a card
		 * inserted. That's why by now, after sc_connect_card() the reader's
		 * metadata may have changed. We re-initialize the metadata for every
		 * slot of this reader here. */
		if (reader->flags & SC_READER_ENABLE_ESCAPE) {
			for (i = 0; i<list_size(&virtual_slots); i++) {
				sc_pkcs11_slot_t *slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
				if (slot->reader == reader)
					init_slot_info(&slot->slot_info, reader);
			}
		}

		sc_log(context, "%s: Connected SC card %p", reader->name, p11card->card);
	}

	/* Detect the framework */
	if (p11card->framework == NULL) {
		struct sc_app_info *app_generic = sc_pkcs15_get_application_by_type(p11card->card, "generic");
		int card_binded = 0;
		CK_RV last_bind_error = CKR_OK;

		sc_log(context, "%s: Detecting Framework. %i on-card applications", reader->name, p11card->card->app_count);
		sc_log(context, "%s: generic application %s", reader->name, app_generic ? app_generic->label : "<none>");

		for (i = 0; frameworks[i]; i++)
			if (frameworks[i]->bind != NULL)
				break;
		/*TODO: only first framework is used: pkcs15init framework is not reachable here */
		if (frameworks[i] == NULL) {
			rv = CKR_GENERAL_ERROR;
			goto fail;
		}

		p11card->framework = frameworks[i];

		if (p11card->card->driver)
		{
			/* Initialize framework */
			sc_log(context, "%s: Detected framework %d. Creating tokens.", reader->name, i);
			/* Bind 'generic' application or (emulated?) card without applications */
			if (app_generic || !p11card->card->app_count) {
				scconf_block *conf_block = NULL;
				int enable_InitToken = 0;

				conf_block = sc_match_atr_block(p11card->card->ctx, NULL,
					&p11card->reader->atr);
				if (!conf_block) /* check default block */
					conf_block = sc_get_conf_block(context,
						"framework", "pkcs15", 1);

				enable_InitToken = scconf_get_bool(conf_block,
					"pkcs11_enable_InitToken", 0);

				sc_log(context, "%s: Try to bind 'generic' token.", reader->name);
				rv = frameworks[i]->bind(p11card, app_generic);
				if (rv == CKR_TOKEN_NOT_RECOGNIZED && enable_InitToken) {
					sc_log(context, "%s: 'InitToken' enabled -- accept non-binded card", reader->name);
					rv = CKR_OK;
				}
				if (rv != CKR_OK) {
					sc_log(context,
						"%s: cannot bind 'generic' token: rv 0x%lX",
						reader->name, rv);
					goto fail;
				}

				sc_log(context, "%s: Creating 'generic' token.", reader->name);
				rv = frameworks[i]->create_tokens(p11card, app_generic);
				if (rv != CKR_OK) {
					sc_log(context,
						"%s: create 'generic' token error 0x%lX",
						reader->name, rv);
					goto fail;
				}
			}

			/* Now bind the rest of applications that are not 'generic' */
			for (j = 0; j < p11card->card->app_count; j++) {
				struct sc_app_info *app_info = p11card->card->app[j];
				char *app_name = app_info ? app_info->label : "<anonymous>";

				if (app_generic && app_generic == p11card->card->app[j])
					continue;

				sc_log(context, "%s: Binding %s token.", reader->name, app_name);
				rv = frameworks[i]->bind(p11card, app_info);
				if (rv != CKR_OK) {
					last_bind_error = rv;
					sc_log(context, "%s: bind %s token error Ox%lX",
						reader->name, app_name, rv);
					continue;
				}

				card_binded = 1;

				sc_log(context, "%s: Creating %s token.", reader->name, app_name);
				rv = frameworks[i]->create_tokens(p11card, app_info);
				if (rv != CKR_OK) {
					sc_log(context,
						"%s: create %s token error 0x%lX",
						reader->name, app_name, rv);
					goto fail;
				}
			}
		}

		/* accept non binded card to avoid reading the card multiple times */
		if (!card_binded && ((p11card->card->driver == NULL) || (p11card->card->app_count > 0) && (last_bind_error == CKR_TOKEN_NOT_RECOGNIZED)))
		{
			frameworks[i]->create_tokens(p11card, NULL);
			p11card->token_not_recognized = 1;
		}
	}


	if (releaseTransaction)
	{
		// release transaction
		sc_unlock(p11card->card);
	}

	sc_log(context, "%s: Detection ended", reader->name);
	return CKR_OK;

fail:
	if (releaseTransaction)
	{
		// release transaction
		sc_unlock(p11card->card);
	}

	if (free_p11card) {
		if (p11card->framework)
			p11card->framework->unbind(p11card);
		if (p11card->card != NULL)
			sc_disconnect_card(p11card->card);
		free(p11card);
	}

	return rv;
}


CK_RV
card_detect_all(void)
{
	unsigned int i;

	sc_log(context, "Detect all cards");
	/* Detect cards in all initialized readers */
	for (i=0; i< sc_ctx_get_reader_count(context); i++) {
		sc_reader_t *reader = sc_ctx_get_reader(context, i);
		if (reader->flags & SC_READER_REMOVED) {
			struct sc_pkcs11_slot *slot;
			card_removed(reader);
			while ((slot = reader_get_slot(reader))) {
				empty_slot(slot);
			}
			_sc_delete_reader(context, reader);
			i--;
		} else {
			if (!reader_get_slot(reader))
				initialize_reader(reader);
			else
				card_detect(sc_ctx_get_reader(context, i));
		}
	}
	sc_log(context, "All cards detected");
	return CKR_OK;
}

/* Allocates an existing slot to a card */
CK_RV slot_allocate(struct sc_pkcs11_slot ** slot, struct sc_pkcs11_card * p11card)
{
	unsigned int i;
	struct sc_pkcs11_slot *tmp_slot = NULL;

	/* Locate a free slot for this reader */
	for (i=0; i< list_size(&virtual_slots); i++) {
		tmp_slot = (struct sc_pkcs11_slot *)list_get_at(&virtual_slots, i);
		if (tmp_slot->reader == p11card->reader && tmp_slot->p11card == NULL)
			break;
	}
	if (!tmp_slot || (i == list_size(&virtual_slots)))
		return CKR_FUNCTION_FAILED;
	sc_log(context, "Allocated slot 0x%lx for card in reader %s", tmp_slot->id, p11card->reader->name);
	tmp_slot->p11card = p11card;
	tmp_slot->events = SC_EVENT_CARD_INSERTED;
	*slot = tmp_slot;
	return CKR_OK;
}

CK_RV slot_get_slot(CK_SLOT_ID id, struct sc_pkcs11_slot ** slot)
{
	if (context == NULL)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	*slot = list_seek(&virtual_slots, &id);	/* FIXME: check for null? */
	if (!*slot)
		return CKR_SLOT_ID_INVALID;
	return CKR_OK;
}

CK_RV slot_get_token(CK_SLOT_ID id, struct sc_pkcs11_slot ** slot)
{
	CK_RV rv;

	sc_log(context, "Slot(id=0x%lX): get token", id);
	rv = slot_get_slot(id, slot);
	if (rv != CKR_OK)
		return rv;

	if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT)) {
		if ((*slot)->reader == NULL)
			return CKR_TOKEN_NOT_PRESENT;
		sc_log(context, "Slot(id=0x%lX): get token: now detect card", id);
		rv = card_detect((*slot)->reader);
		if (rv != CKR_OK)
			return rv;
	}

	if (!((*slot)->slot_info.flags & CKF_TOKEN_PRESENT)) {
		sc_log(context, "card detected, but slot not presenting token");
		return CKR_TOKEN_NOT_PRESENT;
	}
	sc_log(context, "Slot-get-token returns OK");
	return CKR_OK;
}

CK_RV slot_token_removed(CK_SLOT_ID id)
{
    CK_RV rv;
	int token_was_present;
	struct sc_pkcs11_slot *slot;
	struct sc_pkcs11_object *object;

	sc_log(context, "slot_token_removed(0x%lx)", id);
	rv = slot_get_slot(id, &slot);
	if (rv != CKR_OK)
		return rv;

	token_was_present = (slot->slot_info.flags & CKF_TOKEN_PRESENT);

	/* Terminate active sessions */
	sc_pkcs11_close_all_sessions(id);

	while ((object = list_fetch(&slot->objects))) {
		if (object->ops->release)
			object->ops->release(object);
	}

	/* Release framework stuff */
	if (slot->p11card != NULL) {
		if (slot->fw_data != NULL &&
				slot->p11card->framework != NULL && slot->p11card->framework->release_token != NULL) {
			slot->p11card->framework->release_token(slot->p11card, slot->fw_data);
			slot->fw_data = NULL;
		}
		slot->p11card = NULL;
	}

	/* Reset relevant slot properties */
	slot->slot_info.flags &= ~CKF_TOKEN_PRESENT;
	slot->login_user = -1;
	pop_all_login_states(slot);

	if (token_was_present)
		slot->events = SC_EVENT_CARD_REMOVED;

	memset(&slot->token_info, 0, sizeof slot->token_info);

	return CKR_OK;
}

/* Called from C_WaitForSlotEvent */
CK_RV slot_find_changed(CK_SLOT_ID_PTR idp, int mask)
{
	unsigned int i;
	LOG_FUNC_CALLED(context);

	card_detect_all();
	for (i=0; i<list_size(&virtual_slots); i++) {
		sc_pkcs11_slot_t *slot = (sc_pkcs11_slot_t *) list_get_at(&virtual_slots, i);
		sc_log(context, "slot 0x%lx token: %lu events: 0x%02X",
		       slot->id, (slot->slot_info.flags & CKF_TOKEN_PRESENT),
		       slot->events);
		if ((slot->events & SC_EVENT_CARD_INSERTED)
				&& !(slot->slot_info.flags & CKF_TOKEN_PRESENT)) {
			/* If a token has not been initialized, clear the inserted event */
			slot->events &= ~SC_EVENT_CARD_INSERTED;
		}
		sc_log(context, "mask: 0x%02X events: 0x%02X result: %d", mask, slot->events, (slot->events & mask));

		if (slot->events & mask) {
			slot->events &= ~mask;
			*idp = slot->id;
			LOG_FUNC_RETURN(context, CKR_OK);
		}
	}
	LOG_FUNC_RETURN(context, CKR_NO_EVENT);
}
