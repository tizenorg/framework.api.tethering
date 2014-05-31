/*
* Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#include <stdlib.h>
#include <string.h>
#include "tethering_private.h"

API int tethering_client_clone(tethering_client_h *dest, tethering_client_h origin)
{
	_retvm_if(dest == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(dest) is NULL\n");

	__tethering_client_h *si = NULL;
	__tethering_client_h *source = NULL;

	source = (__tethering_client_h *)origin;

	si = malloc(sizeof(__tethering_client_h));
	if (si == NULL) {
		ERR("malloc is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	memcpy(si, source, sizeof(__tethering_client_h));
	si->hostname = g_strdup(source->hostname);
	if (si->hostname == NULL) {
		ERR("malloc is failed\n");
		free(si);
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	*dest = (tethering_client_h)si;

	return TETHERING_ERROR_NONE;
}

API int tethering_client_destroy(tethering_client_h client)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");

	__tethering_client_h *si = NULL;

	si = (__tethering_client_h *)client;

	g_free(si->hostname);

	free(client);

	return TETHERING_ERROR_NONE;
}

API int tethering_client_get_tethering_type(tethering_client_h client, tethering_type_e *type)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");
	_retvm_if(type == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(type) is NULL\n");

	__tethering_client_h *si = (__tethering_client_h *)client;

	*type = si->interface;

	return TETHERING_ERROR_NONE;
}

API int tethering_client_get_name(tethering_client_h client, char **name)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");
	_retvm_if(name == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(name) is NULL\n");

	__tethering_client_h *si = (__tethering_client_h *)client;

	*name = strdup(si->hostname);
	if (*name == NULL) {
		ERR("strdup is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

API int tethering_client_get_ip_address(tethering_client_h client, tethering_address_family_e address_family, char **ip_address)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");
	_retvm_if(ip_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(ip_address) is NULL\n");

	__tethering_client_h *si = (__tethering_client_h *)client;

	*ip_address = strdup(si->ip);
	if (*ip_address == NULL) {
		ERR("strdup is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

API int tethering_client_get_mac_address(tethering_client_h client, char **mac_address)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");
	_retvm_if(mac_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(mac_address) is NULL\n");

	__tethering_client_h *si = (__tethering_client_h *)client;

	*mac_address = strdup(si->mac);
	if (*mac_address == NULL) {
		ERR("strdup is failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	return TETHERING_ERROR_NONE;
}

API int tethering_client_get_time(tethering_client_h client, time_t *timestamp)
{
	_retvm_if(client == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"Parameter(client) is NULL\n");


	__tethering_client_h *si = (__tethering_client_h *)client;

	*timestamp = si->tm;

	return TETHERING_ERROR_NONE;
}

