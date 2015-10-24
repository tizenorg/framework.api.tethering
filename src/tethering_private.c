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
#include <system_info.h>
#include "tethering_private.h"

int tethering_check_feature_supported(const char* feature, ...)
{
	va_list list;
	const char *key;
	int ret;
	bool value, supported = false;

	va_start(list, feature);
	key = feature;
	while(1) {
		ret = system_info_get_platform_bool(key, &value);
		if (ret < 0) {
			ERR("Get feature is failed\n");
			return TETHERING_ERROR_OPERATION_FAILED;
		}
		supported |= value;
		key = va_arg(list, const char *);
		if (!key) break;
	}

	if (!supported)
		return TETHERING_ERROR_NOT_SUPPORT_API;

	return TETHERING_ERROR_NONE;
}
