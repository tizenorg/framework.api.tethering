/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef __TIZEN_NETWORK_TETHERING_DOC_H__
#define __TIZEN_NETWORK_TETHERING_DOC_H__


/**
 * @internal
 * @defgroup CAPI_NETWORK_TETHERING_MODULE Tethering
 * @brief Tethering provides three kinds of tethering : Wi-Fi, Bluetooth and USB.
 * @ingroup CAPI_NETWORK_FRAMEWORK
 *
 * @section CAPI_NETWORK_TETHERING_MODULE_HEADER Required Header
 *   \#include <tethering.h>
 *
 * @section CAPI_NETWORK_TETHERING_MODULE_OVERVIEW Overview
 * Tethering Service consists of @ref CAPI_NETWORK_TETHERING_MANAGER_MODULE and @ref CAPI_NETWORK_TETHERING_CLIENT_MODULE.
 * <table>
 * <tr>
 *    <th>API</th>
 *    <th>Description</th>
 * </tr>
 * <tr>
 *    <td>@ref CAPI_NETWORK_TETHERING_MANAGER_MODULE </td>
 *    <td>Provides functions for managing the tethering.</td>
 * </tr>
 * <tr>
 *    <td>@ref CAPI_NETWORK_TETHERING_CLIENT_MODULE </td>
 *    <td>Provides functions for getting the information about a connected client.</td>
 * </tr>
 * </table>
 */

/**
 * @internal
 * @defgroup CAPI_NETWORK_TETHERING_MANAGER_MODULE Tethering Manager
 * @brief Tethering provides API to manage the tethering.
 * @ingroup CAPI_NETWORK_TETHERING_MODULE
 *
 * @section CAPI_NETWORK_TETHERING_MANAGER_MODULE_HEADER Required Header
 *   \#include <tethering.h>
 *
 * @section CAPI_NETWORK_TETHERING_MANAGER_MODULE_OVERVIEW Overview
 * This set of functions is used to manage tethering.
 * There are three kinds of tethering : Wi-Fi, Bluetooth and USB. \n
 */

/**
 * @internal
 * @defgroup CAPI_NETWORK_TETHERING_WIFI_MODULE Tethering Wi-Fi
 * @brief Tethering Wi-Fi provides API to set the configuration of tethering Wi-Fi.
 * @ingroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 *
 * @section CAPI_NETWORK_TETHERING_MODULE_HEADER Required Header
 *   \#include <tethering.h>
 *
 * @section CAPI_NETWORK_TETHERING_MODULE_OVERVIEW Overview
 * This set of functions is used to manage security types, passphrases and so on.
 */

/**
 * @internal
 * @defgroup CAPI_NETWORK_TETHERING_CLIENT_MODULE Tethering Client
 * @brief Client provides API to get the information about a connected client.
 * @ingroup CAPI_NETWORK_TETHERING_MODULE
 *
 * @section CAPI_NETWORK_TETHERING_CLIENT_MODULE_HEADER Required Header
 *   \#include <tethering.h>
 *
 * @section CAPI_NETWORK_TETHERING_CLIENT_MODULE_OVERVIEW Overview
 * This set of functions is used to get information about a connected client.
 */

#endif /* __TIZEN_NETWORK_MOBILE_AP_DOC_H__ */
