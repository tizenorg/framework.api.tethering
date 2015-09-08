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

#ifndef __TIZEN_NETWORK_TETHERING_H__
#define __TIZEN_NETWORK_TETHERING_H__

#include <tizen.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file tethering.h
 */

/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @internal
 * @brief The tethering handle.
 * @since_tizen 2.3
 */
typedef void * tethering_h;

/**
 * @internal
 * @brief Enumeration for the tethering.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_ERROR_NONE = TIZEN_ERROR_NONE,  /**< Successful */
    TETHERING_ERROR_NOT_PERMITTED = TIZEN_ERROR_NOT_PERMITTED,  /**< Operation not permitted */
    TETHERING_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    TETHERING_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,  /**< Out of memory */
    TETHERING_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,  /**< Resource busy */
    TETHERING_ERROR_NOT_ENABLED = TIZEN_ERROR_TETHERING | 0x0501,  /**< Not enabled */
    TETHERING_ERROR_OPERATION_FAILED = TIZEN_ERROR_TETHERING | 0x0502,  /**< Operation failed */
    TETHERING_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
    TETHERING_ERROR_NOT_SUPPORT_API = TIZEN_ERROR_NOT_SUPPORTED, /**< API is not supported */
    TETHERING_ERROR_PERMISSION_DENIED = TIZEN_ERROR_PERMISSION_DENIED,  /**< Permission denied */
} tethering_error_e;

/**
 * @internal
 * @brief Enumeration for the type of tethering.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_TYPE_ALL = 0,  /**< All type except for TETHERING_TYPE_RESERVED */
    TETHERING_TYPE_USB,  /**< USB type */
    TETHERING_TYPE_WIFI,  /**< Wi-Fi type */
    TETHERING_TYPE_BT,  /**< BT type */
    TETHERING_TYPE_RESERVED,  /**< Reserved type */
} tethering_type_e;

/**
 * @internal
 * @brief Enumeration for the cause of disabling the tethering.
 * @since_tizen 2.3
 */
typedef enum
{
    TETHERING_DISABLED_BY_USB_DISCONNECTION = 0,  /**< Disabled due to usb disconnection */
    TETHERING_DISABLED_BY_FLIGHT_MODE,  /**< Disabled due to flight mode */
    TETHERING_DISABLED_BY_LOW_BATTERY,  /**< Disabled due to low battery */
    TETHERING_DISABLED_BY_NETWORK_CLOSE,  /**< Disabled due to pdp network close */
    TETHERING_DISABLED_BY_TIMEOUT,  /**< Disabled due to timeout */
    TETHERING_DISABLED_BY_OTHERS,  /**< Disabled by other apps */
    TETHERING_DISABLED_BY_REQUEST,  /**< Disabled by your request */
    TETHERING_DISABLED_BY_WIFI_ON,  /**< Disabled due to Wi-Fi on */
    TETHERING_DISABLED_BY_BT_OFF,  /**< Disabled due to Bluetooth off */
    TETHERING_DISABLED_BY_POWER_SAVE_MODE,	/**< Disabled due to power save mode */
} tethering_disabled_cause_e;

/**
 * @}
 */


/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @internal
 * @brief Enumeration for the Wi-Fi security.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_WIFI_SECURITY_TYPE_NONE = 0,  /**< No Security type */
    TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK,  /**< WPA2_PSK */
} tethering_wifi_security_type_e;

/**
 * @}
 */


/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @internal
 * @brief The tethering client handle.
 * @since_tizen 2.3
 */
typedef void * tethering_client_h;

/**
 * @internal
 * @brief Enumeration for address family.
 * @since_tizen 2.3
 */
typedef enum {
    TETHERING_ADDRESS_FAMILY_IPV4 = 0,  /**< IPV4 Address type */
} tethering_address_family_e;

/**
 * @}
 */


/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @internal
 * @brief Called when the tethering is enabled.
 * @since_tizen 2.3
 * @param[in]  result  The result of enabling the tethering
 * @param[in]  type  The tethering type
 * @param[in]  is_requested  Indicates whether this change is requested
 * @param[in]  user_data  The user data passed from tethering_set_enabled_cb()
 * @pre  If you register callback function using tethering_set_enabled_cb(), this will be invoked when the tethering is enabled.
 * @see	tethering_enable()
 * @see	tethering_unset_enabled_cb()
 */
typedef void (*tethering_enabled_cb)(tethering_error_e result, tethering_type_e type, bool is_requested, void *user_data);

/**
 * @internal
 * @brief Called when the tethering is disabled.
 * @since_tizen 2.3
 * @param[in]  result  The result of disabling the tethering
 * @param[in]  type  The tethering type
 * @param[in]  cause  The cause of disabling
 * @param[in]  user_data  The user data passed from tethering_set_disabled_cb()
 * @pre  If you register callback function using tethering_set_disabled_cb(), this will be invoked when the tethering is disabled.
 * @see	tethering_set_disabled_cb()
 * @see	tethering_unset_disabled_cb()
 */
typedef void (*tethering_disabled_cb)(tethering_error_e result, tethering_type_e type, tethering_disabled_cause_e cause, void *user_data);

/**
 * @internal
 * @brief Called when the connection state is changed.
 * @since_tizen 2.3
 * @remarks @a client is valid only in this function. In order to use it outside this function, a user must copy the client with tethering_client_clone().
 * @param[in]  client  The client of which connection state is changed
 * @param[in]  opened  @c true when connection is opened, otherwise false
 * @param[in]  user_data  The user data passed from tethering_set_connection_state_changed_cb()
 * @pre  If you register callback function using tethering_set_connection_state_changed_cb(), this will be invoked when the connection state is changed.
 * @see	tethering_set_connection_state_changed_cb()
 * @see	tethering_unset_connection_state_changed_cb()
 */
typedef void (*tethering_connection_state_changed_cb)(tethering_client_h client, bool opened, void *user_data);

/**
 * @internal
 * @brief Called when you get the connected client repeatedly.
 * @since_tizen 2.3
 * @remarks @a client is valid only in this function. In order to use the client outside this function, a user must copy the client with tethering_client_clone().
 * @param[in]  client  The connected client
 * @param[in]  user_data  The user data passed from the request function
 * @return  @c true to continue with the next iteration of the loop, \n @c false to break out of the loop
 * @pre  tethering_foreach_connected_clients() will invoke this callback.
 * @see  tethering_foreach_connected_clients()
 */
typedef bool(*tethering_connected_client_cb)(tethering_client_h client, void *user_data);

/**
 * @internal
 * @brief Called when you get the data usage.
 * @since_tizen 2.3
 * @param[in]  result  The result of getting the data usage
 * @param[in]  received_data  The usage of received data
 * @param[in]  sent_data  The usage of sent data
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_get_data_usage() will invoked this callback.
 */
typedef void (*tethering_data_usage_cb)(tethering_error_e result, unsigned long long received_data, unsigned long long sent_data, void *user_data);

/**
 * @internal
 * @brief Called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @param[in]  changed_type  The changed security type of Wi-Fi tethering
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_security_type_changed_cb()
 * @see	tethering_wifi_unset_security_type_changed_cb()
 */
typedef void (*tethering_wifi_security_type_changed_cb)(tethering_wifi_security_type_e changed_type, void *user_data);

/**
 * @internal
 * @brief Called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @param[in]  changed_visible  The changed visibility of SSID
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_ssid_visibility_changed_cb()
 * @see	tethering_wifi_unset_ssid_visibility_changed_cb()
 */
typedef void (*tethering_wifi_ssid_visibility_changed_cb)(bool changed_visible, void *user_data);

/**
 * @internal
 * @brief Called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_passphrase_changed_cb()
 * @see	tethering_wifi_unset_passphrase_changed_cb()
 */
typedef void (*tethering_wifi_passphrase_changed_cb)(void *user_data);

/**
 * @internal
 * @brief Called when the settings are reloaded.
 * @since_tizen 2.3
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_wifi_reload_settings() will invoke this callback.
 */
typedef void (*tethering_wifi_settings_reloaded_cb)(tethering_error_e result, void *user_data);

/**
 * @internal
 * @brief Called when Wi-Fi AP settings are reloaded.
 * @since_tizen 2.3
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_wifi_ap_reload_settings() will invoke this callback.
 */
typedef void (*tethering_wifi_ap_settings_reloaded_cb)(tethering_error_e result, void *user_data);

/**
 * @internal
 * @brief Creates the handle for tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks The @a tethering must be released using tethering_destroy().
 * @param[out]  tethering  A handle of a new mobile ap handle on success
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API is not supported
 * @see  tethering_destroy()
 */
int tethering_create(tethering_h *tethering);

/**
 * @internal
 * @brief Destroys the handle for tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_create()
 */
int tethering_destroy(tethering_h tethering);

/**
 * @internal
 * @brief Enables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_enabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_disable()
 */
int tethering_enable(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Disables the tethering, asynchronously.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_disabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_disable(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Checks whether the tethering is enabled or not.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @return  @c true if tethering is enabled, \n @c false if tethering is disabled
 */
bool tethering_is_enabled(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Gets the MAC address of local device as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a mac_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_mac_address(tethering_h tethering, tethering_type_e type, char **mac_address);

/**
 * @internal
 * @brief Gets the name of network interface (e.g. usb0).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a interface_name must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[out]  interface_name  The name of the network interface
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_network_interface_name(tethering_h tethering, tethering_type_e type, char **interface_name);

/**
 * @internal
 * @brief Gets the local IP address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ip_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  ip_address  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_ip_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **ip_address);

/**
 * @internal
 * @brief Gets the Gateway address.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a gateway_address must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  gateway_address  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_gateway_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **gateway_address);

/**
 * @internal
 * @brief Gets the Subnet Mask.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a subnet_mask must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  address_family  The address family of IP address (currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported)
 * @param[out]  subnet_mask  The local IP address
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_subnet_mask(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **subnet_mask);

/**
 * @internal
 * @brief Gets the data usage.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  usage  The data usage
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_data_usage(tethering_h tethering, tethering_data_usage_cb callback, void *user_data);

/**
 * @internal
 * @brief Gets the clients which are connected.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @pre  The tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_foreach_connected_clients(tethering_h tethering, tethering_type_e type, tethering_connected_client_cb callback, void *user_data);

/**
 * @internal
 * @brief Registers the callback function, which is called when tethering is enabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_enabled_cb()
 */
int tethering_set_enabled_cb(tethering_h tethering, tethering_type_e type, tethering_enabled_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when tethering is enabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_enabled_cb()
 */
int tethering_unset_enabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Registers the callback function called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_disabled_cb()
 */
int tethering_set_disabled_cb(tethering_h tethering, tethering_type_e type, tethering_disabled_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when tethering is disabled.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_disabled_cb()
 */
int tethering_unset_disabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Registers the callback function, which is called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_connection_state_changed_cb_cb()
 */
int tethering_set_connection_state_changed_cb(tethering_h tethering, tethering_type_e type, tethering_connection_state_changed_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when the state of connection is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_connection_state_changed_cb()
 */
int tethering_unset_connection_state_changed_cb(tethering_h tethering, tethering_type_e type);

/**
 * @internal
 * @brief Registers the callback function, which is called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_security_type_changed_cb()
 */
int tethering_wifi_set_security_type_changed_cb(tethering_h tethering, tethering_wifi_security_type_changed_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when the security type of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The tethering type
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_security_type_changed_cb()
 */
int tethering_wifi_unset_security_type_changed_cb(tethering_h tethering);

/**
 * @internal
 * @brief Registers the callback function , which iscalled when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_ssid_visibility_changed_cb_cb()
 */
int tethering_wifi_set_ssid_visibility_changed_cb(tethering_h tethering, tethering_wifi_ssid_visibility_changed_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when the visibility of SSID is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_ssid_visibility_changed_cb()
 */
int tethering_wifi_unset_ssid_visibility_changed_cb(tethering_h tethering);

/**
 * @internal
 * @brief Registers the callback function, which is called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_passphrase_changed_cb()
 */
int tethering_wifi_set_passphrase_changed_cb(tethering_h tethering, tethering_wifi_passphrase_changed_cb callback, void *user_data);

/**
 * @internal
 * @brief Unregisters the callback function, which is called when the passphrase of Wi-Fi tethering is changed.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_passphrase_changed_cb()
 */
int tethering_wifi_unset_passphrase_changed_cb(tethering_h tethering);

/**
 * @}
 */


/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @internal
 * @brief Sets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_security_type()
 */
int tethering_wifi_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type);

/**
 * @internal
 * @brief Gets the security type of Wi-Fi tethering.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_security_type()
 */
int tethering_wifi_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type);

/**
 * @internal
 * @brief Sets the SSID (service set identifier).
 * @details The SSID cannot exceed 32 bytes. If SSID is not set, device name is used as SSID.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled with same @a tethering handle.
 * @param[in]  tethering  The tethering handle
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_set_ssid(tethering_h tethering, const char *ssid);

/**
 * @internal
 * @brief Gets the SSID (service set identifier).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ssid must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_get_ssid(tethering_h tethering, char **ssid);

/**
 * @internal
 * @brief Sets the visibility of SSID (service set identifier).
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan will not find the device.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_ssid_visibility()
 */
int tethering_wifi_set_ssid_visibility(tethering_h tethering, bool visible);

/**
 * @internal
 * @brief Gets the visibility of SSID (service set identifier).
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan will not find the device.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_ssid_visibility()
 */
int tethering_wifi_get_ssid_visibility(tethering_h tethering, bool *visible);

/**
 * @internal
 * @brief Sets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_passphrase()
 */
int tethering_wifi_set_passphrase(tethering_h tethering, const char *passphrase);

/**
 * @internal
 * @brief Gets the passphrase.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a passphrase must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_passphrase()
 */
int tethering_wifi_get_passphrase(tethering_h tethering, char **passphrase);

/**
 * @internal
 * @brief Reloads the settings (SSID / Passphrase / Security type / SSID visibility).
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks Connected devices via Wi-Fi tethering or MobileAP will be disconnected when the settings are reloaded.
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_reload_settings(tethering_h tethering, tethering_wifi_settings_reloaded_cb callback, void *user_data);

/**
 * @internal
 * @brief Sets the security type of Wi-Fi AP.
 * @details If security type is not set, WPA2_PSK is used.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_security_type()
 */
int tethering_wifi_ap_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type);

/**
 * @internal
 * @brief Gets the security type of Wi-Fi AP.
 * @details If security type is not set, WPA2_PSK is used.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_security_type()
 */
int tethering_wifi_ap_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type);

/**
 * @internal
 * @brief Sets the SSID (service set identifier) for Wi-Fi AP.
 * @details The SSID cannot exceed 32 bytes. If SSID is not set, device name is used as SSID.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_ap_set_ssid(tethering_h tethering, const char *ssid);

/**
 * @internal
 * @brief Gets the SSID (service set identifier) for Wi-Fi AP.
 * @details If SSID is not set, Device name is used as SSID.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ssid must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_ap_get_ssid(tethering_h tethering, char **ssid);

/**
 * @internal
 * @brief Sets the visibility of SSID (service set identifier) for Wi-Fi AP.
 * @details If you set the visibility to invisible, then the SSID of this device is hidden and Wi-Fi scan won't find your device.
 * @details By default visibility is set to @c true.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks This change is applied next time Wi-Fi tethering is enabled.
 * @param[in]  tethering  The tethering handle
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_ssid_visibility()
 */
int tethering_wifi_ap_set_ssid_visibility(tethering_h tethering, bool visible);

/**
 * @internal
 * @brief Gets the visibility of SSID (service set identifier) for Wi-Fi AP.
 * @details If the visibility is set to invisible, then the SSID of this device is hidden and Wi-Fi scan won't find your device.
 * @details By default visibility is set to @c true.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_ssid_visibility()
 */
int tethering_wifi_ap_get_ssid_visibility(tethering_h tethering, bool *visible);

/**
 * @internal
 * @brief Sets the passphrase for Wi-Fi AP.
 * @details If the passphrase is not set, random string of 8 characters will be used.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  tethering  The tethering handle
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_get_passphrase()
 */
int tethering_wifi_ap_set_passphrase(tethering_h tethering, const char *passphrase);

/**
 * @internal
 * @brief Gets the passphrase for Wi-Fi AP.
 * @details If the passphrase is not set, random string of 8 characters will be used.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a passphrase must be released using free().
 * @param[in]  tethering  The tethering handle
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_wifi_ap_set_passphrase()
 */
int tethering_wifi_ap_get_passphrase(tethering_h tethering, char **passphrase);

/**
 * @internal
 * @brief Reloads the settings (SSID / Passphrase / Security type / SSID visibility) for Wi-Fi AP.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks Devices connected via MobileAP will be disconnected when the settings are reloaded.
 * @param[in]  tethering  The tethering handle
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_ap_reload_settings(tethering_h tethering, tethering_wifi_ap_settings_reloaded_cb callback, void *user_data);

/**
 * @}
 */


/**
 * @internal
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @internal
 * @brief Clones the handle of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a dest must be release using tethering_client_destroy().
 * @param[out]  dest  The cloned client handle
 * @param[in]  origin  The origin client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_client_destroy()
 */
int tethering_client_clone(tethering_client_h *dest, tethering_client_h origin);

/**
 * @internal
 * @brief Destroys the handle of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  client  The client handle
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_client_clone()
 */
int tethering_client_destroy(tethering_client_h client);

/**
 * @internal
 * @brief  Gets the tethering type of client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in]  client  The handle of client
 * @param[out]  type  The type of tethering
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_tethering_type(tethering_client_h client, tethering_type_e *type);

/**
 * @internal
 * @brief Gets the name of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a name must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  name  The name of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_name(tethering_client_h client, char **name);

/**
 * @internal
 * @brief Gets the IP address of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a ip_address must be released using free().
 * @param[in]  client  The client handle
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported
 * @param[out]  ip_address  The IP address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_ip_address(tethering_client_h client, tethering_address_family_e address_family, char **ip_address);

/**
 * @internal
 * @brief Gets the MAC address of a client such as "FC:A1:3E:D6:B1:B1".
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @remarks @a mac_address must be released using free().
 * @param[in]  client  The client handle
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_mac_address(tethering_client_h client, char **mac_address);

/**
 * @internal
 * @brief Gets the connection time of a client.
 * @since_tizen 2.3
 * @privlevel platform
 * @privilege http://tizen.org/privilege/tethering.admin
 * @param[in] client The client handle
 * @param[out]  time  The connected time of the client
 * @return  0 on success, otherwise a negative error value
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_time(tethering_client_h client, time_t *timestamp);

/**
 * @}
 */


#ifdef __cplusplus
 }
#endif

#endif /* __TIZEN_NETWORK_TETHERING_H__ */


