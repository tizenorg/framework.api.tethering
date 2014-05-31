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
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @brief The handle for tethering.
 */
typedef void * tethering_h;

/**
 * @brief Enumeration for the tethering.
 */
typedef enum {
    TETHERING_ERROR_NONE = TIZEN_ERROR_NONE,  /**< Successful */
    TETHERING_ERROR_NOT_PERMITTED = TIZEN_ERROR_NOT_PERMITTED,  /**< Operation not permitted */
    TETHERING_ERROR_INVALID_PARAMETER = TIZEN_ERROR_INVALID_PARAMETER,  /**< Invalid parameter */
    TETHERING_ERROR_OUT_OF_MEMORY = TIZEN_ERROR_OUT_OF_MEMORY,  /**< Out of memory */
    TETHERING_ERROR_RESOURCE_BUSY = TIZEN_ERROR_RESOURCE_BUSY,  /**< Resource busy */
    TETHERING_ERROR_NOT_ENABLED = TIZEN_ERROR_NETWORK_CLASS | 0x0501,  /**< Not enabled */
    TETHERING_ERROR_OPERATION_FAILED = TIZEN_ERROR_NETWORK_CLASS | 0x0502,  /**< Operation failed */
    TETHERING_ERROR_INVALID_OPERATION = TIZEN_ERROR_INVALID_OPERATION, /**< Invalid operation */
    TETHERING_ERROR_NOT_SUPPORT_API = TIZEN_ERROR_NOT_SUPPORT_API, /**< API is not supported */
} tethering_error_e;

/**
 * @brief Enumeration for the type of tethering.
 */
typedef enum {
    TETHERING_TYPE_ALL = 0,  /**< All type except for TETHERING_TYPE_WIFI_AP */
    TETHERING_TYPE_USB,  /**< USB type */
    TETHERING_TYPE_WIFI,  /**< Wi-Fi type */
    TETHERING_TYPE_BT,  /**< BT type */
    TETHERING_TYPE_WIFI_AP,  /**< Wi-Fi AP type which is the same as TETHERING_TYPE_WIFI but remote device is unable to use internet.
			       When Wi-Fi AP is enabled, other type tethering cannot be enabled.
			       When other type tethering is enabled, Wi-Fi AP cannot be enabled. */
} tethering_type_e;

/**
 * @brief Enumeration for the cause of disabling the tethering.
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
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @brief Enumeration for the Wi-Fi security.
 */
typedef enum {
    TETHERING_WIFI_SECURITY_TYPE_NONE = 0,  /**< No Security type */
    TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK,  /**< WPA2_PSK */
} tethering_wifi_security_type_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @brief The handle for tethering client.
 */
typedef void * tethering_client_h;

/**
 * @brief Enumerations of Address family
 */
typedef enum {
    TETHERING_ADDRESS_FAMILY_IPV4 = 0,  /**< IPV4 Address type */
} tethering_address_family_e;

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_MANAGER_MODULE
 * @{
 */

/**
 * @brief  Called when the tethering is enabled.
 * @param[in]  result  The result of enabling the tethering
 * @param[in]  type  The type of tethering
 * @param[in]  is_requested  Indicates whether this change is requested by you
 * @param[in]  user_data  The user data passed from tethering_set_enabled_cb()
 * @pre  If you register callback function using tethering_set_enabled_cb(), this will be invoked when the tethering is enabled.
 * @see	tethering_enable()
 * @see	tethering_unset_enabled_cb()
 */
typedef void (*tethering_enabled_cb)(tethering_error_e result, tethering_type_e type, bool is_requested, void *user_data);

/**
 * @brief  Called when the tethering is disabled.
 * @param[in]  result  The result of disabling the tethering
 * @param[in]  type  The type of tethering
 * @param[in]  cause  The cause of disabling
 * @param[in]  user_data  The user data passed from tethering_set_disabled_cb()
 * @pre  If you register callback function using tethering_set_disabled_cb(), this will be invoked when the tethering is disabled.
 * @see	tethering_set_disabled_cb()
 * @see	tethering_unset_disabled_cb()
 */
typedef void (*tethering_disabled_cb)(tethering_error_e result, tethering_type_e type, tethering_disabled_cause_e cause, void *user_data);

/**
 * @brief  Called when the connection state is changed.
 * @remakrs  @c tethering_client_h is valid only in this function. In order to use it outside this function, you must copy the client with tethering_client_clone().
 * @param[in]  client  The client of which connection state is changed
 * @param[in]  opened  @c true when connection is opened, otherwise false
 * @param[in]  user_data  The user data passed from tethering_set_connection_state_changed_cb()
 * @pre  If you register callback function using tethering_set_connection_state_changed_cb(), this will be invoked when the connection state is changed.
 * @see	tethering_set_connection_state_changed_cb()
 * @see	tethering_unset_connection_state_changed_cb()
 */
typedef void (*tethering_connection_state_changed_cb)(tethering_client_h client, bool opened, void *user_data);

/**
 * @brief Called when you get the connected client repeatedly.
 * @remarks  @a client is valid only in this function. In order to use the client outside this function, you must copy the client with tethering_client_clone().
 * @param[in]  client  The connected client
 * @param[in]  user_data  The user data passed from the request function
 * @return  @c true to continue with the next iteration of the loop, \n @c false to break out of the loop
 * @pre  tethering_foreach_connected_clients() will invoke this callback.
 * @see  tethering_foreach_connected_clients()
 */
typedef bool(*tethering_connected_client_cb)(tethering_client_h client, void *user_data);

/**
 * @brief  Called when you get the data usage.
 * @param[in]  result  The result of getting the data usage
 * @param[in]  received_data  The usage of received data
 * @param[in]  sent_data  The usage of sent data
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_get_data_usage() will invoked this callback
 */
typedef void (*tethering_data_usage_cb)(tethering_error_e result, unsigned long long received_data, unsigned long long sent_data, void *user_data);

/**
 * @brief  Called when the security type of Wi-Fi tethering is changed
 * @param[in]  changed_type  The changed security type of Wi-Fi tethering
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_security_type_changed_cb()
 * @see	tethering_wifi_unset_security_type_changed_cb()
 */
typedef void (*tethering_wifi_security_type_changed_cb)(tethering_wifi_security_type_e changed_type, void *user_data);

/**
 * @brief  Called when the visibility of SSID is changed
 * @param[in]  changed_visible  The changed visibility of SSID
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_ssid_visibility_changed_cb()
 * @see	tethering_wifi_unset_ssid_visibility_changed_cb()
 */
typedef void (*tethering_wifi_ssid_visibility_changed_cb)(bool changed_visible, void *user_data);

/**
 * @brief  Called when the passphrase of Wi-Fi tethering is changed
 * @param[in]  user_data  The user data passed from the register function
 * @see	tethering_wifi_set_passphrase_changed_cb()
 * @see	tethering_wifi_unset_passphrase_changed_cb()
 */
typedef void (*tethering_wifi_passphrase_changed_cb)(void *user_data);

/**
 * @brief  Called when the settings are reloaded
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_wifi_reload_settings() will invoke this callback
 */
typedef void (*tethering_wifi_settings_reloaded_cb)(tethering_error_e result, void *user_data);

/**
 * @brief  Called when Wi-Fi AP settings are reloaded
 * @param[in]  result  The result of reloading the settings
 * @param[in]  user_data  The user data passed from the request function
 * @pre  tethering_wifi_ap_reload_settings() will invoke this callback
 */
typedef void (*tethering_wifi_ap_settings_reloaded_cb)(tethering_error_e result, void *user_data);

/**
 * @brief  Creates the handle of tethering.
 * @remarks  The @a tethering must be released tethering_destroy() by you.
 * @param[out]  tethering  A handle of a new mobile ap handle on success
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_NOT_SUPPORT_API  API is not supported
 * @see  tethering_destroy()
 */
int tethering_create(tethering_h *tethering);

/**
 * @brief  Destroys the handle of tethering.
 * @param[in]  tethering  The handle of tethering
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_create()
 */
int tethering_destroy(tethering_h tethering);

/**
 * @brief Enables the tethering, asynchronously.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_enabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_disable()
 */
int tethering_enable(tethering_h tethering, tethering_type_e type);

/**
 * @brief Disables the tethering, asynchronously.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @post tethering_disabled_cb() will be invoked.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_disable(tethering_h tethering, tethering_type_e type);

/**
 * @brief  Checks whetehr the tethering is enabled or not.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return  @c true if tethering is enabled, \n @c false if tethering is disabled.
 */
bool tethering_is_enabled(tethering_h tethering, tethering_type_e type);

/**
 * @brief  Gets the MAC address of local device as "FC:A1:3E:D6:B1:B1".
 * @remarks @a mac_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_mac_address(tethering_h tethering, tethering_type_e type, char **mac_address);

/**
 * @brief Gets the name of network interface. For example, usb0.
 * @remarks @a interface_name must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[out]  interface_name  The name of network interface
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_network_interface_name(tethering_h tethering, tethering_type_e type, char **interface_name);

/**
 * @brief Gets the local IP address.
 * @remarks @a ip_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  ip_address  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_ip_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **ip_address);

/**
 * @brief Gets the Gateway address.
 * @remarks @a gateway_address must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  gateway_address  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_gateway_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **gateway_address);

/**
 * @brief Gets the Subnet Mask.
 * @remarks @a subnet_mask must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  subnet_mask  The local IP address
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_subnet_mask(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **subnet_mask);

/**
 * @brief Gets the data usage.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  usage  The data usage
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_get_data_usage(tethering_h tethering, tethering_data_usage_cb callback, void *user_data);

/**
 * @brief Gets the clients which are connected.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_NOT_ENABLED  Not enabled
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @pre  tethering must be enabled.
 * @see  tethering_is_enabled()
 * @see  tethering_enable()
 */
int tethering_foreach_connected_clients(tethering_h tethering, tethering_type_e type, tethering_connected_client_cb callback, void *user_data);

/**
 * @brief Registers the callback function called when tethering is enabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_enabled_cb()
 */
int tethering_set_enabled_cb(tethering_h tethering, tethering_type_e type, tethering_enabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when tethering is disabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_enabled_cb()
 */
int tethering_unset_enabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function called when tethering is disabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_disabled_cb()
 */
int tethering_set_disabled_cb(tethering_h tethering, tethering_type_e type, tethering_disabled_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when tethering is disabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_disabled_cb()
 */
int tethering_unset_disabled_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function called when the state of connection is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_unset_connection_state_changed_cb_cb()
 */
int tethering_set_connection_state_changed_cb(tethering_h tethering, tethering_type_e type, tethering_connection_state_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when the state of connection is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_connection_state_changed_cb()
 */
int tethering_unset_connection_state_changed_cb(tethering_h tethering, tethering_type_e type);

/**
 * @brief Registers the callback function called when the security type of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_security_type_changed_cb()
 */
int tethering_wifi_set_security_type_changed_cb(tethering_h tethering, tethering_wifi_security_type_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when the security type of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_security_type_changed_cb()
 */
int tethering_wifi_unset_security_type_changed_cb(tethering_h tethering);

/**
 * @brief Registers the callback function called when the visibility of SSID is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_ssid_visibility_changed_cb_cb()
 */
int tethering_wifi_set_ssid_visibility_changed_cb(tethering_h tethering, tethering_wifi_ssid_visibility_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when the visibility of SSID is changed.
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_ssid_visibility_changed_cb()
 */
int tethering_wifi_unset_ssid_visibility_changed_cb(tethering_h tethering);

/**
 * @brief Registers the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_passphrase_changed_cb()
 */
int tethering_wifi_set_passphrase_changed_cb(tethering_h tethering, tethering_wifi_passphrase_changed_cb callback, void *user_data);

/**
 * @brief Unregisters the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_passphrase_changed_cb()
 */
int tethering_wifi_unset_passphrase_changed_cb(tethering_h tethering);

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_WIFI_MODULE
 * @{
 */

/**
 * @brief Sets the security type of Wi-Fi tethering.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_security_type()
 */
int tethering_wifi_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type);

/**
 * @brief Gets the security type of Wi-Fi tethering.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_security_type()
 */
int tethering_wifi_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type);

/**
 * @brief Sets the SSID (service set identifier). The SSID cannot exceed 32 bytes.
 * @details If SSID is not set, Device name is used as SSID
 * @remarks This change is applied next time Wi-Fi tethering is enabled with same @a tethering handle
 * @param[in]  tethering  The handle of tethering
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_set_ssid(tethering_h tethering, const char *ssid);

/**
 * @brief Gets the SSID (service set identifier).
 * @remarks @a ssid must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_get_ssid(tethering_h tethering, char **ssid);

/**
 * @brief Sets the visibility of SSID(service set identifier).
 * @details If you set the visibility invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_ssid_visibility()
 */
int tethering_wifi_set_ssid_visibility(tethering_h tethering, bool visible);

/**
 * @brief Gets the visibility of SSID(service set identifier).
 * @details If the visibility is set invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_ssid_visibility()
 */
int tethering_wifi_get_ssid_visibility(tethering_h tethering, bool *visible);

/**
 * @brief Sets the passphrase.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_get_passphrase()
 */
int tethering_wifi_set_passphrase(tethering_h tethering, const char *passphrase);

/**
 * @brief Gets the passphrase.
 * @remarks @a passphrase must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_set_passphrase()
 */
int tethering_wifi_get_passphrase(tethering_h tethering, char **passphrase);

/**
 * @brief Reload the settings (SSID / Passphrase / Security type / SSID visibility).
 * @remarks Connected devices via Wi-Fi tethering or MobileAP will be disconnected when the settings are reloaded
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_reload_settings(tethering_h tethering, tethering_wifi_settings_reloaded_cb callback, void *user_data);

/**
 * @brief Sets the security type of Wi-Fi AP.
 * @details If security type is not set, WPA2_PSK is used
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_security_type()
 */
int tethering_wifi_ap_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type);

/**
 * @brief Gets the security type of Wi-Fi AP.
 * @details If security type is not set, WPA2_PSK is used
 * @param[in]  tethering  The handle of tethering
 * @param[out]  type  The security type
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_security_type()
 */
int tethering_wifi_ap_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type);

/**
 * @brief Sets the SSID (service set identifier) for Wi-Fi AP. The SSID cannot exceed 32 bytes.
 * @details If SSID is not set, Device name is used as SSID
 * @param[in]  tethering  The handle of tethering
 * @param[in]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_ap_set_ssid(tethering_h tethering, const char *ssid);

/**
 * @brief Gets the SSID (service set identifier) for Wi-Fi AP.
 * @details If SSID is not set, Device name is used as SSID
 * @remarks @a ssid must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
int tethering_wifi_ap_get_ssid(tethering_h tethering, char **ssid);

/**
 * @brief Sets the visibility of SSID(service set identifier) for Wi-Fi AP.
 * @details If you set the visibility invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @details by default visibility is set to true.
 * @remarks This change is applied next time Wi-Fi tethering is enabled
 * @param[in]  tethering  The handle of tethering
 * @param[in]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_wifi_ap_get_ssid_visibility()
 */
int tethering_wifi_ap_set_ssid_visibility(tethering_h tethering, bool visible);

/**
 * @brief Gets the visibility of SSID(service set identifier) for Wi-Fi AP.
 * @details If the visibility is set invisible, then the SSID of this device is hidden. So, Wi-Fi scan can't find your device.
 * @details by default visibility is set to true.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  visible  The visibility of SSID: (@c true = visible, @c false = invisible)
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_set_ssid_visibility()
 */
int tethering_wifi_ap_get_ssid_visibility(tethering_h tethering, bool *visible);

/**
 * @brief Sets the passphrase for Wi-Fi AP.
 * @details If the passphrase is not set, random string of 8 alphabets will be used.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_ap_get_passphrase()
 */
int tethering_wifi_ap_set_passphrase(tethering_h tethering, const char *passphrase);

/**
 * @brief Gets the passphrase for Wi-Fi AP.
 * @details If the passphrase is not set, random string of 8 alphabets will be used.
 * @remarks @a passphrase must be released with free() by you.
 * @param[in]  tethering  The handle of tethering
 * @param[out]  passphrase  The passphrase
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_wifi_ap_set_passphrase()
 */
int tethering_wifi_ap_get_passphrase(tethering_h tethering, char **passphrase);

/**
 * @brief Reload the settings (SSID / Passphrase / Security type / SSID visibility) for Wi-Fi AP.
 * @remarks Connected devices via MobileAP will be disconnected when the settings are reloaded
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 */
int tethering_wifi_ap_reload_settings(tethering_h tethering, tethering_wifi_ap_settings_reloaded_cb callback, void *user_data);

/**
 * @}
 */


/**
 * @addtogroup CAPI_NETWORK_TETHERING_CLIENT_MODULE
 * @{
 */

/**
 * @brief  Clones the handle of client.
 * @remarks  The @cloned_client must be release tethering_client_destroy() by you.
 * @param[out]  dest  The cloned client handle
 * @param[in]  origin  The origin client handle
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_client_destroy()
 */
int tethering_client_clone(tethering_client_h *dest, tethering_client_h origin);

/**
 * @brief  Destroys the handle of client.
 * @param[in]  client  The handle of client
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_client_clone()
 */
int tethering_client_destroy(tethering_client_h client);

/**
 * @brief  Gets the tethering type of client.
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
 * @brief  Gets the name of client.
 * @remarks @a name must be released with free() by you.
 * @param[in]  client  The handle of client
 * @param[out]  name  The name of client
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_name(tethering_client_h client, char **name);

/**
 * @brief  Gets the IP address of client.
 * @remarks @a ip_address must be released with free() by you.
 * @param[in]  client  The handle of client
 * @param[in]  address_family  The address family of IP address. Currently, #TETHERING_ADDRESS_FAMILY_IPV4 is only supported.
 * @param[out]  ip_address  The IP address
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_ip_address(tethering_client_h client, tethering_address_family_e address_family, char **ip_address);

/**
 * @brief  Gets the MAC address of client such as "FC:A1:3E:D6:B1:B1".
 * @remarks @a mac_address must be released with free() by you.
 * @param[in]  client  The handle of client
 * @param[out]  mac_address  The MAC address
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 * @see  tethering_usb_get_connected_client()
 * @see  tethering_connection_state_changed_cb()
 */
int tethering_client_get_mac_address(tethering_client_h client, char **mac_address);

/**
 * @brief  Gets the connection time of client.
 * @param[in]  client  The handle of client
 * @param[out]  time  The connected time of client
 * @return  0 on success, otherwise a negative error value.
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


