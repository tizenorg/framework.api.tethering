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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib-object.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vconf.h>

#include "tethering.h"

#define INPUT_BUF_LEN		128
#define DISABLE_REASON_TEXT_LEN	64
#define COMMON_STR_BUF_LEN	32

typedef struct {
	tethering_enabled_cb enabled_cb;
	tethering_disabled_cb disabled_cb;
	tethering_connection_state_changed_cb changed_cb;
	tethering_wifi_security_type_changed_cb security_type_changed_cb;
	tethering_wifi_ssid_visibility_changed_cb ssid_visibility_changed_cb;
	tethering_wifi_passphrase_changed_cb passphrase_changed_cb;
} __tethering_cbs;

static GMainLoop *mainloop = NULL;

static bool __is_err(tethering_error_e ret)
{
	char *err_msg = NULL;

	switch (ret) {
	case TETHERING_ERROR_INVALID_PARAMETER:
		err_msg = "Wrong parameter is used";
		break;

	case TETHERING_ERROR_OUT_OF_MEMORY:
		err_msg = "Memory is not enough";
		break;

	case TETHERING_ERROR_NONE:
		return false;

	case TETHERING_ERROR_NOT_ENABLED:
		err_msg = "Tethering is not enabled";
		break;

	case TETHERING_ERROR_OPERATION_FAILED:
		err_msg = "Operation is failed";
		break;

	case TETHERING_ERROR_RESOURCE_BUSY:
		err_msg = "Resource is busy";
		break;

	default:
		err_msg = "This should not be happened";
		break;
	}

	g_print("%s\n", err_msg);

	return true;
}

static const char *__convert_tethering_type_to_str(const tethering_type_e type)
{
	static char str_buf[COMMON_STR_BUF_LEN] = {0, };

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(str_buf, "USB Tethering", sizeof(str_buf));
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(str_buf, "Wi-Fi Tethering", sizeof(str_buf));
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(str_buf, "Bluetooth Tethering", sizeof(str_buf));
		break;

	case TETHERING_TYPE_WIFI_AP:
		g_strlcpy(str_buf, "Wi-Fi AP", sizeof(str_buf));
		break;

	default:
		g_strlcpy(str_buf, "Unknown", sizeof(str_buf));
		break;
	}

	return str_buf;
}

static const char *__convert_disabled_code_to_str(const tethering_disabled_cause_e code)
{
	static char str_buf[DISABLE_REASON_TEXT_LEN] = {0, };

	switch (code) {
	case TETHERING_DISABLED_BY_USB_DISCONNECTION:
		strncpy(str_buf, "disabled due to usb disconnection", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_FLIGHT_MODE:
		strncpy(str_buf, "disabled due to flight mode on", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_LOW_BATTERY:
		strncpy(str_buf, "disabled due to low battery", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_NETWORK_CLOSE:
		strncpy(str_buf, "disabled due to pdp network close", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_TIMEOUT:
		strncpy(str_buf, "disabled due to timeout", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_OTHERS:
		strncpy(str_buf, "disabled by other apps", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_REQUEST:
		strncpy(str_buf, "disabled by my request", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_WIFI_ON:
		strncpy(str_buf, "disabled by Wi-Fi station on", sizeof(str_buf));
		break;

	case TETHERING_DISABLED_BY_BT_OFF:
		strncpy(str_buf, "disabled by bluetooth off", sizeof(str_buf));
		break;

	default:
		strncpy(str_buf, "disabled by unknown reason", sizeof(str_buf));
		break;
	}

	return str_buf;
}

static void __register_cbs(tethering_h th, __tethering_cbs *cbs, void *user_data)
{
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = tethering_set_enabled_cb(th, TETHERING_TYPE_ALL,
			cbs->enabled_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_enabled_cb is failed\n");
	}

	ret = tethering_set_enabled_cb(th, TETHERING_TYPE_WIFI_AP,
			cbs->enabled_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_enabled_cb is failed\n");
	}

	ret = tethering_set_disabled_cb(th, TETHERING_TYPE_ALL,
			cbs->disabled_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_disabled_cb is failed\n");
	}

	ret = tethering_set_disabled_cb(th, TETHERING_TYPE_WIFI_AP,
			cbs->disabled_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_disabled_cb is failed\n");
	}

	ret = tethering_set_connection_state_changed_cb(th, TETHERING_TYPE_ALL,
			cbs->changed_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_connection_state_changed_cb is failed\n");
	}

	ret = tethering_set_connection_state_changed_cb(th, TETHERING_TYPE_WIFI_AP,
			cbs->changed_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_set_connection_state_changed_cb is failed\n");
	}

	ret = tethering_wifi_set_security_type_changed_cb(th,
			cbs->security_type_changed_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_set_security_type_changed_cb is failed\n");
	}

	ret = tethering_wifi_set_ssid_visibility_changed_cb(th,
			cbs->ssid_visibility_changed_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_set_ssid_visibility_changed_cb is failed\n");
	}

	ret = tethering_wifi_set_passphrase_changed_cb(th,
			cbs->passphrase_changed_cb, user_data);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_set_passphrase_changed_cb is failed\n");
	}

	return;
}

static void __deregister_cbs(tethering_h th)
{
	tethering_error_e ret = TETHERING_ERROR_NONE;

	ret = tethering_unset_enabled_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_enabled_cb is failed\n");
	}

	ret = tethering_unset_enabled_cb(th, TETHERING_TYPE_WIFI_AP);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_enabled_cb is failed\n");
	}

	ret = tethering_unset_disabled_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_disabled_cb is failed\n");
	}

	ret = tethering_unset_disabled_cb(th, TETHERING_TYPE_WIFI_AP);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_disabled_cb is failed\n");
	}

	ret = tethering_unset_connection_state_changed_cb(th, TETHERING_TYPE_ALL);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_connection_state_changed_cb is failed\n");
	}

	ret = tethering_unset_connection_state_changed_cb(th, TETHERING_TYPE_WIFI_AP);
	if (__is_err(ret) == true) {
		g_print("tethering_unset_connection_state_changed_cb is failed\n");
	}

	ret = tethering_wifi_unset_security_type_changed_cb(th);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_unset_security_type_changed_cb is failed\n");
	}

	ret = tethering_wifi_unset_ssid_visibility_changed_cb(th);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_unset_ssid_visibility_changed_cb is failed\n");
	}

	ret = tethering_wifi_unset_passphrase_changed_cb(th);
	if (__is_err(ret) == true) {
		g_print("tethering_wifi_unset_passphrase_changed_cb is failed\n");
	}

	return;
}

/* Tethering callbacks */
static void __enabled_cb(tethering_error_e error, tethering_type_e type, bool is_requested, void *data)
{
	if (error != TETHERING_ERROR_NONE) {
		if (!is_requested) {
			return;
		}

		g_print("## %s is not enabled. error code[0x%X]\n",
				__convert_tethering_type_to_str(type),
				error);
		return;
	}

	if (is_requested)
		g_print("## %s is enabled successfully\n",
				__convert_tethering_type_to_str(type));
	else
		g_print("## %s is enabled by other app\n",
				__convert_tethering_type_to_str(type));

	return;
}

static void __disabled_cb(tethering_error_e error, tethering_type_e type, tethering_disabled_cause_e code, void *data)
{
	if (error != TETHERING_ERROR_NONE) {
		if (code != TETHERING_DISABLED_BY_REQUEST) {
			return;
		}

		g_print("## %s is not disabled. error code[0x%X]\n",
				__convert_tethering_type_to_str(type), error);
		return;
	}

	g_print("## %s is %s\n",
			__convert_tethering_type_to_str(type),
			__convert_disabled_code_to_str(code));

	return;
}

static void __connection_state_changed_cb(tethering_client_h client, bool open, void *data)
{
	tethering_client_h clone = NULL;
	tethering_type_e type;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;

	tethering_client_clone(&clone, client);
	if (clone == NULL) {
		g_print("tetheirng_client_clone is failed\n");
		return;
	}

	tethering_client_get_tethering_type(clone, &type);
	tethering_client_get_ip_address(clone,
			TETHERING_ADDRESS_FAMILY_IPV4, &ip_address);
	tethering_client_get_mac_address(clone, &mac_address);
	tethering_client_get_name(clone, &hostname);

	if (open) {
		g_print("## New station Type [%s], IP [%s], MAC [%s], hostname [%s]\n",
				__convert_tethering_type_to_str(type),
				ip_address, mac_address, hostname);
	} else {
		g_print("## Disconnected station Type [%s], IP [%s], MAC [%s], hostname [%s]\n",
				__convert_tethering_type_to_str(type),
				ip_address, mac_address, hostname);
	}

	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	tethering_client_destroy(clone);

	return;
}

static void __data_usage_cb(tethering_error_e result, unsigned long long received_data,
		unsigned long long sent_data, void *user_data)
{
	g_print("__data_usage_cb\n");

	if (result != TETHERING_ERROR_NONE) {
		g_print("tethering_get_data_usage is failed. error[0x%X]\n", result);
		return;
	}

	g_print("## Received data : %llu bytes\n", received_data);
	g_print("## Sent data : %llu bytes\n", sent_data);

	return;
}

static void __settings_reloaded_cb(tethering_error_e result, void *user_data)
{
	g_print("__settings_reloaded_cb\n");

	if (result != TETHERING_ERROR_NONE) {
		g_print("tethering_wifi_reload_settings is failed. error[0x%X]\n", result);
		return;
	}

	g_print("## Wi-Fi tethering setting is reloaded\n");

	return;
}

static bool __clients_foreach_cb(tethering_client_h client, void *data)
{
	tethering_client_h clone = NULL;
	tethering_type_e type;
	char *ip_address = NULL;
	char *mac_address = NULL;
	char *hostname = NULL;

	/* Clone internal information */
	if (tethering_client_clone(&clone, client) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_clone is failed\n");
		return false;
	}

	/* Get information */
	if (tethering_client_get_tethering_type(clone, &type) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_get_type is failed\n");
	}

	if (tethering_client_get_ip_address(clone, TETHERING_ADDRESS_FAMILY_IPV4, &ip_address) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_get_ip_address is failed\n");
	}

	if (tethering_client_get_mac_address(clone, &mac_address) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_get_mac_address is failed\n");
	}

	if (tethering_client_get_name(clone, &hostname) != TETHERING_ERROR_NONE) {
		g_print("tethering_client_get_hostname is failed\n");
	}
	/* End of getting information */

	g_print("\n< Client Info. >\n");
	g_print("\tType %s\n", __convert_tethering_type_to_str(type));
	g_print("\tIP Address %s\n", ip_address);
	g_print("\tMAC Address : %s\n", mac_address);
	g_print("\tHostname : %s\n", hostname);

	/* Destroy cloned objects */
	if (ip_address)
		free(ip_address);
	if (mac_address)
		free(mac_address);
	if (hostname)
		free(hostname);

	tethering_client_destroy(clone);

	/* Continue iteration */
	return true;
}

static void __security_type_changed_cb(tethering_wifi_security_type_e changed_type, void *user_data)
{
	g_print("Wi-Fi Tethering Security type is changed to [%s]\n",
			changed_type == TETHERING_WIFI_SECURITY_TYPE_NONE ?
			"open" : "wpa2-psk");
	return;
}

static void __ssid_visibility_changed_cb(bool changed_visible, void *user_data)
{
	g_print("SSID visibility for Wi-Fi tethering changed to [%s]\n",
			changed_visible ? "visible" : "invisible");
	return;
}

static void __passphrase_changed_cb(void *user_data)
{
	g_print("Wi-Fi Tethering passphrase is changed\n");
	return;
}
/* End of tethering callbacks */

static void __enable_tethering(tethering_h th, tethering_type_e type)
{
	if (th == NULL)
		return;

	tethering_error_e error = TETHERING_ERROR_NONE;

	error = tethering_enable(th, type);
	__is_err(error);

	return;
}

static void __disable_tethering(tethering_h th, tethering_type_e type)
{
	if (th == NULL)
		return;

	tethering_error_e error = TETHERING_ERROR_NONE;

	error = tethering_disable(th, type);
	__is_err(error);

	return;
}

static void __print_interface_info(tethering_h th, tethering_type_e type)
{
	char *interface = NULL;
	char *mac_address = NULL;
	char *ip_address = NULL;
	char *gateway_address = NULL;
	char *subnet_mask = NULL;

	if (tethering_is_enabled(th, type) == FALSE) {
		g_print("%s is not enabled\n",
				__convert_tethering_type_to_str(type));
		return;
	}

	tethering_get_network_interface_name(th, type, &interface);
	tethering_get_mac_address(th, type, &mac_address);
	tethering_get_ip_address(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&ip_address);
	tethering_get_gateway_address(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&gateway_address);
	tethering_get_subnet_mask(th, type, TETHERING_ADDRESS_FAMILY_IPV4,
			&subnet_mask);

	g_print("interface name : %s\n", interface);
	g_print("mac address : %s\n", mac_address);
	g_print("ip address : %s\n", ip_address);
	g_print("gateway address: %s\n", gateway_address);
	g_print("subnet mask : %s\n", subnet_mask);

	if (interface)
		free(interface);
	if (mac_address)
		free(mac_address);
	if (ip_address)
		free(ip_address);
	if (gateway_address)
		free(gateway_address);
	if (subnet_mask)
		free(subnet_mask);

	return;
}

static void __print_wifi_tethering_setting(tethering_h th)
{
	char *ssid = NULL;
	char *passphrase = NULL;
	bool visibility = false;
	tethering_wifi_security_type_e security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;

	int error = TETHERING_ERROR_NONE;

	error = tethering_wifi_get_ssid(th, &ssid);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\n\t** WiFi tethering SSID : %s\n", ssid);

	error = tethering_wifi_get_passphrase(th, &passphrase);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering passphrase : %s\n", passphrase);

	error = tethering_wifi_get_ssid_visibility(th, &visibility);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering ssid visibility : %s\n",
				visibility ? "visible" : "invisible");

	error = tethering_wifi_get_security_type(th, &security_type);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi tethering security_type : %s\n",
				security_type ==
				TETHERING_WIFI_SECURITY_TYPE_NONE ?
				"open" : "wpa2-psk");

	if (ssid)
		free(ssid);
	if (passphrase)
		free(passphrase);

	return;
}

static void __print_wifi_ap_setting(tethering_h th)
{
	char *ssid = NULL;
	char *passphrase = NULL;
	bool visibility = false;
	tethering_wifi_security_type_e security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;

	int error = TETHERING_ERROR_NONE;

	error = tethering_wifi_ap_get_ssid(th, &ssid);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\n\t** WiFi AP SSID : %s\n", ssid);

	error = tethering_wifi_ap_get_passphrase(th, &passphrase);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi AP passphrase : %s\n", passphrase);

	error = tethering_wifi_ap_get_ssid_visibility(th, &visibility);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi AP ssid visibility : %s\n",
				visibility ? "visible" : "invisible");

	error = tethering_wifi_ap_get_security_type(th, &security_type);
	if (error != TETHERING_ERROR_NONE)
		__is_err(error);
	else
		g_print("\t** WiFi AP security_type : %s\n",
				security_type ==
				TETHERING_WIFI_SECURITY_TYPE_NONE ?
				"open" : "wpa2-psk");

	if (ssid)
		free(ssid);
	if (passphrase)
		free(passphrase);

	return;
}

void print_menu(void)
{
	g_print("\nTo get client information, enter 'clients [USB | WIFI | BT | AP | ALL]'");
	g_print("\nTo get interface information, enter 'info [USB | WIFI | BT | AP]'");
	g_print("\nTo get data usage, enter 'get data_usage'");
	g_print("\nTo enable tethering, enter 'enable [USB | WIFI | BT | AP | ALL]'");
	g_print("\nTo disable tethering, enter 'disable [USB | WIFI | BT | AP | ALL]'");
	g_print("\nTo get Wi-Fi tethering setting, enter 'get wifi_setting'");
	g_print("\nTo get Wi-Fi AP setting, enter 'get wifi_ap_setting'");
	g_print("\nTo reload Wi-Fi tethering setting, enter 'reload wifi_setting'");
	g_print("\nTo reload Wi-Fi AP setting, enter 'reload wifi_ap_setting'");
	g_print("\nTo set Wi-Fi tethering setting, enter '[set_security_type | set_visibility] [0 | 1]'");
	g_print("\nTo set Wi-Fi AP setting, enter '[set_ap_security_type | set_ap_visibility] [0 | 1]'");
	g_print("\nTo set Wi-Fi tethering passphrase, enter 'set_passphrase [passphrase]'");
	g_print("\nTo set Wi-Fi AP passphrase, enter 'set_ap_passphrase [passphrase]'");
	g_print("\nTo set Wi-Fi tethering SSID, enter 'set_ssid [SSID]'");
	g_print("\nTo set Wi-Fi AP SSID, enter 'set_ap_ssid [SSID]'");
	g_print("\nTo quit, enter 'quit'\n> ");

	return;
}

gboolean input(GIOChannel *channel, GIOCondition condition, gpointer data)
{
	tethering_h th = (tethering_h)data;
	tethering_type_e type = 0;
	tethering_error_e error = 0;
	gchar buf[INPUT_BUF_LEN] = {0, };
	gchar *cmd = NULL;
	gchar *param = NULL;
	gsize read = 0;

#if !GLIB_CHECK_VERSION(2, 31, 0)
	if (g_io_channel_read(channel, buf, INPUT_BUF_LEN, &read) != G_IO_ERROR_NONE) {
		g_print("g_io_channel_read is failed\n");
		return FALSE;
	}
#else
	GError *err = NULL;
	GIOStatus ios;

	ios = g_io_channel_read_chars(channel, buf, INPUT_BUF_LEN, &read, &err);
	if (err != NULL) {
		g_print("g_io_channel_read_chars is failed : %s\n",
				err->message);
		g_error_free(err);
		return FALSE;
	} else if (ios != G_IO_STATUS_NORMAL) {
		g_print("g_io_channel_read_chars is failed : %d\n", ios);
		return FALSE;
	}
#endif

	buf[read] = '\0';
	g_strstrip(buf);

	cmd = buf;
	param = strrchr(buf, ' ');

	/* No parameter */
	if (!strcmp(cmd, "quit")) {
		g_main_loop_quit(mainloop);
		return TRUE;
	}

	if (param == NULL) {
		print_menu();
		return TRUE;
	}
	*param = '\0';
	param++;

	/* One parameter except type */
	if (!strcmp(cmd, "get") && !strcmp(param, "data_usage")) {
		error = tethering_get_data_usage(th, __data_usage_cb, NULL);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_get_data_usage is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "get") && !strcmp(param, "wifi_setting")) {
		__print_wifi_tethering_setting(th);
		goto DONE;
	}

	if (!strcmp(cmd, "get") && !strcmp(param, "wifi_ap_setting")) {
		__print_wifi_ap_setting(th);
		goto DONE;
	}

	if (!strcmp(cmd, "reload") && !strcmp(param, "wifi_setting")) {
		error = tethering_wifi_reload_settings(th, __settings_reloaded_cb, NULL);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_reload_settings is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "reload") && !strcmp(param, "wifi_ap_setting")) {
		error = tethering_wifi_ap_reload_settings(th, __settings_reloaded_cb, NULL);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_ap_reload_settings is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_visibility")) {
		error = tethering_wifi_set_ssid_visibility(th, atoi(param));
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_set_ssid_visibility is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_ap_visibility")) {
		error = tethering_wifi_ap_set_ssid_visibility(th, atoi(param));
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_ap_set_ssid_visibility is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_security_type")) {
		error = tethering_wifi_set_security_type(th, atoi(param));
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_set_security_type is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_ap_security_type")) {
		error = tethering_wifi_ap_set_security_type(th, atoi(param));
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_ap_set_security_type is failed [0x%X]\n",
					error);
		goto DONE;
	}

	/* This should be removed */
	if (!strcmp(cmd, "set_passphrase")) {
		error = tethering_wifi_set_passphrase(th, param);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_set_passphrase is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_ap_passphrase")) {
		error = tethering_wifi_ap_set_passphrase(th, param);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_ap_set_passphrase is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_ssid")) {
		error = tethering_wifi_set_ssid(th, param);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_set_ssid is failed [0x%X]\n",
					error);
		goto DONE;
	}

	if (!strcmp(cmd, "set_ap_ssid")) {
		error = tethering_wifi_ap_set_ssid(th, param);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_wifi_ap_set_ssid is failed [0x%X]\n",
				error);
		goto DONE;
	}

	/* One parameter(type) */
	if (!strcmp(param, "USB"))
		type = TETHERING_TYPE_USB;
	else if (!strcmp(param, "WIFI"))
		type = TETHERING_TYPE_WIFI;
	else if (!strcmp(param, "BT"))
		type = TETHERING_TYPE_BT;
	else if (!strcmp(param, "AP"))
		type = TETHERING_TYPE_WIFI_AP;
	else if (!strcmp(param, "ALL"))
		type = TETHERING_TYPE_ALL;
	else {
		goto DONE;
	}

	if (!strcmp(cmd, "clients")) {
		error = tethering_foreach_connected_clients(th, type,
				__clients_foreach_cb, NULL);
		if (error != TETHERING_ERROR_NONE)
			g_print("tethering_get_data_usage is failed [0x%X]\n",
					error);
	} else if (!strcmp(cmd, "info")) {
		__print_interface_info(th, type);
	} else if (!strcmp(cmd, "enable")) {
		__enable_tethering(th, type);
	} else if (!strcmp(cmd, "disable")) {
		__disable_tethering(th, type);
	} else {
		goto DONE;
	}

DONE:
	print_menu();
	return TRUE;
}

int main(int argc, char *argv[])
{
	tethering_h th = NULL;
	GIOChannel *stdin_channel = NULL;
	tethering_error_e ret = TETHERING_ERROR_NONE;
	__tethering_cbs cbs = {
		__enabled_cb, __disabled_cb,
		__connection_state_changed_cb, __security_type_changed_cb,
		__ssid_visibility_changed_cb, __passphrase_changed_cb};

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif

	/* Create tethering handle */
	ret = tethering_create(&th);
	if (__is_err(ret) == true)
		return 0;

	/* Register cbs */
	__register_cbs(th, &cbs, NULL);

	stdin_channel = g_io_channel_unix_new(0);
	if (stdin_channel == NULL)
		return 0;

	g_io_channel_set_encoding(stdin_channel, NULL, NULL);
	g_io_channel_set_flags(stdin_channel,
			G_IO_FLAG_APPEND | G_IO_FLAG_NONBLOCK, NULL);

	g_io_add_watch(stdin_channel, G_IO_IN, input, (gpointer)th);

	print_menu();

	mainloop = g_main_loop_new (NULL, 0);

	g_main_loop_run(mainloop);
	g_main_loop_unref(mainloop);

	/* Deregister cbs */
	__deregister_cbs(th);

	/* Destroy tethering handle */
	ret = tethering_destroy(th);
	__is_err(ret);

	return 0;
}
