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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <vconf.h>

#include "tethering-client-stub.h"
#include "marshal.h"
#include "tethering_private.h"

static void __handle_wifi_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_wifi_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_usb_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_usb_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_bt_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_bt_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_net_closed(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_no_data_timeout(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_low_battery_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_flight_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_security_type_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_ssid_visibility_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data);
static void __handle_passphrase_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data);

static __tethering_sig_t sigs[] = {
	{SIGNAL_NAME_NET_CLOSED, __handle_net_closed},
	{SIGNAL_NAME_WIFI_TETHER_ON, __handle_wifi_tether_on},
	{SIGNAL_NAME_WIFI_TETHER_OFF, __handle_wifi_tether_off},
	{SIGNAL_NAME_USB_TETHER_ON, __handle_usb_tether_on},
	{SIGNAL_NAME_USB_TETHER_OFF, __handle_usb_tether_off},
	{SIGNAL_NAME_BT_TETHER_ON, __handle_bt_tether_on},
	{SIGNAL_NAME_BT_TETHER_OFF, __handle_bt_tether_off},
	{SIGNAL_NAME_NO_DATA_TIMEOUT, __handle_no_data_timeout},
	{SIGNAL_NAME_LOW_BATTERY_MODE, __handle_low_battery_mode},
	{SIGNAL_NAME_FLIGHT_MODE, __handle_flight_mode},
	{SIGNAL_NAME_SECURITY_TYPE_CHANGED, __handle_security_type_changed},
	{SIGNAL_NAME_SSID_VISIBILITY_CHANGED, __handle_ssid_visibility_changed},
	{SIGNAL_NAME_PASSPHRASE_CHANGED, __handle_passphrase_changed},
	{"", NULL}};

static bool __any_tethering_is_enabled(tethering_h tethering)
{
	if (tethering_is_enabled(tethering, TETHERING_TYPE_USB) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_WIFI) ||
			tethering_is_enabled(tethering, TETHERING_TYPE_BT))
		return true;

	return false;
}

static tethering_error_e __get_error(int agent_error)
{
	tethering_error_e err = TETHERING_ERROR_NONE;

	switch (agent_error) {
	case MOBILE_AP_ERROR_NONE:
		err = TETHERING_ERROR_NONE;
		break;

	case MOBILE_AP_ERROR_RESOURCE:
		err = TETHERING_ERROR_OUT_OF_MEMORY;
		break;

	case MOBILE_AP_ERROR_INTERNAL:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_INVALID_PARAM:
		err = TETHERING_ERROR_INVALID_PARAMETER;
		break;

	case MOBILE_AP_ERROR_ALREADY_ENABLED:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NOT_ENABLED:
		err = TETHERING_ERROR_NOT_ENABLED;
		break;

	case MOBILE_AP_ERROR_NET_OPEN:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NET_CLOSE:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_DHCP:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_IN_PROGRESS:
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;

	case MOBILE_AP_ERROR_NOT_PERMITTED:
		err = TETHERING_ERROR_NOT_PERMITTED;
		break;

	default:
		ERR("Not defined error : %d\n", agent_error);
		err = TETHERING_ERROR_OPERATION_FAILED;
		break;
	}

	return err;
}

static void __handle_dhcp(DBusGProxy *proxy, const char *member,
		guint interface, const char *ip, const char *mac,
		const char *name, guint timestamp, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	bool opened = false;
	tethering_type_e type = 0;
	tethering_connection_state_changed_cb ccb = NULL;
	__tethering_client_h client = {0, };
	void *data = NULL;

	if (!g_strcmp0(member, "DhcpConnected")) {
		opened = true;
	} else if (!g_strcmp0(member, "DhcpLeaseDeleted")) {
		opened = false;
	} else {
		ERR("Unknown event [%s]\n", member);
		return;
	}

	if (interface == MOBILE_AP_TYPE_USB)
		type = TETHERING_TYPE_USB;
	else if (interface == MOBILE_AP_TYPE_WIFI)
		type = TETHERING_TYPE_WIFI;
	else if (interface == MOBILE_AP_TYPE_BT)
		type = TETHERING_TYPE_BT;
	else {
		ERR("Not supported tethering type [%d]\n", interface);
		return;
	}

	ccb = th->changed_cb[type];
	if (ccb == NULL)
		return;
	data = th->changed_user_data[type];

	client.interface = type;
	g_strlcpy(client.ip, ip, sizeof(client.ip));
	g_strlcpy(client.mac, mac, sizeof(client.mac));
	g_strlcpy(client.hostname, name, sizeof(client.hostname));
	client.tm = (time_t)timestamp;

	ccb((tethering_client_h)&client, opened, data);

	return;
}

static void __handle_net_closed(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_NETWORK_CLOSE;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}

	return;
}

static void __handle_wifi_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_WIFI;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_wifi_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_WIFI;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_WIFI_ON;
	else if (!g_strcmp0(value_name, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_usb_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_USB;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_usb_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_USB;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_USB_DISCONNECTION;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_bt_tether_on(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_BT;
	bool is_requested = false;
	tethering_enabled_cb ecb = NULL;
	void *data = NULL;

	ecb = th->enabled_cb[type];
	if (ecb == NULL)
		return;
	data = th->enabled_user_data[type];

	ecb(TETHERING_ERROR_NONE, type, is_requested, data);
}

static void __handle_bt_tether_off(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = TETHERING_TYPE_BT;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_OTHERS;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	dcb = th->disabled_cb[type];
	if (dcb == NULL)
		return;
	data = th->disabled_user_data[type];

	if (!g_strcmp0(value_name, SIGNAL_MSG_NOT_AVAIL_INTERFACE))
		code = TETHERING_DISABLED_BY_BT_OFF;
	else if (!g_strcmp0(value_name, SIGNAL_MSG_TIMEOUT))
		code = TETHERING_DISABLED_BY_TIMEOUT;

	dcb(TETHERING_ERROR_NONE, type, code, data);

	return;
}

static void __handle_no_data_timeout(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_TIMEOUT;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_low_battery_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_LOW_BATTERY;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_flight_mode(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_type_e type = 0;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_FLIGHT_MODE;

	for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
		dcb = th->disabled_cb[type];
		if (dcb == NULL)
			continue;
		data = th->disabled_user_data[type];

		dcb(TETHERING_ERROR_NONE, type, code, data);
	}
}

static void __handle_security_type_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_wifi_security_type_changed_cb scb = NULL;
	void *data = NULL;
	tethering_wifi_security_type_e security_type;

	scb = th->security_type_changed_cb;
	if (scb == NULL)
		return;

	data = th->security_type_user_data;
	if (g_strcmp0(value_name, TETHERING_WIFI_SECURITY_TYPE_OPEN_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_NONE;
	else if (g_strcmp0(value_name, TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR) == 0)
		security_type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	else {
		ERR("Unknown security type : %s\n", value_name);
		return;
	}

	scb(security_type, data);

	return;
}

static void __handle_ssid_visibility_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_wifi_ssid_visibility_changed_cb scb = NULL;
	void *data = NULL;
	bool visible = false;

	scb = th->ssid_visibility_changed_cb;
	if (scb == NULL)
		return;

	data = th->ssid_visibility_user_data;
	if (g_strcmp0(value_name, SIGNAL_MSG_SSID_VISIBLE) == 0)
		visible = true;

	scb(visible, data);

	return;
}

static void __handle_passphrase_changed(DBusGProxy *proxy, const char *value_name, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;
	tethering_wifi_passphrase_changed_cb pcb = NULL;
	void *data = NULL;

	pcb = th->passphrase_changed_cb;
	if (pcb == NULL)
		return;

	data = th->passphrase_user_data;

	pcb(data);

	return;
}

static void __cfm_cb(DBusGProxy *remoteobj, guint event, guint info,
		GError *g_error, gpointer user_data)
{
	DBG("+\n");

	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	tethering_type_e type = 0;
	tethering_error_e error = __get_error(info);
	bool is_requested = true;
	tethering_disabled_cause_e code = TETHERING_DISABLED_BY_REQUEST;

	tethering_enabled_cb ecb = NULL;
	tethering_disabled_cb dcb = NULL;
	void *data = NULL;

	if (g_error) {
		ERR("DBus error [%s]\n", g_error->message);
		g_error_free(g_error);
		return;
	}

	DBG("cfm event : %d info : %d\n", event, info);
	switch (event) {
	case MOBILE_AP_ENABLE_WIFI_TETHERING_CFM:
		type = TETHERING_TYPE_WIFI;
		ecb = th->enabled_cb[type];
		data = th->enabled_user_data[type];
		if (ecb)
			ecb(error, type, is_requested, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_ON,
				G_CALLBACK(__handle_wifi_tether_on),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_DISABLE_WIFI_TETHERING_CFM:
		type = TETHERING_TYPE_WIFI;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_ENABLE_BT_TETHERING_CFM:
		type = TETHERING_TYPE_BT;
		ecb = th->enabled_cb[type];
		data = th->enabled_user_data[type];
		if (ecb)
			ecb(error, type, is_requested, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_BT_TETHER_ON,
				G_CALLBACK(__handle_bt_tether_on),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_DISABLE_BT_TETHERING_CFM:
		type = TETHERING_TYPE_BT;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_ENABLE_USB_TETHERING_CFM:
		type = TETHERING_TYPE_USB;
		ecb = th->enabled_cb[type];
		data = th->enabled_user_data[type];
		if (ecb)
			ecb(error, type, is_requested, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_USB_TETHER_ON,
				G_CALLBACK(__handle_usb_tether_on),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_DISABLE_USB_TETHERING_CFM:
		type = TETHERING_TYPE_USB;
		dcb = th->disabled_cb[type];
		data = th->disabled_user_data[type];
		if (dcb)
			dcb(error, type, code, data);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering, NULL);
		break;

	case MOBILE_AP_DISABLE_CFM:
		for (type = TETHERING_TYPE_USB; type <= TETHERING_TYPE_BT; type++) {
			dcb = th->disabled_cb[type];
			if (dcb == NULL)
				continue;
			data = th->disabled_user_data[type];

			dcb(error, type, code, data);
		}

		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering, NULL);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering, NULL);
		dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering, NULL);
		break;

	default:
		ERR("Invalid event\n");
		return;
	}

	return;
}

static void __get_data_usage_cb(DBusGProxy *remoteobj, guint event,
		guint64 tx_bytes, guint64 rx_bytes,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	__tethering_h *th = (__tethering_h *)user_data;

	if (th->data_usage_cb == NULL) {
		ERR("There is no data_usage_cb\n");
		return;
	}

	if (error || event != MOBILE_AP_GET_DATA_PACKET_USAGE_CFM) {
		if (error)  {
			ERR("DBus fail [%s]\n", error->message);
			g_error_free(error);
		}

		th->data_usage_cb(TETHERING_ERROR_OPERATION_FAILED,
				0LL, 0LL, th->data_usage_user_data);

		th->data_usage_cb = NULL;
		th->data_usage_user_data = NULL;

		return;
	}

	th->data_usage_cb(TETHERING_ERROR_NONE,
			rx_bytes, tx_bytes, th->data_usage_user_data);

	th->data_usage_cb = NULL;
	th->data_usage_user_data = NULL;

	return;
}

static void __ip_forward_cb(DBusGProxy *remoteobj, gint result,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	return;
}

static void __connect_signals(tethering_h tethering)
{
	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	int i = 0;

	for (i = 0; sigs[i].cb != NULL; i++) {
		dbus_g_proxy_add_signal(proxy, sigs[i].name,
				G_TYPE_STRING, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal(proxy, sigs[i].name,
				G_CALLBACK(sigs[i].cb), (gpointer)tethering, NULL);
	}

	dbus_g_object_register_marshaller(marshal_VOID__STRING_UINT_STRING_STRING_STRING_UINT,
			G_TYPE_NONE, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_add_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_TYPE_STRING, G_TYPE_UINT, G_TYPE_STRING,
			G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_CALLBACK(__handle_dhcp), (gpointer)tethering, NULL);

	return;
}

static void __disconnect_signals(tethering_h tethering)
{
	_retm_if(tethering == NULL, "parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	int i = 0;

	for (i = 0; sigs[i].cb != NULL; i++) {
		dbus_g_proxy_disconnect_signal(proxy, sigs[i].name,
				G_CALLBACK(sigs[i].cb), (gpointer)tethering);
	}

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_DHCP_STATUS,
			G_CALLBACK(__handle_dhcp), (gpointer)tethering);

	return;
}

static bool __get_intf_name(tethering_type_e type, char *buf, unsigned int len)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(buf, TETHERING_USB_IF, len);
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(buf, TETHERING_WIFI_IF, len);
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(buf, TETHERING_BT_IF, len);
		break;

	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}

	return true;
}

static bool __get_gateway_addr(tethering_type_e type, char *buf, unsigned int len)
{
	_retvm_if(buf == NULL, false, "parameter(buf) is NULL\n");

	switch (type) {
	case TETHERING_TYPE_USB:
		g_strlcpy(buf, TETHERING_USB_GATEWAY, len);
		break;

	case TETHERING_TYPE_WIFI:
		g_strlcpy(buf, TETHERING_WIFI_GATEWAY, len);
		break;

	case TETHERING_TYPE_BT:
		g_strlcpy(buf, TETHERING_BT_GATEWAY, len);
		break;

	default:
		ERR("Not supported type : %d\n", type);
		return false;
	}

	return true;
}

static void __deinit_cb(DBusGProxy *remoteobj,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	return;
}

static void __wifi_set_security_type_cb(DBusGProxy *remoteobj,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_SECURITY_TYPE_CHANGED,
			G_CALLBACK(__handle_security_type_changed),
			(gpointer)tethering, NULL);

	return;
}

static void __wifi_set_ssid_visibility_cb(DBusGProxy *remoteobj,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_SSID_VISIBILITY_CHANGED,
			G_CALLBACK(__handle_ssid_visibility_changed),
			(gpointer)tethering, NULL);

	return;
}

static void __wifi_set_passphrase_cb(DBusGProxy *remoteobj,
		GError *error, gpointer user_data)
{
	_retm_if(user_data == NULL, "parameter(user_data) is NULL\n");

	tethering_h tethering = (tethering_h)user_data;
	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	if (error) {
		ERR("DBus fail [%s]\n", error->message);
		g_error_free(error);
	}

	dbus_g_proxy_connect_signal(proxy, SIGNAL_NAME_PASSPHRASE_CHANGED,
			G_CALLBACK(__handle_passphrase_changed),
			(gpointer)tethering, NULL);

	return;
}

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
API int tethering_create(tethering_h *tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = NULL;
	GError *error = NULL;
	int retry = TETHERING_DBUS_MAX_RETRY_COUNT;

	th = (__tethering_h *)malloc(sizeof(__tethering_h));
	_retvm_if(th == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"malloc is failed\n");
	memset(th, 0x00, sizeof(__tethering_h));

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif
	th->client_bus = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (error) {
		ERR("Couldn't connect to the System bus[%s]", error->message);
		g_error_free(error);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	th->client_bus_proxy = dbus_g_proxy_new_for_name(th->client_bus,
			TETHERING_SERVICE_NAME,
			TETHERING_SERVICE_OBJECT_PATH,
			TETHERING_SERVICE_INTERFACE);
	if (!th->client_bus_proxy) {
		ERR("Couldn't create the proxy object");
		dbus_g_connection_unref(th->client_bus);
		free(th);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	while (retry--) {
		org_tizen_tethering_init(th->client_bus_proxy, &error);
		if (error != NULL) {
			ERR("Couldn't connect to the System bus[%s]",
					error->message);

			if (error->code == DBUS_GERROR_SERVICE_UNKNOWN) {
				DBG("Tethering is not supported\n");
				g_error_free(error);
				error = NULL;
				dbus_g_connection_unref(th->client_bus);
				free(th);
				return TETHERING_ERROR_NOT_SUPPORT_API;
			}

			g_error_free(error);
			error = NULL;
			if (retry == 0) {
				dbus_g_connection_unref(th->client_bus);
				free(th);
				return TETHERING_ERROR_OPERATION_FAILED;
			}
		} else {
			break;
		}
	}

	__connect_signals((tethering_h)th);

	*tethering = (tethering_h)th;
	DBG("Tethering Handle : 0x%X\n", th);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief  Destroys the handle of tethering.
 * @param[in]  tethering  The handle of tethering
 * @return  0 on success, otherwise a negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_create()
 */
API int tethering_destroy(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	DBG("Tethering Handle : 0x%X\n", th);
	__disconnect_signals(tethering);

	org_tizen_tethering_deinit_async(th->client_bus_proxy, __deinit_cb,
			(gpointer)tethering);

	if (th->ssid)
		free(th->ssid);
	g_object_unref(th->client_bus_proxy);
	dbus_g_connection_unref(th->client_bus);
	memset(th, 0x00, sizeof(__tethering_h));
	free(th);

	return TETHERING_ERROR_NONE;
}

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
API int tethering_enable(tethering_h tethering, tethering_type_e type)
{
	DBG("+\n");

	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	switch (type) {
	case TETHERING_TYPE_USB:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_ON,
				G_CALLBACK(__handle_usb_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_usb_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_WIFI:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_ON,
				G_CALLBACK(__handle_wifi_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_wifi_tethering_async(proxy,
				th->ssid ? th->ssid : "", "", false,
				__cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_BT:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_ON,
				G_CALLBACK(__handle_bt_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_bt_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);

		break;

	case TETHERING_TYPE_ALL:
		/* TETHERING_TYPE_USB */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_ON,
				G_CALLBACK(__handle_usb_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_usb_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_WIFI */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_ON,
				G_CALLBACK(__handle_wifi_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_wifi_tethering_async(proxy,
				th->ssid ? th->ssid : "", "", false,
				__cfm_cb, (gpointer)tethering);

		/* TETHERING_TYPE_BT */
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_ON,
				G_CALLBACK(__handle_bt_tether_on),
				(gpointer)tethering);
		org_tizen_tethering_enable_bt_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;

	default:
		ERR("Unknown type : %d\n", type);
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	return TETHERING_ERROR_NONE;
}

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
API int tethering_disable(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	switch (type) {
	case TETHERING_TYPE_USB:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_usb_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_WIFI:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_wifi_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;
	case TETHERING_TYPE_BT:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_bt_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;

	case TETHERING_TYPE_ALL:
		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_USB_TETHER_OFF,
				G_CALLBACK(__handle_usb_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_usb_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_WIFI_TETHER_OFF,
				G_CALLBACK(__handle_wifi_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_wifi_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);

		dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_BT_TETHER_OFF,
				G_CALLBACK(__handle_bt_tether_off),
				(gpointer)tethering);
		org_tizen_tethering_disable_bt_tethering_async(proxy,
				__cfm_cb, (gpointer)tethering);
		break;

	default :
		ERR("Not supported tethering type [%d]\n", type);
		return TETHERING_ERROR_INVALID_PARAMETER;
		break;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @brief  Checks whetehr the tethering is enabled or not.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @return  @c true if tethering is enabled, \n @c false if tethering is disabled.
 */
API bool tethering_is_enabled(tethering_h tethering, tethering_type_e type)
{
	int is_on = 0;
	int vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_NONE;

	if (vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &is_on) != 0) {
		return FALSE;
	}

	switch (type) {
	case TETHERING_TYPE_USB:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_USB;
		break;

	case TETHERING_TYPE_WIFI:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI;
		break;

	case TETHERING_TYPE_BT:
		vconf_type = VCONFKEY_MOBILE_HOTSPOT_MODE_BT;
		break;

	default:
		ERR("Not supported type : %d\n", type);
		break;
	}

	return is_on & vconf_type ? true : false;
}

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
API int tethering_get_mac_address(tethering_h tethering, tethering_type_e type, char **mac_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(mac_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(mac_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	struct ifreq ifr;
	int s = 0;
	char *macbuf = NULL;

	_retvm_if(!__get_intf_name(type, ifr.ifr_name, sizeof(ifr.ifr_name)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");

	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, TETHERING_ERROR_OPERATION_FAILED,
			"getting socket is failed\n");
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
		ERR("getting mac is failed\n");
		close(s);
		return TETHERING_ERROR_OPERATION_FAILED;
	}
	close(s);

	macbuf = (char *)malloc(TETHERING_STR_INFO_LEN);
	_retvm_if(macbuf == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");
	snprintf(macbuf, TETHERING_STR_INFO_LEN, "%02X:%02X:%02X:%02X:%02X:%02X",
			(unsigned char)ifr.ifr_hwaddr.sa_data[0],
			(unsigned char)ifr.ifr_hwaddr.sa_data[1],
			(unsigned char)ifr.ifr_hwaddr.sa_data[2],
			(unsigned char)ifr.ifr_hwaddr.sa_data[3],
			(unsigned char)ifr.ifr_hwaddr.sa_data[4],
			(unsigned char)ifr.ifr_hwaddr.sa_data[5]);

	*mac_address = macbuf;

	return TETHERING_ERROR_NONE;
}

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
API int tethering_get_network_interface_name(tethering_h tethering, tethering_type_e type, char **interface_name)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(interface_name == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(interface_name) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	char intf[TETHERING_STR_INFO_LEN] = {0, };

	_retvm_if(!__get_intf_name(type, intf, sizeof(intf)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");
	*interface_name = strdup(intf);
	_retvm_if(*interface_name == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

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
API int tethering_get_ip_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **ip_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ip_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ip_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	struct ifreq ifr;
	int s = 0;
	char *ipbuf = NULL;

	_retvm_if(!__get_intf_name(type, ifr.ifr_name, sizeof(ifr.ifr_name)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting interface name is failed\n");

	s = socket(AF_INET, SOCK_DGRAM, 0);
	_retvm_if(s < 0, TETHERING_ERROR_OPERATION_FAILED,
			"getting socket is failed\n");
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		ERR("ioctl is failed\n");
		close(s);
		return TETHERING_ERROR_OPERATION_FAILED;
	}
	close(s);

	ipbuf = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
	*ip_address = strdup(ipbuf);
	_retvm_if(*ip_address == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

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
API int tethering_get_gateway_address(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **gateway_address)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(gateway_address == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(gateway_address) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering type[%d] is not enabled\n", type);

	char gateway_buf[TETHERING_STR_INFO_LEN] = {0, };

	_retvm_if(!__get_gateway_addr(type, gateway_buf, sizeof(gateway_buf)),
			TETHERING_ERROR_OPERATION_FAILED,
			"getting gateway address is failed\n");

	*gateway_address = strdup(gateway_buf);

	return TETHERING_ERROR_NONE;
}

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
API int tethering_get_subnet_mask(tethering_h tethering, tethering_type_e type, tethering_address_family_e address_family, char **subnet_mask)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(tethering_is_enabled(tethering, type) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");
	_retvm_if(subnet_mask == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(subnet_mask) is NULL\n");

	*subnet_mask = strdup(TETHERING_SUBNET_MASK);
	_retvm_if(*subnet_mask == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"Not enough memory\n");

	return TETHERING_ERROR_NONE;
}

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
API int tethering_get_data_usage(tethering_h tethering, tethering_data_usage_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	th->data_usage_cb = callback;
	th->data_usage_user_data = user_data;

	org_tizen_tethering_get_data_packet_usage_async(proxy,
			__get_data_usage_cb, (gpointer)th);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Gets the client which is connected by USB tethering.
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
API int tethering_foreach_connected_clients(tethering_h tethering, tethering_type_e type, tethering_connected_client_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");
	_retvm_if(__any_tethering_is_enabled(tethering) == false,
			TETHERING_ERROR_NOT_ENABLED,
			"tethering is not enabled\n");

	__tethering_h *th = (__tethering_h *)tethering;
	__tethering_client_h client = {0, };

	guint event = 0;
	GPtrArray *array = NULL;
	GValue value = {0, {{0}}};
	GError *error = NULL;
	int i = 0;
	int no_of_client = 0;
	guint interface = 0;
	gchar *ip = NULL;
	gchar *mac = NULL;
	gchar *hostname = NULL;
	guint timestamp = 0;

	org_tizen_tethering_get_station_info(th->client_bus_proxy, &event,
			&array, &error);
	if (error != NULL) {
		ERR("DBus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	g_value_init(&value, DBUS_STRUCT_STATIONS);
	no_of_client = array->len;
	for (i = 0; i < no_of_client; i++) {
		g_value_set_boxed(&value, g_ptr_array_index(array, i));

		dbus_g_type_struct_get(&value, 0, &interface, 1, &ip,
				2, &mac, 3, &hostname, 4, &timestamp, G_MAXUINT);

		if (interface == MOBILE_AP_TYPE_USB)
			client.interface = TETHERING_TYPE_USB;
		else if (interface == MOBILE_AP_TYPE_WIFI)
			client.interface = TETHERING_TYPE_WIFI;
		else if (interface == MOBILE_AP_TYPE_BT)
			client.interface = TETHERING_TYPE_BT;

		if (client.interface != type && TETHERING_TYPE_ALL != type)
			continue;

		g_strlcpy(client.ip, ip, sizeof(client.ip));
		g_strlcpy(client.mac, mac, sizeof(client.mac));
		g_strlcpy(client.hostname, hostname, sizeof(client.hostname));
		client.tm = (time_t)timestamp;

		if (callback((tethering_client_h)&client, user_data) == false) {
			DBG("iteration is stopped\n");
			return TETHERING_ERROR_NONE;
		}
	}

	if (array->len > 0)
		g_ptr_array_free(array, TRUE);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Set the ip forward status
 * @param[in]  tethering  The handle of tethering
 * @param[in]  status  The ip forward status: (@c true = enable, @c false = disable)
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_get_ip_forward_status()
 */
API int tethering_set_ip_forward_status(tethering_h tethering, bool status)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;

	org_tizen_tethering_set_ip_forward_status_async(proxy, status,
			__ip_forward_cb, (gpointer)tethering);

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Get the ip forward status
 * @param[in]  tethering  The handle of tethering
 * @param[out]  status  The ip forward status: (@c true = enable, @c false = disable)
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OPERATION_FAILED  Operation failed
 * @see  tethering_set_ip_forward_status()
 */
API int tethering_get_ip_forward_status(tethering_h tethering, bool *status)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(status == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(status) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	int forward_mode = 0;

	org_tizen_tethering_get_ip_forward_status(proxy, &forward_mode, &error);
	if (error != NULL) {
		ERR("DBus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (forward_mode == 1)
		*status = true;
	else
		*status = false;

	return TETHERING_ERROR_NONE;
}


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
API int tethering_set_enabled_cb(tethering_h tethering, tethering_type_e type, tethering_enabled_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->enabled_cb[type] = callback;
		th->enabled_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->enabled_cb[ti] = callback;
		th->enabled_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Unregisters the callback function called when tethering is disabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_enabled_cb()
 */
API int tethering_unset_enabled_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->enabled_cb[type] = NULL;
		th->enabled_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->enabled_cb[ti] = NULL;
		th->enabled_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

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
API int tethering_set_disabled_cb(tethering_h tethering, tethering_type_e type, tethering_disabled_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->disabled_cb[type] = callback;
		th->disabled_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->disabled_cb[ti] = callback;
		th->disabled_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Unregisters the callback function called when tethering is disabled.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_disabled_cb()
 */
API int tethering_unset_disabled_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->disabled_cb[type] = NULL;
		th->disabled_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->disabled_cb[ti] = NULL;
		th->disabled_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

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
API int tethering_set_connection_state_changed_cb(tethering_h tethering, tethering_type_e type, tethering_connection_state_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->changed_cb[type] = callback;
		th->changed_user_data[type] = user_data;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->changed_cb[ti] = callback;
		th->changed_user_data[ti] = user_data;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Unregisters the callback function called when the state of connection is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_set_connection_state_changed_cb()
 */
API int tethering_unset_connection_state_changed_cb(tethering_h tethering, tethering_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	tethering_type_e ti;

	if (type != TETHERING_TYPE_ALL) {
		th->changed_cb[type] = NULL;
		th->changed_user_data[type] = NULL;

		return TETHERING_ERROR_NONE;
	}

	/* TETHERING_TYPE_ALL */
	for (ti = TETHERING_TYPE_USB; ti <= TETHERING_TYPE_BT; ti++) {
		th->changed_cb[ti] = NULL;
		th->changed_user_data[ti] = NULL;
	}

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Registers the callback function called when the security type of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_security_type_changed_cb()
 */
API int tethering_wifi_set_security_type_changed_cb(tethering_h tethering, tethering_wifi_security_type_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->security_type_changed_cb = callback;
	th->security_type_user_data = user_data;

	return TETHERING_ERROR_NONE;

}

/**
 * @brief Unregisters the callback function called when the security type of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  type  The type of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_security_type_changed_cb()
 */
API int tethering_wifi_unset_security_type_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->security_type_changed_cb = NULL;
	th->security_type_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Registers the callback function called when the visibility of SSID is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_ssid_visibility_changed_cb_cb()
 */
API int tethering_wifi_set_ssid_visibility_changed_cb(tethering_h tethering, tethering_wifi_ssid_visibility_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->ssid_visibility_changed_cb = callback;
	th->ssid_visibility_user_data = user_data;

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Unregisters the callback function called when the visibility of SSID is changed.
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_ssid_visibility_changed_cb()
 */
API int tethering_wifi_unset_ssid_visibility_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->ssid_visibility_changed_cb = NULL;
	th->ssid_visibility_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Registers the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @param[in]  callback  The callback function to invoke
 * @param[in]  user_data  The user data to be passed to the callback function
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_unset_passphrase_changed_cb()
 */
API int tethering_wifi_set_passphrase_changed_cb(tethering_h tethering, tethering_wifi_passphrase_changed_cb callback, void *user_data)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(callback == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(callback) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->passphrase_changed_cb = callback;
	th->passphrase_user_data = user_data;

	return TETHERING_ERROR_NONE;
}

/**
 * @brief Unregisters the callback function called when the passphrase of Wi-Fi tethering is changed.
 * @param[in]  tethering  The handle of tethering
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @see  tethering_wifi_set_passphrase_changed_cb()
 */
API int tethering_wifi_unset_passphrase_changed_cb(tethering_h tethering)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;

	th->passphrase_changed_cb = NULL;
	th->passphrase_user_data = NULL;

	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_set_security_type(tethering_h tethering, tethering_wifi_security_type_e type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	char *type_str = NULL;

	if (type == TETHERING_WIFI_SECURITY_TYPE_NONE) {
		type_str = TETHERING_WIFI_SECURITY_TYPE_OPEN_STR;
	} else if (type == TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK) {
		type_str = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR;
	} else {
		ERR("Unsupported type\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_SECURITY_TYPE_CHANGED,
			G_CALLBACK(__handle_security_type_changed),
			(gpointer)tethering);

	org_tizen_tethering_set_wifi_tethering_security_type_async(proxy, type_str,
			__wifi_set_security_type_cb, (gpointer)tethering);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_get_security_type(tethering_h tethering, tethering_wifi_security_type_e *type)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(type == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(type) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	char *type_str = NULL;

	org_tizen_tethering_get_wifi_tethering_security_type(proxy, &type_str, &error);
	if (error != NULL) {
		ERR("DBus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (type_str == NULL)
		return TETHERING_ERROR_OPERATION_FAILED;

	DBG("security type : %s\n", type_str);
	if (strcmp(type_str, TETHERING_WIFI_SECURITY_TYPE_OPEN_STR) == 0)
		*type = TETHERING_WIFI_SECURITY_TYPE_NONE;
	else if (strcmp(type_str, TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK_STR) == 0)
		*type = TETHERING_WIFI_SECURITY_TYPE_WPA2_PSK;
	else {
		ERR("Unknown security type : %s\n", type_str);
		g_free(type_str);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	g_free(type_str);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

/**
 * @brief Sets the SSID (service set identifier).
 * @details If SSID is not set, Device name is used as SSID
 * @remarks This change is applied next time Wi-Fi tethering is enabled with same @a tethering handle
 * @param[in]  tethering  The handle of tethering
 * @param[out]  ssid  The SSID
 * @return 0 on success, otherwise negative error value.
 * @retval  #TETHERING_ERROR_NONE  Successful
 * @retval  #TETHERING_ERROR_INVALID_PARAMETER  Invalid parameter
 * @retval  #TETHERING_ERROR_OUT_OF_MEMORY  Out of memory
 */
API int tethering_wifi_set_ssid(tethering_h tethering, const char *ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");

	__tethering_h *th = (__tethering_h *)tethering;
	char *p_ssid;
	int ssid_len;

	ssid_len = strlen(ssid);
	if (ssid_len > TETHERING_WIFI_SSID_MAX_LEN) {
		ERR("parameter(ssid) is too long");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	p_ssid = strdup(ssid);
	_retvm_if(p_ssid == NULL, TETHERING_ERROR_OUT_OF_MEMORY,
			"strdup is failed\n");

	if (th->ssid)
		free(th->ssid);
	th->ssid = p_ssid;

	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_get_ssid(tethering_h tethering, char **ssid)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(ssid == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(ssid) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	char *ssid_buf = NULL;

	if (tethering_is_enabled(NULL, TETHERING_TYPE_WIFI) == false &&
			th->ssid != NULL) {
		DBG("Private SSID is set : %s\n", th->ssid);
		*ssid = strdup(th->ssid);
		if (*ssid == NULL) {
			ERR("Memory allocation failed\n");
			return TETHERING_ERROR_OUT_OF_MEMORY;
		}
		DBG("-\n");
		return TETHERING_ERROR_NONE;
	}

	org_tizen_tethering_get_wifi_tethering_ssid(proxy, &ssid_buf, &error);
	if (error != NULL) {
		ERR("dbus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (ssid_buf == NULL)
		return TETHERING_ERROR_OPERATION_FAILED;

	*ssid = strdup(ssid_buf);
	if (*ssid == NULL) {
		ERR("Memory allocation failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	g_free(ssid_buf);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_set_ssid_visibility(tethering_h tethering, bool visible)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	int hide_mode = 0;

	if (visible)
		hide_mode = VCONFKEY_MOBILE_AP_HIDE_OFF;
	else
		hide_mode = VCONFKEY_MOBILE_AP_HIDE_ON;

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_SSID_VISIBILITY_CHANGED,
			G_CALLBACK(__handle_ssid_visibility_changed),
			(gpointer)tethering);

	org_tizen_tethering_set_wifi_tethering_hide_mode_async(proxy, hide_mode,
			__wifi_set_ssid_visibility_cb, (gpointer)tethering);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_get_ssid_visibility(tethering_h tethering, bool *visible)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(visible == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(visible) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	int hide_mode = 0;

	org_tizen_tethering_get_wifi_tethering_hide_mode(proxy, &hide_mode, &error);
	if (error != NULL) {
		ERR("dbus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}
	DBG("hide mode : %d\n", hide_mode);

	if (hide_mode == VCONFKEY_MOBILE_AP_HIDE_OFF)
		*visible = true;
	else
		*visible = false;

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_set_passphrase(tethering_h tethering, const char *passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	int passphrase_len;

	passphrase_len = strlen(passphrase);
	if (passphrase_len < TETHERING_WIFI_KEY_MIN_LEN ||
			passphrase_len > TETHERING_WIFI_KEY_MAX_LEN) {
		ERR("parameter(passphrase) is too short or long\n");
		return TETHERING_ERROR_INVALID_PARAMETER;
	}

	dbus_g_proxy_disconnect_signal(proxy, SIGNAL_NAME_PASSPHRASE_CHANGED,
			G_CALLBACK(__handle_passphrase_changed),
			(gpointer)tethering);

	org_tizen_tethering_set_wifi_tethering_passphrase_async(proxy,
			passphrase, passphrase_len,
			__wifi_set_passphrase_cb, (gpointer)tethering);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}

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
API int tethering_wifi_get_passphrase(tethering_h tethering, char **passphrase)
{
	_retvm_if(tethering == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(tethering) is NULL\n");
	_retvm_if(passphrase == NULL, TETHERING_ERROR_INVALID_PARAMETER,
			"parameter(passphrase) is NULL\n");
	DBG("+\n");

	__tethering_h *th = (__tethering_h *)tethering;
	DBusGProxy *proxy = th->client_bus_proxy;
	GError *error = NULL;
	char *passphrase_buf = NULL;
	unsigned int len = 0;

	org_tizen_tethering_get_wifi_tethering_passphrase(proxy,
			&passphrase_buf, &len, &error);
	if (error != NULL) {
		ERR("dbus fail : %s\n", error->message);
		g_error_free(error);
		return TETHERING_ERROR_OPERATION_FAILED;
	}

	if (passphrase_buf == NULL)
		return TETHERING_ERROR_OPERATION_FAILED;

	*passphrase = strdup(passphrase_buf);
	if (*passphrase == NULL) {
		ERR("Memory allocation failed\n");
		return TETHERING_ERROR_OUT_OF_MEMORY;
	}

	g_free(passphrase_buf);

	DBG("-\n");
	return TETHERING_ERROR_NONE;
}
