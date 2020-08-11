#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <math.h>
#include <assert.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/eventfd.h>
#include <gio/gio.h>
#include <gio/gunixfdlist.h>

#include "hfp_sco_relay.h"

#define HFP_PROFILE_NAME		"Hands-Free"
#define HFP_PROFILE_UUID		"0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_HF_SERVICE_CLASS_UUID	"0000111e-0000-1000-8000-00805f9b34fb"
#define HFP_AG_SERVICE_CLASS_UUID	"0000111f-0000-1000-8000-00805f9b34fb"
#define HFP_HF_PROFILE_PATH		"/org/bluez/hfp/hf/client"
#define HFP_AG_PROFILE_PATH		"/org/bluez/hfp/ag/client"

#define MAX_LEN_AT	512

#define BDADDR_STRLEN	17

#define VDB_NUM_PKTS	16		/* TODO: Minimize number of packets in buffer */

/* TODO: Remove initial writes and minimize pre-fill to minimize latency */
#define NUM_PKTS_INITIAL_WRITE	8
#define NUM_PKTS_PRE_FILL	4

enum hfp_role {hands_free_unit = 0, audio_gateway = 1};

struct voice_data_buffer {
	struct sco_data_packet packet[VDB_NUM_PKTS];
	unsigned int read_index;
	unsigned int write_index;
};

struct hfp_connection {
	enum hfp_role local_role;
	bool connected;					/* Used by handle_method_call to determine if HFP role has already been connected */
	pthread_t slc_thread;
	pthread_mutex_t sco_use_lock;			/* Locked by sco_thread when connection is in use */
	int efd;					/* eventfd used to signal status updates from slc_thread_func_xx to sco_thread_func */

	/* Flags slc_established and slc_disconnect are set true once and then never cleared as long as sco_use_lock mutex is held by sco_thread */
	bool slc_established;				/* Set true by slc_thread_func_xx when SLC connection reaches established state */
	bool slc_disconnect;				/* Set true by slc_thread_func_xx when RFCOMM SLC connection is terminated */

	char *device_path;				/* Set on init, never changed */
	char *device_name;				/* Set on init, never changed */
	bdaddr_t remote_bdaddr;				/* Set on init, never changed */
	bdaddr_t local_bdaddr;				/* Set on init, never changed */
	char remote_bdaddr_str[BDADDR_STRLEN + 1];	/* Set on init, never changed */
	char local_bdaddr_str[BDADDR_STRLEN + 1];	/* Set on init, never changed */

	/* slc_thread exclusive use members */
	int rc_fd;

	/* sco_thread exclusive use members */
	int sco_fd;
	int sco_data_len;
	uint32_t sco_pkts_sent;
	uint32_t sco_pkts_rcvd;
	struct voice_data_buffer vdb;
};

static void *sco_thread_func(void *arg);

static struct hfp_connection conn_hfp[2];

static const gchar introspection_xml[] =
	"<node>"
	"  <interface name='org.bluez.Profile1'>"
	"    <method name='Release' />"
	"    <method name='NewConnection'>"
	"      <arg type='o' name='device' direction='in' />"
	"      <arg type='h' name='fd' direction='in' />"
	"      <arg type='a{sv}' name='fd_properties' direction='in' />"
	"    </method>"
	"    <method name='RequestDisconnection'>"
	"      <arg type='o' name='device' direction='in' />"
	"    </method>"
	"  </interface>"
	"</node>";

static GMainLoop *loop;

static struct sco_data_packet fixed_data_pkt = {
		.data = {
			0, 0, 236, 46, 77, 74, 77, 74, 236, 46, 0, 0, 20, -46, 179, -74, 179, -74, 20, -46,
			0, 0, 236, 46, 77, 74, 77, 74, 236, 46, 0, 0, 20, -46, 179, -74, 179, -74, 20, -46,
			0, 0, 236, 46, 77, 74, 77, 74, 236, 46, 0, 0, 20, -46, 179, -74, 179, -74, 20, -46
		}
};

static struct sco_data_packet discard_data_pkt;

static void handle_method_call(GDBusConnection *conn, const char *sender, const char *path, const char *interface,
		const char *method, GVariant *params, GDBusMethodInvocation *invocation, void *userdata);

static GDBusInterfaceVTable vtable = {
	.method_call = handle_method_call,
};

/* Command line configurable variables */
static int stdout_logging = 1;

static const struct option long_options[] = {
	{"log-addr", required_argument, 0, 'a'},
	{"log-port", required_argument, 0, 'p'},
	{"log-level", required_argument, 0, 'l'},
	{"no-stdout", no_argument, &stdout_logging, 0},
	{0, 0, 0, 0}
};

static ssize_t receive_voice_data_pkt(struct hfp_connection *hc)
{
	ssize_t bytes_read;
	struct sco_data_packet *packet;

	/* Buffer overflow check */
	if (!hc->vdb.packet[hc->vdb.write_index].has_data)
		packet = &hc->vdb.packet[hc->vdb.write_index];
	else
		packet = &discard_data_pkt;

	bytes_read = read(hc->sco_fd, packet->data, hc->sco_data_len);

	if (bytes_read != -1) {
		hc->sco_pkts_rcvd++;
		log_sco_data_pkt(packet, &hc->remote_bdaddr, &hc->local_bdaddr, hc->sco_pkts_rcvd);
		if (bytes_read != hc->sco_data_len)
			log_print(LOG_LEVEL_WARNING, "Expected %u bytes of SCO data, got %lu bytes\n", hc->sco_data_len, bytes_read);

		/* Buffer overflow check */
		if (hc->vdb.packet[hc->vdb.write_index].has_data) {
			log_print(LOG_LEVEL_WARNING, "Overflow in \"%s\" SCO data buffer\n",
					(hc->local_role == hands_free_unit ? "hands_free_unit" : "audio_gateway"));
			log_print(LOG_LEVEL_DEBUG, "read_index:%u, write_index: %u, sco_pkts_sent: %u, sco_pkts_rcvd: %u\n",
					hc->vdb.read_index, hc->vdb.write_index, hc->sco_pkts_sent, hc->sco_pkts_rcvd);
		} else {
			hc->vdb.packet[hc->vdb.write_index].has_data = true;
			hc->vdb.write_index++;
			if (hc->vdb.write_index == VDB_NUM_PKTS)
				hc->vdb.write_index = 0;
		}
	}

	return bytes_read;
}

/*
 *	get_voice_data_pkt
 *
 *	Function will return a pointer to the next available data packet
 *	If no packet is available it will return a pointer to a fixed packet (containing a sine tone for testing purposes)
 *	The packet will be marked as empty and data could be overwritten by the next receive_voice_data() call
 */
static struct sco_data_packet *get_voice_data_pkt(struct hfp_connection *hc)
{
	struct sco_data_packet *packet;

	/* Buffer empty check */
	if (!hc->vdb.packet[hc->vdb.read_index].has_data) {
		log_print(LOG_LEVEL_WARNING, "Underflow in \"%s\" SCO data buffer\n",
				(hc->local_role == hands_free_unit ? "hands_free_unit" : "audio_gateway"));
		log_print(LOG_LEVEL_DEBUG, "read_index:%u, write_index: %u, sco_pkts_sent: %u, sco_pkts_rcvd: %u\n",
				hc->vdb.read_index, hc->vdb.write_index, hc->sco_pkts_sent, hc->sco_pkts_rcvd);

		packet = &fixed_data_pkt;
	} else {
		packet = &hc->vdb.packet[hc->vdb.read_index];
		hc->vdb.packet[hc->vdb.read_index].has_data = false;
		hc->vdb.read_index++;
		if (hc->vdb.read_index == VDB_NUM_PKTS)
			hc->vdb.read_index = 0;
	}

	return packet;
}

void insert_voice_data_pkt(struct hfp_connection *hc, struct sco_data_packet *src_pkt)
{
	struct sco_data_packet *dst_pkt = &hc->vdb.packet[hc->vdb.write_index];

	memcpy(dst_pkt->data, src_pkt->data, hc->sco_data_len);

	/* Buffer overflow check */
	if (hc->vdb.packet[hc->vdb.write_index].has_data) {
		log_print(LOG_LEVEL_WARNING, "Overflow in \"%s\" SCO data buffer\n",
				(hc->local_role == hands_free_unit ? "hands_free_unit" : "audio_gateway"));
		log_print(LOG_LEVEL_DEBUG, "read_index:%u, write_index: %u, sco_pkts_sent: %u, sco_pkts_rcvd: %u\n",
				hc->vdb.read_index, hc->vdb.write_index, hc->sco_pkts_sent, hc->sco_pkts_rcvd);
	}
	hc->vdb.packet[hc->vdb.write_index].has_data = true;
	hc->vdb.write_index++;
	if (hc->vdb.write_index == VDB_NUM_PKTS)
		hc->vdb.write_index = 0;
}

static ssize_t send_voice_data_pkt(struct hfp_connection *hc, struct sco_data_packet *packet)
{
	ssize_t bytes_written;

	bytes_written = write(hc->sco_fd, packet->data, hc->sco_data_len);
	if (bytes_written != -1) {
		hc->sco_pkts_sent++;
		log_sco_data_pkt(packet, &hc->local_bdaddr, &hc->remote_bdaddr, hc->sco_pkts_sent);
		if (bytes_written != hc->sco_data_len)
			log_print(LOG_LEVEL_ERROR, "Tried to write %u bytes of SCO data, wrote %lu bytes\n", hc->sco_data_len, bytes_written);
	}
	return bytes_written;
}

static int send_at_command(int fd, const char *command, char *response, int response_len)
{
	int result;
	int bytes_read;
	struct pollfd fds[1];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	log_print(LOG_LEVEL_DEBUG, "Send AT command: %s\n", command);
	write(fd, command, strlen(command));

	result = poll(fds, 1, -1);
	if (result >= 0) {
		if (fds[0].revents & POLLIN) {
			bytes_read = read(fd, response, response_len);
			assert(bytes_read != -1);
			response[bytes_read] = 0;
			log_print(LOG_LEVEL_DEBUG, "Received AT response: %s", response);
			result = 0;
		} else {
			result = -1;
		}
	}
	return result;
}

static int hfp_connection_deinit(struct hfp_connection *hc)
{
	free(hc->device_path);
	free(hc->device_name);
	hc->connected = false;
	hc->rc_fd = -1;
	hc->sco_fd = -1;
	hc->slc_established = false;
	hc->slc_disconnect = false;

	return 0;
}

static int hfp_connection_init(struct hfp_connection *hc, int fd, char *device_path, char *device_name, enum hfp_role local_role)
{
	int result = -1;
	struct sockaddr_rc sa = {0};
	socklen_t sa_len;

	hc->connected = false;
	hc->local_role = local_role;
	hc->rc_fd = fd;
	hc->sco_fd = -1;
	hc->slc_established = false;
	hc->slc_disconnect = false;
	hc->device_path = malloc(strlen(device_path)+1);
	if (!hc->device_path)
		goto exit;

	strcpy(hc->device_path, device_path);

	hc->device_name = malloc(strlen(device_name)+1);
	if (!hc->device_name)
		goto exit;

	strcpy(hc->device_name, device_name);

	sa_len = sizeof(sa);
	if (getpeername(fd, (struct sockaddr *)&sa, &sa_len) == -1) {
		log_perror("Couldn't get remote address, getpeername() failed");
		goto free_device_path;
	}
	bacpy(&hc->remote_bdaddr, &sa.rc_bdaddr);
	ba2str(&sa.rc_bdaddr, hc->remote_bdaddr_str);
	sa_len = sizeof(sa);
	if (getsockname(fd, (struct sockaddr *)&sa, &sa_len) == -1) {
		log_perror("Couldn't get local address, getsockname() failed");
		goto free_device_path;
	}
	bacpy(&hc->local_bdaddr, &sa.rc_bdaddr);
	ba2str(&sa.rc_bdaddr, hc->local_bdaddr_str);

	log_print(LOG_LEVEL_DEBUG, "HFP connection initialized remote BDADDR: %s, local BDADDR: %s\n", hc->remote_bdaddr_str, hc->local_bdaddr_str);

	result = 0;	/* Success */
	goto exit;
free_device_path:
	free(hc->device_path);
exit:
	return result;
}

static void *slc_thread_func_hf(void *arg)
{
	int bytes_read;
	uint64_t event = 1;
	struct hfp_connection *hc = (struct hfp_connection *)arg;
	struct pollfd fds[1];
	char *at_buf = malloc(MAX_LEN_AT + 1);

	if (!at_buf)
		goto exit;

	log_print(LOG_LEVEL_DEBUG, "%s: Started\n", __func__);

	/* Service Level Connection Initialization */
	send_at_command(hc->rc_fd, "AT+BRSF=0\r", at_buf, MAX_LEN_AT);
	send_at_command(hc->rc_fd, "AT+CIND=?\r", at_buf, MAX_LEN_AT);
	send_at_command(hc->rc_fd, "AT+CIND?\r", at_buf, MAX_LEN_AT);
	send_at_command(hc->rc_fd, "AT+CMER=3,0,0,1\r", at_buf, MAX_LEN_AT);

	hc->slc_established = true;
	write(hc->efd, &event, sizeof(event));	/* Signal status update (slc_established) to sco thread */

	fds[0].fd = hc->rc_fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	while (1) {
		if (poll(fds, 1, 1000) > 0) {
			if (fds[0].revents & POLLIN) {
				bytes_read = read(fds[0].fd, at_buf, MAX_LEN_AT);
				assert(bytes_read != -1);
				at_buf[bytes_read] = 0;
				log_print(LOG_LEVEL_DEBUG, "AT command received from AG: %s\n", at_buf);
			} else if (fds[0].revents & POLLHUP) {
				break;
			}
		}
	}

	free(at_buf);

	hc->slc_disconnect = true;
	write(hc->efd, &event, sizeof(event));	/* Signal status update (slc_disconnect) to sco thread */

	assert(!pthread_mutex_lock(&hc->sco_use_lock));	/* Wait for sco thread to be done with this HFP connection */
	close(hc->rc_fd);
	hfp_connection_deinit(hc);
	assert(!pthread_mutex_unlock(&hc->sco_use_lock));
exit:
	log_print(LOG_LEVEL_DEBUG, "Exiting %s\n", __func__);

	return NULL;
}

static void *slc_thread_func_ag(void *arg)
{
	int bytes_read;
	uint64_t event = 1;
	struct hfp_connection *hc = (struct hfp_connection *)arg;
	struct pollfd fds[1];
	char *at_buf = malloc(MAX_LEN_AT + 1);

	if (!at_buf)
		goto exit;

	log_print(LOG_LEVEL_DEBUG, "%s: Started\n", __func__);

	fds[0].fd = hc->rc_fd;
	fds[0].events = POLLIN;
	while (1) {
		fds[0].revents = 0;
		poll(fds, 1, 1000);
		if (fds[0].revents & POLLIN) {
			bytes_read = read(fds[0].fd, at_buf, MAX_LEN_AT);
			assert(bytes_read != -1);

			at_buf[bytes_read] = 0;
			log_print(LOG_LEVEL_DEBUG, "AT command received from HF: %s\n", at_buf);

			if (strncmp(at_buf, "AT+BRSF=", strlen("AT+BRSF=")) == 0) {
				strcpy(at_buf, "\r\n+BRSF: 0\r\n\r\nOK\r\n");
			} else if (strncmp(at_buf, "AT+CIND=?", strlen("AT+CIND=?")) == 0) {
				strcpy(at_buf, "\r\n+CIND: (\"service\",(0,1)),(\"call\",(0,1))\r\n\r\nOK\r\n");
			} else if (strncmp(at_buf, "AT+CIND?", strlen("AT+CIND?")) == 0) {
				strcpy(at_buf, "\r\n+CIND: 1,0\r\n\r\nOK\r\n");
			} else if (strncmp(at_buf, "AT+CMER", strlen("AT+CMER")) == 0) {
				strcpy(at_buf, "\r\nOK\r\n");
				hc->slc_established = true;
				write(hc->efd, &event, sizeof(event));	/* Signal status update (slc_established) to sco thread */
			} else {
				strcpy(at_buf, "\r\nERROR\r\n");
			}

			log_print(LOG_LEVEL_DEBUG, "Sending AT response: %s", at_buf);
			write(fds[0].fd, at_buf, strlen(at_buf));
		}
		if (fds[0].revents & POLLHUP)
			break;
	}

	free(at_buf);

	hc->slc_disconnect = true;
	write(hc->efd, &event, sizeof(event));	/* Signal status update (slc_disconnect) to sco thread */

	assert(!pthread_mutex_lock(&hc->sco_use_lock));	/* Wait for sco thread to be done with this HFP connection */
	close(hc->rc_fd);
	hfp_connection_deinit(hc);
	assert(!pthread_mutex_unlock(&hc->sco_use_lock));
exit:
	log_print(LOG_LEVEL_DEBUG, "Exiting %s\n", __func__);

	return NULL;
}

static void handle_method_call(GDBusConnection *conn, const char *sender, const char *path, const char *interface,
		const char *method, GVariant *params, GDBusMethodInvocation *invocation, void *userdata)
{
	int err;
	int fd_handle;
	int fd;
	char *device_path;
	char *device_name;
	GError *error = NULL;
	GVariantIter *properties;
	GUnixFDList *fd_list;
	GDBusProxy *dev_proxy;
	GVariant *name;
	GDBusMessage *dbus_msg;
	void *(*thread_func)(void *arg);
	enum hfp_role local_role = (enum hfp_role)userdata;

	if (strcmp(method, "NewConnection") == 0) {
		g_variant_get(params, "(&oha{sv})", &device_path, &fd_handle, &properties);

		dev_proxy = g_dbus_proxy_new_sync(conn, G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS, NULL,
				"org.bluez", device_path, "org.bluez.Device1", NULL, &error);
		g_assert_no_error(error);
		name = g_dbus_proxy_get_cached_property(dev_proxy, "Name");
		g_variant_get(name, "s", &device_name);
		log_print(LOG_LEVEL_INFO, "Incoming connection attempt to %s from %s \"%s\"\n", (local_role == audio_gateway ? "AG" : "HF"),
				(local_role == audio_gateway ? "HF" : "AG"), device_name);

		dbus_msg = g_dbus_method_invocation_get_message(invocation);
		fd_list = g_dbus_message_get_unix_fd_list(dbus_msg);
		fd = g_unix_fd_list_get(fd_list, fd_handle, &error);
		g_assert_no_error(error);

		if (conn_hfp[local_role].connected) {
			log_print(LOG_LEVEL_WARNING, "Rejecting connection, HFP role already connected\n");
			close(fd);
			g_dbus_method_invocation_return_dbus_error(invocation, "org.bluez.Error.Rejected", "HFP role already connected");
		} else if (hfp_connection_init(&conn_hfp[local_role], fd, device_path, device_name, local_role) != 0) {
			log_print(LOG_LEVEL_ERROR, "Rejecting connection, hfp_connection_init failed\n");
			close(fd);
			g_dbus_method_invocation_return_dbus_error(invocation, "org.bluez.Error.Rejected", "Connection init failed");
		} else {
			g_dbus_method_invocation_return_value(invocation, NULL);

			thread_func = (local_role == hands_free_unit ? slc_thread_func_hf : slc_thread_func_ag);
			err = pthread_create(&conn_hfp[local_role].slc_thread, NULL, thread_func, &conn_hfp[local_role]);
			assert(err == 0);
			conn_hfp[local_role].connected = true;
		}

		g_free(device_name);
		g_variant_unref(name);
		g_object_unref(dev_proxy);
		g_free(device_path);
	} else if (strcmp(method, "RequestDisconnection") == 0) {
		assert(0); /* Call not expected */
	} else if (strcmp(method, "Release") == 0) {
		assert(0); /* Call not expected */
	}
}

int main(int argc, char **argv)
{
	int result = -1;
	GDBusConnection *conn;
	GError *error = NULL;
	GDBusMessage *dbus_msg;
	GVariantBuilder options;
	GDBusNodeInfo *introspection;
	GDBusInterfaceInfo *interface_info;
	pthread_t sco_thread;
	int ch;
	int option_index = 0;
	char *log_server_address = "192.168.1.249";
	unsigned int log_server_port = 4445;
	unsigned int log_level = 0;

	while ((ch = getopt_long (argc, argv, "a:p:l:", long_options, &option_index)) != -1) {
		switch (ch) {
		case 'a':
			log_server_address = optarg;
			break;

		case 'p':
			sscanf(optarg, "%u", &log_server_port);
			break;

		case 'l':
			sscanf(optarg, "%u", &log_level);
			break;

		case 0:
			if (long_options[option_index].flag != 0)
				break;

		default:
			goto exit;
		}
	}

	log_init(log_level, (stdout_logging ? stdout : NULL), log_server_address, log_server_port);
	log_print(LOG_LEVEL_DEBUG, "Logging to %s:%u\n", log_server_address, log_server_port);

	/* TODO: Handle inits in separate func */
	/* TODO: Use pointers to dynamically allocated connections */
	conn_hfp[audio_gateway].connected = false;
	conn_hfp[hands_free_unit].connected = false;
	pthread_mutex_init(&conn_hfp[audio_gateway].sco_use_lock, NULL);
	pthread_mutex_init(&conn_hfp[hands_free_unit].sco_use_lock, NULL);
	conn_hfp[audio_gateway].efd = eventfd(0, 0);
	conn_hfp[hands_free_unit].efd = eventfd(0, 0);

	for (int i = 0; i < VDB_NUM_PKTS; i++) {
		conn_hfp[audio_gateway].vdb.packet[i].header.msg_type = htons(sco_data_packet_type);
		conn_hfp[hands_free_unit].vdb.packet[i].header.msg_type = htons(sco_data_packet_type);
		conn_hfp[audio_gateway].vdb.packet[i].header.msg_len_after_header = htons(sizeof(struct sco_data_packet) - sizeof(struct log_message_header));
		conn_hfp[hands_free_unit].vdb.packet[i].header.msg_len_after_header = htons(sizeof(struct sco_data_packet) - sizeof(struct log_message_header));
		conn_hfp[audio_gateway].vdb.packet[i].data_len = SCO_DATA_LEN;
		conn_hfp[hands_free_unit].vdb.packet[i].data_len = SCO_DATA_LEN;
	}
	fixed_data_pkt.header.msg_type = htons(sco_data_packet_type);
	fixed_data_pkt.header.msg_len_after_header = htons(sizeof(struct sco_data_packet) - sizeof(struct log_message_header));
	fixed_data_pkt.data_len = SCO_DATA_LEN;
	discard_data_pkt.header.msg_type = htons(sco_data_packet_type);
	discard_data_pkt.header.msg_len_after_header = htons(sizeof(struct sco_data_packet) - sizeof(struct log_message_header));
	discard_data_pkt.data_len = SCO_DATA_LEN;

	/* Create thread for SCO relay */
	if (pthread_create(&sco_thread, NULL, &sco_thread_func, NULL)) {
		log_print(LOG_LEVEL_ERROR, "Failed to create sco_thread\n");
		result = -1;
		goto exit;
	}

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	g_assert_no_error(error);

	/* Register profile callbacks for HF role */
	introspection = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_assert_no_error(error);
	interface_info = g_dbus_node_info_lookup_interface(introspection, "org.bluez.Profile1");
	g_dbus_connection_register_object(conn, HFP_HF_PROFILE_PATH, interface_info, &vtable, (void *)hands_free_unit, NULL, &error);
	g_assert_no_error(error);
	g_dbus_node_info_unref(introspection);

	/* Register profile client for HF role (connecting to AG) */
	dbus_msg = g_dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.ProfileManager1", "RegisterProfile");

	g_variant_builder_init(&options, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&options, "{sv}", "Name", g_variant_new_string(HFP_PROFILE_NAME));
	g_variant_builder_add(&options, "{sv}", "RequireAuthentication", g_variant_new_boolean(FALSE));
	g_variant_builder_add(&options, "{sv}", "RequireAuthorization", g_variant_new_boolean(FALSE));

	g_dbus_message_set_body(dbus_msg, g_variant_new("(osa{sv})", HFP_HF_PROFILE_PATH, HFP_PROFILE_UUID, &options));

	g_variant_builder_clear(&options);

	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	/* Register profile callbacks for AG role*/
	introspection = g_dbus_node_info_new_for_xml(introspection_xml, &error);
	g_assert_no_error(error);
	interface_info = g_dbus_node_info_lookup_interface(introspection, "org.bluez.Profile1");
	g_dbus_connection_register_object(conn, HFP_AG_PROFILE_PATH, interface_info, &vtable, (void *)audio_gateway, NULL, &error);
	g_assert_no_error(error);
	g_dbus_node_info_unref(introspection);

	/* Register profile client for AG role (connecting to HF)*/
	dbus_msg = g_dbus_message_new_method_call("org.bluez", "/org/bluez", "org.bluez.ProfileManager1", "RegisterProfile");

	g_variant_builder_init(&options, G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(&options, "{sv}", "Name", g_variant_new_string(HFP_PROFILE_NAME));
	g_variant_builder_add(&options, "{sv}", "RequireAuthentication", g_variant_new_boolean(FALSE));
	g_variant_builder_add(&options, "{sv}", "RequireAuthorization", g_variant_new_boolean(FALSE));

	g_dbus_message_set_body(dbus_msg, g_variant_new("(osa{sv})", HFP_AG_PROFILE_PATH, HFP_AG_SERVICE_CLASS_UUID, &options));

	g_variant_builder_clear(&options);

	g_dbus_connection_send_message_with_reply_sync(conn, dbus_msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, -1, NULL, NULL, &error);
	g_assert_no_error(error);
	g_object_unref(dbus_msg);

	log_print(LOG_LEVEL_INFO, "HFP profile roles registered\n");

	loop = g_main_loop_new(NULL, FALSE);
	g_main_loop_run(loop);
exit:
	return result;
}

static void *sco_thread_func(void *arg)
{
	int sock_server_fd = -1;
	int i;
	int j;
	int bytes_read;
	int bytes_written;
	struct sockaddr_sco sock_addr = {0};
	struct bt_voice voice_opts = {0};
	struct sco_options sco_opts = {0};
	socklen_t voice_opts_len = sizeof(voice_opts);
	socklen_t sco_opts_len = sizeof(sco_opts);
	struct timespec mutex_timeout = {.tv_sec = 0, .tv_nsec = 10000};
	struct pollfd event_fds[1] = {0};
	struct pollfd listen_fds[2];
	struct pollfd sco_fds[2] = {0};
	bool ag_connected;
	struct hfp_connection *hc[2];
	uint64_t counter;

	while (1) {
		hc[audio_gateway] = &conn_hfp[audio_gateway];
		hc[hands_free_unit] = &conn_hfp[hands_free_unit];

		/* Wait for connected remote AG */
		event_fds[0].fd = hc[hands_free_unit]->efd;
		event_fds[0].events = POLLIN;
		if (poll(event_fds, 1, 2000) < 0) {
			log_perror("poll event_fd failed");
			continue;
		}

		if (event_fds[0].revents & POLLIN)
			assert(read(hc[hands_free_unit]->efd, &counter, sizeof(uint64_t)) > 0);

		if (pthread_mutex_timedlock(&hc[hands_free_unit]->sco_use_lock, &mutex_timeout))
			continue;


		if (!hc[hands_free_unit]->slc_established || hc[hands_free_unit]->slc_disconnect) {
			assert(!pthread_mutex_unlock(&hc[hands_free_unit]->sco_use_lock));
			continue;
		}

		/* Open SCO connection to AG device */
		sock_server_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
		if (sock_server_fd < 0) {
			log_perror("socket BTPROTO_SCO failed");
			continue;
		}

		/* Bind to local address */
		sock_addr.sco_family = AF_BLUETOOTH;
		str2ba(hc[hands_free_unit]->local_bdaddr_str, &sock_addr.sco_bdaddr);

		if (bind(sock_server_fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
			log_perror("bind sock_server_fd failed");
			goto unlock_sco_use_lock;
		}

		/* Listen for connections */
		if (listen(sock_server_fd, 10)) {
			log_perror("listen sock_server_fd failed");
			goto unlock_sco_use_lock;
		}

		while (!hc[hands_free_unit]->slc_disconnect) {
			log_print(LOG_LEVEL_INFO, "Waiting for SCO connection from remote AG\n");

			listen_fds[0].fd = sock_server_fd;
			listen_fds[0].events = POLLIN;
			listen_fds[1].fd = hc[hands_free_unit]->efd;
			listen_fds[1].events = POLLIN;
			if (poll(listen_fds, 2, -1) < 0) {
				log_perror("poll failed");
				goto unlock_sco_use_lock;	/* Unlock mutex and break loop */
			} else if (listen_fds[0].revents & POLLIN) {
				socklen_t sa_len = sizeof(sock_addr);

				hc[hands_free_unit]->sco_fd = accept(sock_server_fd, (struct sockaddr *) &sock_addr, &sa_len);
				if (hc[hands_free_unit]->sco_fd < 0) {
					log_perror("accept sock_server_fd failed");
					goto unlock_sco_use_lock;
				}
				/* TODO: Verify SRC address */
			} else if (listen_fds[1].revents & POLLIN) {
				assert(read(hc[hands_free_unit]->efd, &counter, sizeof(uint64_t)) > 0);
				if (hc[hands_free_unit]->slc_disconnect) {
					log_print(LOG_LEVEL_DEBUG, "slc_disconnect signaled for remote AG\n");
					goto unlock_sco_use_lock;
				}
			} else {
				log_print(LOG_LEVEL_DEBUG, "fd poll returned unexpected revent\n");
				goto unlock_sco_use_lock;
			}

			log_print(LOG_LEVEL_INFO, "SCO connection accepted from remote AG\n");
			hc[hands_free_unit]->sco_pkts_rcvd = 0;
			hc[hands_free_unit]->sco_pkts_sent = 0;

			if (getsockopt(hc[hands_free_unit]->sco_fd, SOL_SCO, SCO_OPTIONS, &sco_opts, &sco_opts_len) < 0) {
				log_perror("getsockopt hc[hands_free_unit]->sco_fd SOL_SCO failed");
				goto close_hf_sco_fd;
			}

			/* TODO: Avoid hard-coding sco_data_len */
			hc[hands_free_unit]->sco_data_len = SCO_DATA_LEN;

			if (getsockopt(hc[hands_free_unit]->sco_fd, SOL_BLUETOOTH, BT_VOICE, &voice_opts, &voice_opts_len) < 0) {
				log_perror("getsockopt hc[hands_free_unit]->sco_fd SOL_BLUETOOTH failed");
				goto close_hf_sco_fd;
			}

			if (!(voice_opts.setting & BT_VOICE_CVSD_16BIT)) {
				log_print(LOG_LEVEL_ERROR, "Voice format BT_VOICE_CVSD_16BIT not set\n");
				goto close_hf_sco_fd;
			}

			sco_fds[hands_free_unit].fd = hc[hands_free_unit]->sco_fd;
			sco_fds[audio_gateway].fd = -1;	/* Ignore this fd when polling by default */

			/* Try to acquire lock for sco use of local AG */
			if (!pthread_mutex_trylock(&hc[audio_gateway]->sco_use_lock)) {
				if (hc[audio_gateway]->slc_established && !hc[audio_gateway]->slc_disconnect) {
					ag_connected = true;
				} else {
					ag_connected = false;
					assert(!pthread_mutex_unlock(&hc[audio_gateway]->sco_use_lock));
				}
			}

			if (ag_connected) {
				bool fail = false;

				/* Open SCO connection to remote HF*/
				hc[audio_gateway]->sco_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
				if (hc[audio_gateway]->sco_fd < 0) {
					log_perror("socket BTPROTO_SCO failed");
					fail = true;
				}

				/* Bind to local address (in case of multiple attached controllers) */
				sock_addr.sco_family = AF_BLUETOOTH;
				str2ba(hc[audio_gateway]->local_bdaddr_str, &sock_addr.sco_bdaddr);

				if (bind(hc[audio_gateway]->sco_fd, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) < 0) {
					log_perror("bind hc[audio_gateway]->sco_fd failed");
					goto unlock_sco_use_lock;
				}

				if (!fail && setsockopt(hc[audio_gateway]->sco_fd, SOL_BLUETOOTH, BT_VOICE, &voice_opts, sizeof(voice_opts)) < 0) {
					log_perror("setsockopt hc[audio_gateway]->sco_fd SOL_BLUETOOTH failed");
					fail = true;
				}

				sock_addr.sco_family = AF_BLUETOOTH;
				str2ba(hc[audio_gateway]->remote_bdaddr_str, &sock_addr.sco_bdaddr);

				log_print(LOG_LEVEL_DEBUG, "Opening SCO socket to %s\n", hc[audio_gateway]->remote_bdaddr_str);
				if (!fail && connect(hc[audio_gateway]->sco_fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) < 0) {
					log_perror("connect hc[audio_gateway]->sco_fd failed");
					fail = true;
				}
				log_print(LOG_LEVEL_DEBUG, "SCO socket open to %s\n", hc[audio_gateway]->remote_bdaddr_str);

				hc[audio_gateway]->sco_pkts_rcvd = 0;
				hc[audio_gateway]->sco_pkts_sent = 0;

				if (!fail && getsockopt(hc[audio_gateway]->sco_fd, SOL_SCO, SCO_OPTIONS, &sco_opts, &sco_opts_len) < 0) {
					log_perror("getsockopt hc[audio_gateway]->sco_fd SOL_SCO failed");
					fail = true;
				}
				/* TODO: Avoid hard-coding sco_data_len */
				hc[audio_gateway]->sco_data_len = SCO_DATA_LEN;

				log_print(LOG_LEVEL_INFO, "SCO connection established to HF\n");

				if (!fail) {
					sco_fds[audio_gateway].fd = hc[audio_gateway]->sco_fd;
					sco_fds[audio_gateway].events = POLLIN;
				} else {
					if (hc[audio_gateway]->sco_fd != -1) {
						close(hc[audio_gateway]->sco_fd);
						hc[audio_gateway]->sco_fd = -1;
					}

					ag_connected = false;
					assert(!pthread_mutex_unlock(&hc[audio_gateway]->sco_use_lock));
				}

			}

			sco_fds[hands_free_unit].events = POLLOUT;
			sco_fds[audio_gateway].events = POLLOUT;

			assert(poll(sco_fds, 2, 1000) >= 0);
			if (ag_connected && !(sco_fds[audio_gateway].revents & POLLOUT))
				log_print(LOG_LEVEL_WARNING, "Local AG SCO socket not ready for writing\n");
			if (!(sco_fds[hands_free_unit].revents & POLLOUT))
				log_print(LOG_LEVEL_WARNING, "Local HF SCO socket not ready for writing\n");

			/* Flush SCO application data buffers */
			hc[hands_free_unit]->vdb.read_index = 0;
			hc[hands_free_unit]->vdb.write_index = 0;
			for (i = 0; i < VDB_NUM_PKTS; i++)
				hc[hands_free_unit]->vdb.packet[i].has_data = false;

			if (ag_connected) {
				hc[audio_gateway]->vdb.read_index = 0;
				hc[audio_gateway]->vdb.write_index = 0;
				for (i = 0; i < VDB_NUM_PKTS; i++)
					hc[audio_gateway]->vdb.packet[i].has_data = false;
			}

			for (i = 0, j = 0; i < NUM_PKTS_INITIAL_WRITE && j < NUM_PKTS_INITIAL_WRITE; ) {
				/* Use (sine) read data from HF to write HF to distinguish this data in logs */
				insert_voice_data_pkt(hc[hands_free_unit], &fixed_data_pkt); /* Avoid underflow messages */
				bytes_written = send_voice_data_pkt(hc[hands_free_unit], get_voice_data_pkt(hc[hands_free_unit]));
				if (bytes_written != -1)
					i++;

				if (ag_connected) {
					/* Use (sine) read data from AG to write AG to distinguish this data in logs */
					insert_voice_data_pkt(hc[audio_gateway], &fixed_data_pkt); /* Avoid underflow messages */
					bytes_written = send_voice_data_pkt(hc[audio_gateway], get_voice_data_pkt(hc[audio_gateway]));
					if (bytes_written != -1)
						j++;
				} else {
					j = NUM_PKTS_INITIAL_WRITE;
				}
			}

			sco_fds[hands_free_unit].events = POLLIN;
			sco_fds[audio_gateway].events = POLLIN;

			/* Flush SCO socket input data buffers */
			log_print(LOG_LEVEL_DEBUG, "Flushing SCO socket input buffers, sco_data_len_ag: %d, sco_data_len_hf: %d\n", hc[audio_gateway]->sco_data_len, hc[hands_free_unit]->sco_data_len);
			while (poll(sco_fds, 2, 0) > 0) {
				if (sco_fds[audio_gateway].revents & POLLIN) {
					bytes_read = receive_voice_data_pkt(hc[audio_gateway]);
					if (bytes_read <= 0)
						log_perror("read sock_fd");
				}
				if (sco_fds[hands_free_unit].revents & POLLIN) {
					bytes_read = receive_voice_data_pkt(hc[hands_free_unit]);
					if (bytes_read <= 0)
						log_perror("read sock_fd");
				}
			}
			log_print(LOG_LEVEL_DEBUG, "SCO socket input buffers flushed\n");

			/* Pre-fill voice data buffers to avoid underflow */
			for (i = 0; i < NUM_PKTS_PRE_FILL; i++) {
				insert_voice_data_pkt(hc[audio_gateway], &fixed_data_pkt);
				if (ag_connected)
					insert_voice_data_pkt(hc[hands_free_unit], &fixed_data_pkt);
			}

			log_print(LOG_LEVEL_INFO, "Starting test relay loop\n");
			while (1) {
				if (poll(sco_fds, 2, 1000) > 0) {
					if (sco_fds[audio_gateway].revents & POLLIN) {
						bytes_read = receive_voice_data_pkt(hc[audio_gateway]);
						if (bytes_read != -1) {
							bytes_written = send_voice_data_pkt(hc[audio_gateway], get_voice_data_pkt(hc[hands_free_unit]));
							if (bytes_written == -1)
								log_print(LOG_LEVEL_WARNING, "Socket write failure \"audio_gateway\"!\n");
						}
					}
					if (sco_fds[hands_free_unit].revents & POLLIN) {
						bytes_read = receive_voice_data_pkt(hc[hands_free_unit]);
						if (bytes_read != -1) {
							bytes_written = send_voice_data_pkt(hc[hands_free_unit], get_voice_data_pkt(hc[audio_gateway]));
							if (bytes_written == -1)
								log_print(LOG_LEVEL_WARNING, "Socket write failure \"hands_free_unit\"!\n");
						}
					}
					if (sco_fds[hands_free_unit].revents & POLLHUP) {
						log_print(LOG_LEVEL_INFO, "Remote AG closed SCO connection\n");
						break;
					}

					if (sco_fds[audio_gateway].revents & POLLHUP) {
						log_print(LOG_LEVEL_INFO, "Remote HF closed SCO connection\n");
						sco_fds[audio_gateway].fd = -1;	/* Ignore this fd for remaining SCO stream */
					}

					if (sco_fds[hands_free_unit].revents & ~POLLIN)
						log_print(LOG_LEVEL_DEBUG, "Local HF SCO fd poll returned unexpected revent\n");

					if (sco_fds[audio_gateway].revents & ~POLLIN)
						log_print(LOG_LEVEL_DEBUG, "Local AG SCO fd poll returned unexpected revent\n");
				} else {
					log_perror("poll failed or timed out");
					break;
				}
			}
			if (ag_connected) {
				log_print(LOG_LEVEL_DEBUG, "read_index[hands_free_unit]: %d, read_index[audio_gateway]: %d\n", hc[hands_free_unit]->vdb.read_index, hc[audio_gateway]->vdb.read_index);
				log_print(LOG_LEVEL_DEBUG, "write_index[hands_free_unit]: %d, write_index[audio_gateway]: %d\n", hc[hands_free_unit]->vdb.write_index, hc[audio_gateway]->vdb.write_index);
				log_print(LOG_LEVEL_DEBUG, "hc[audio_gateway]->sco_pkts_rcvd: %d\n", hc[audio_gateway]->sco_pkts_rcvd);
				log_print(LOG_LEVEL_DEBUG, "hc[audio_gateway]->sco_pkts_sent: %d\n", hc[audio_gateway]->sco_pkts_sent);
			}
			log_print(LOG_LEVEL_DEBUG, "hc[hands_free_unit]->sco_pkts_rcvd: %d\n", hc[hands_free_unit]->sco_pkts_rcvd);
			log_print(LOG_LEVEL_DEBUG, "hc[hands_free_unit]->sco_pkts_sent: %d\n", hc[hands_free_unit]->sco_pkts_sent);

			close(hc[hands_free_unit]->sco_fd);
			hc[hands_free_unit]->sco_fd = -1;
			if (ag_connected) {
				close(hc[audio_gateway]->sco_fd);
				hc[audio_gateway]->sco_fd = -1;
				ag_connected = false;
				assert(!pthread_mutex_unlock(&hc[audio_gateway]->sco_use_lock));
			}
		}	/* while(!hc[hands_free_unit]->slc_disconnect) */
close_hf_sco_fd:
		if (sco_fds[hands_free_unit].fd != -1)
			close(hc[hands_free_unit]->sco_fd);
unlock_sco_use_lock:
		assert(!close(sock_server_fd));
		sock_server_fd = -1;
		assert(!pthread_mutex_unlock(&hc[hands_free_unit]->sco_use_lock));
	} /* while (1) */

	if (sock_server_fd != -1)
		close(sock_server_fd);

	log_print(LOG_LEVEL_DEBUG, "Exiting SCO thread\n");

	return NULL;
}

