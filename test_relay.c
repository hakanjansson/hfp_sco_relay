#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <poll.h>
#include <getopt.h>
#include <sys/timerfd.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/sco.h>
#include <bluetooth/rfcomm.h>

#define SCO_DATA_LEN	60
/* TODO: Log samples to log server */
#define MAX_SAMPLES_TO_WRITE (20 * 8000)		/* Write max 20 seconds of stream data to CSV file */

#define MAX_LEN_AT 512

#define CHECKPRINT(revents, flag)	do {if (revents & flag) printf(" %s", #flag); } while (0)

struct conn_info {
	FILE *pcm_in;
	FILE *pcm_out;
	int sco_fd;
	uint32_t pkts_sent;
	uint32_t pkts_rcvd;
	uint32_t total_bytes_written;
	uint32_t total_bytes_read;

	/* Buffers to hold audio stream data in memory for writing to CSV file later */
	int16_t bytes_sent[MAX_SAMPLES_TO_WRITE];
	int16_t bytes_rcvd[MAX_SAMPLES_TO_WRITE];
};

static struct conn_info ag;
static struct conn_info hf;

static unsigned char sco_data_in[SCO_DATA_LEN];		/* Input buffer for reads from SCO socket */
static unsigned char sco_data_out[SCO_DATA_LEN * 2];	/* Buffer to temporarily hold data for writes to SCO socket */

static char at_str[MAX_LEN_AT + 1];

static int wait_for_keypress;

static const struct option long_options[] = {
	{"wait-for-keypress", no_argument, &wait_for_keypress, 1},
	{"ag-addr", required_argument, 0, 'a'},
	{"hf-addr", required_argument, 0, 'h'},
	{"relay-addr", required_argument, 0, 'r'},
	{"relay-hf-channel", required_argument, 0, 'x'},
	{"relay-ag-channel", required_argument, 0, 'y'},
	{"pcm-in-ag", required_argument, 0, 'i'},
	{"pcm-in-hf", required_argument, 0, 'j'},
	{0, 0, 0, 0}
};

static void print_revents(unsigned int revents)
{
	CHECKPRINT(revents, POLLIN);
	CHECKPRINT(revents, POLLPRI);
	CHECKPRINT(revents, POLLOUT);
	CHECKPRINT(revents, POLLRDNORM);
	CHECKPRINT(revents, POLLRDBAND);
	CHECKPRINT(revents, POLLWRNORM);
	CHECKPRINT(revents, POLLWRBAND);
	CHECKPRINT(revents, POLLERR);
	CHECKPRINT(revents, POLLHUP);
	CHECKPRINT(revents, POLLNVAL);
}

static void write_csv_file(struct conn_info *ag, struct conn_info *hf)
{
	uint32_t num_samples;

	FILE *f = fopen("test_relay_streams.csv", "w");

	fprintf(f, "Local AG Sent,Local AG Rcvd,Local HF Sent,Local HF Rcvd\n");

	num_samples = (hf->total_bytes_written > ag->total_bytes_written ? hf->total_bytes_written : ag->total_bytes_written);
	num_samples /= 2;
	num_samples = (num_samples < MAX_SAMPLES_TO_WRITE ? num_samples : MAX_SAMPLES_TO_WRITE);

	for (int i = 0; i < num_samples; i++) {
		fprintf(f, "%d,", (int16_t)bt_get_le16(&ag->bytes_sent[i]));
		fprintf(f, "%d,", (int16_t)bt_get_le16(&ag->bytes_rcvd[i]));
		fprintf(f, "%d,", (int16_t)bt_get_le16(&hf->bytes_sent[i]));
		fprintf(f, "%d\n", (int16_t)bt_get_le16(&hf->bytes_rcvd[i]));
	}

	fclose(f);
}

static int send_at_command(int fd, const char *command, char *response, int response_len)
{
	int bytes_read;
	struct pollfd fds[1];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	printf("Command: %s\n", command);
	write(fd, command, strlen(command));

	poll(fds, 1, -1);
	if (fds[0].revents & POLLIN) {
		bytes_read = read(fd, response, response_len);
		assert(bytes_read != -1);
		response[bytes_read] = 0;
		printf("Response: %s", response);
		return 0;
	} else {
		return -1;
	}
}

static void establish_ag_slc(int fd)
{
	/* Service Level Connection Initialization */
	send_at_command(fd, "AT+BRSF=0\r", &at_str[0], MAX_LEN_AT);
	send_at_command(fd, "AT+CIND=?\r", &at_str[0], MAX_LEN_AT);
	send_at_command(fd, "AT+CIND?\r", &at_str[0], MAX_LEN_AT);
	send_at_command(fd, "AT+CMER=3,0,0,1\r", &at_str[0], MAX_LEN_AT);
}

static void establish_hf_slc(int fd)
{
	int bytes_read;
	bool established = false;
	struct pollfd fds[1];

	fds[0].fd = fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;

	while (!established) {

		poll(fds, 1, -1);
		if (fds[0].revents & POLLIN) {
			bytes_read = read(fd, &at_str[0], MAX_LEN_AT);
			assert(bytes_read != -1);

			at_str[bytes_read] = 0;
			printf("AT command received from HF: %s\n", at_str);

			if (strncmp(at_str, "AT+BRSF=", strlen("AT+BRSF=")) == 0) {
				strcpy(at_str, "\r\n+BRSF: 0\r\n\r\nOK\r\n");
			} else if (strncmp(at_str, "AT+CIND=?", strlen("AT+CIND=?")) == 0) {
				strcpy(at_str, "\r\n+CIND: (\"service\",(0,1)),(\"call\",(0,1))\r\n\r\nOK\r\n");
			} else if (strncmp(at_str, "AT+CIND?", strlen("AT+CIND?")) == 0) {
				strcpy(at_str, "\r\n+CIND: 1,0\r\n\r\nOK\r\n");
			} else if (strncmp(at_str, "AT+CMER", strlen("AT+CMER")) == 0) {
				strcpy(at_str, "\r\nOK\r\n");
				established = true;
			} else {
				strcpy(at_str, "\r\nERROR\r\n");
			}

			printf("Response: %s", at_str);
			write(fd, at_str, strlen(at_str));
		}
	}
}

static void transfer_sco_data(struct conn_info *ag, struct conn_info *hf)
{
	struct pollfd sco_fds[3] = {0};
	struct timespec ts;
	int bytes_read;
	int bytes_written;
	struct itimerspec new_value;
	int sco_write_timer_fd = timerfd_create(CLOCK_REALTIME, 0);

	timespec_get(&ts, TIME_UTC);

	new_value.it_value.tv_sec = ts.tv_sec;
	new_value.it_value.tv_nsec = ts.tv_nsec + 3750000;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = 7500000;

	if (new_value.it_value.tv_nsec > 1000000000) {
		new_value.it_value.tv_nsec -= 1000000000;
		new_value.it_value.tv_sec++;
	}

	if (timerfd_settime(sco_write_timer_fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1)
		assert(0);

	sco_fds[0].fd = ag->sco_fd;
	sco_fds[1].fd = hf->sco_fd;
	sco_fds[2].fd = sco_write_timer_fd;

	while (1) {
		sco_fds[0].events = POLLIN;
		sco_fds[1].events = POLLIN;
		sco_fds[2].events = POLLIN;
		if (poll(sco_fds, 3, 1000) > 0) {
			if (sco_fds[0].revents & POLLIN) {
				bytes_read = read(ag->sco_fd, &sco_data_in[0], SCO_DATA_LEN);
				if (bytes_read != -1) {
					ag->pkts_rcvd++;
					if (ag->total_bytes_read + bytes_read <= MAX_SAMPLES_TO_WRITE * 2) {
						memcpy(&ag->bytes_rcvd[ag->total_bytes_read/2], &sco_data_in[0], bytes_read);
						ag->total_bytes_read += bytes_read;
					}
				}
			}

			if (sco_fds[1].revents & POLLIN) {
				bytes_read = read(hf->sco_fd, &sco_data_in[0], SCO_DATA_LEN);
				if (bytes_read != -1) {
					hf->pkts_rcvd++;
					if (hf->total_bytes_read + bytes_read <= MAX_SAMPLES_TO_WRITE * 2) {
						memcpy(&hf->bytes_rcvd[hf->total_bytes_read / 2], &sco_data_in[0], bytes_read);
						hf->total_bytes_read += bytes_read;
					}
				}
			}

			if (sco_fds[2].revents & POLLIN) {
				uint64_t counter;

				read(sco_write_timer_fd, &counter, sizeof(counter));
				if (counter != 1)
					printf("WARNING: sco_write_timer_fd read counter: %ld\n", counter);

				if (ag->sco_fd != -1) {
					if (!fread(sco_data_out, SCO_DATA_LEN, 2, ag->pcm_in))
						break;	/* Exit on EOF */

					bytes_written = write(ag->sco_fd, &sco_data_out[0], SCO_DATA_LEN);
					if (bytes_written != -1) {
						ag->pkts_sent++;
						if (ag->total_bytes_written + bytes_written <= MAX_SAMPLES_TO_WRITE * 2) {
							memcpy(&ag->bytes_sent[ag->total_bytes_written/2], &sco_data_out[0], bytes_written);
							ag->total_bytes_written += bytes_written;
						}
					}
					bytes_written = write(ag->sco_fd, &sco_data_out[60], SCO_DATA_LEN);
					if (bytes_written != -1) {
						ag->pkts_sent++;
						if (ag->total_bytes_written + bytes_written <= MAX_SAMPLES_TO_WRITE * 2) {
							memcpy(&ag->bytes_sent[ag->total_bytes_written/2], &sco_data_out[60], bytes_written);
							ag->total_bytes_written += bytes_written;
						}
					}
				}
				if (hf->sco_fd != -1) {
					if (!fread(sco_data_out, 60, 2, hf->pcm_in))
						break;	/* Exit on EOF */

					bytes_written = write(hf->sco_fd, &sco_data_out[0], SCO_DATA_LEN);
					if (bytes_written != -1) {
						hf->pkts_sent++;
						if (hf->total_bytes_written + bytes_written <= MAX_SAMPLES_TO_WRITE * 2) {
							memcpy(&hf->bytes_sent[hf->total_bytes_written / 2], &sco_data_out[0], bytes_written);
							hf->total_bytes_written += bytes_written;
						}
					}
					bytes_written = write(hf->sco_fd, &sco_data_out[60], SCO_DATA_LEN);
					if (bytes_written != -1) {
						hf->pkts_sent++;
						if (hf->total_bytes_written + bytes_written <= MAX_SAMPLES_TO_WRITE * 2) {
							memcpy(&hf->bytes_sent[hf->total_bytes_written / 2], &sco_data_out[60], bytes_written);
							hf->total_bytes_written += bytes_written;
						}
					}
				}
			}

			if (sco_fds[0].revents & ~POLLIN) {
				printf("sco_fds[0].revents: ");
				print_revents(sco_fds[0].revents);
				printf("\n");
			}

			if (sco_fds[1].revents & ~POLLIN) {
				printf("sco_fds[1].revents: ");
				print_revents(sco_fds[1].revents);
				printf("\n");
			}
		}
	}
	write_csv_file(ag, hf);
	printf("CSV file written\n");
	close(sco_write_timer_fd);
}

int main(int argc, char **argv)
{
	int ret = -1;

	int rc_sock_hf_fd = -1;
	int rc_sock_ag_fd = -1;

	int sco_sock_hf_accepted_fd = -1;
	int sco_sock_hf_listening_fd = -1;
	int sco_sock_ag_fd = -1;

	struct sockaddr_rc rc_sock_addr_local_hf = {0};
	struct sockaddr_rc rc_sock_addr_local_ag = {0};
	struct sockaddr_rc rc_sock_addr_relay_hf = {0};
	struct sockaddr_rc rc_sock_addr_relay_ag = {0};

	struct sockaddr_sco sco_sock_addr_local_hf = {0};
	struct sockaddr_sco sco_sock_addr_local_ag = {0};
	struct sockaddr_sco sco_sock_addr_relay = {0};
	socklen_t addr_len;

	struct bt_voice voice_opts_ag = {0};
	struct sco_options sco_opts_ag = {0};
	socklen_t sco_opts_len_ag = sizeof(sco_opts_ag);

	int ch;
	int option_index = 0;

	char *bdaddr_hf = NULL;
	char *bdaddr_ag = NULL;
	char *bdaddr_relay = NULL;
	int relay_ag_channel = 13;
	int relay_hf_channel = 7;
	char *pcm_in_ag_file_name = "pcm_in_ag.pcm";
	char *pcm_in_hf_file_name = "pcm_in_hf.pcm";

	while ((ch = getopt_long (argc, argv, "a:h:r:i:j:", long_options, &option_index)) != -1) {
		switch (ch) {
		case 'a':
			bdaddr_ag = optarg;
			break;

		case 'h':
			bdaddr_hf = optarg;
			break;

		case 'r':
			bdaddr_relay = optarg;
			break;

		case 'x':
			sscanf(optarg, "%u", &relay_hf_channel);
			break;

		case 'y':
			sscanf(optarg, "%u", &relay_ag_channel);
			break;

		case 'i':
			pcm_in_ag_file_name = optarg;
			break;

		case 'j':
			pcm_in_hf_file_name = optarg;
			break;

		case 0:
			if (long_options[option_index].flag != 0)
				break;

		default:
			ret = -1;
			goto exit;
		}
	}

	printf("Relay BDADDR: %s, AG Channel: %d, HF Channel: %d\n", bdaddr_relay, relay_ag_channel, relay_hf_channel);
	printf("Local AG BDADDR: %s\n", bdaddr_ag);
	printf("Local HF BDADDR: %s\n", bdaddr_hf);
	printf("PCM input Local AG file name: %s\n", pcm_in_ag_file_name);
	printf("PCM input Local HF file name: %s\n", pcm_in_hf_file_name);
	printf("Wait for keypress: %s\n", (wait_for_keypress ? "TRUE" : "FALSE"));

	if (!bdaddr_ag && !bdaddr_hf) {
		ret = -1;
		goto exit;
	}

	if (bdaddr_ag) {
		ag.pcm_in = fopen(pcm_in_ag_file_name, "r");
		if (!ag.pcm_in) {
			printf("ERROR: Couldn't open PCM input file \"%s\"\n", pcm_in_ag_file_name);
			ret = -1;
			goto exit;
		}

		/* Connect local AG to Relay HF */
		rc_sock_ag_fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
		assert(rc_sock_ag_fd >= 0);
		printf("Local AG RFCOMM socket created\n");

		rc_sock_addr_local_ag.rc_family = AF_BLUETOOTH;
		rc_sock_addr_local_ag.rc_channel = 0;
		str2ba(bdaddr_ag, &rc_sock_addr_local_ag.rc_bdaddr);

		if (bind(rc_sock_ag_fd, (struct sockaddr *) &rc_sock_addr_local_ag, sizeof(rc_sock_addr_local_ag)) < 0) {
			printf("ERROR: bind failed: %s\n", strerror(errno));
			assert(0);
		}

		rc_sock_addr_relay_hf.rc_family = AF_BLUETOOTH;
		rc_sock_addr_relay_hf.rc_channel = relay_hf_channel;
		str2ba(bdaddr_relay, &rc_sock_addr_relay_hf.rc_bdaddr);

		ret = connect(rc_sock_ag_fd, (struct sockaddr *)&rc_sock_addr_relay_hf, sizeof(rc_sock_addr_relay_hf));
		if (ret == -1) {
			printf("ERROR: Couldn't open AG RFCOMM socket: %s\n", strerror(errno));
			assert(0);
		}
		establish_hf_slc(rc_sock_ag_fd);
		printf("Local AG RFCOMM connected\n");
	}

	sleep(1);

	if (bdaddr_hf) {
		hf.pcm_in = fopen(pcm_in_hf_file_name, "r");
		if (!hf.pcm_in) {
			printf("ERROR: Couldn't open PCM input file \"%s\"\n", pcm_in_hf_file_name);
			goto exit;
		}

		/* Connect local HF to Relay AG */
		rc_sock_hf_fd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
		assert(rc_sock_hf_fd >= 0);
		printf("Local HF RFCOMM socket created\n");

		rc_sock_addr_local_hf.rc_family = AF_BLUETOOTH;
		rc_sock_addr_local_hf.rc_channel = 0;
		str2ba(bdaddr_hf, &rc_sock_addr_local_hf.rc_bdaddr);

		if (bind(rc_sock_hf_fd, (struct sockaddr *) &rc_sock_addr_local_hf, sizeof(rc_sock_addr_local_hf)) < 0) {
			printf("ERROR: bind failed: %s\n", strerror(errno));
			assert(0);
		}

		rc_sock_addr_relay_ag.rc_family = AF_BLUETOOTH;
		rc_sock_addr_relay_ag.rc_channel = relay_ag_channel;
		str2ba(bdaddr_relay, &rc_sock_addr_relay_ag.rc_bdaddr);

		ret = connect(rc_sock_hf_fd, (struct sockaddr *)&rc_sock_addr_relay_ag, sizeof(rc_sock_addr_relay_ag));
		if (ret == -1) {
			printf("ERROR: Couldn't open HF RFCOMM socket: %s\n", strerror(errno));
			assert(0);
		}
		establish_ag_slc(rc_sock_hf_fd);
		printf("Local HF RFCOMM connected\n");
	}

	sleep(1);
	if (wait_for_keypress) {
		printf("Press enter to continue!\n");
		getchar();
	}


	if (bdaddr_hf) {
		/* Setup SCO listening socket */
		sco_sock_hf_listening_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
		assert(sco_sock_hf_listening_fd >= 0);
		printf("Local HF SCO listen socket created\n");

		/* Bind to local address */
		memset(&sco_sock_addr_local_hf, 0, sizeof(sco_sock_addr_local_hf));
		sco_sock_addr_local_hf.sco_family = AF_BLUETOOTH;
		str2ba(bdaddr_hf, &sco_sock_addr_local_hf.sco_bdaddr);

		if (bind(sco_sock_hf_listening_fd, (struct sockaddr *) &sco_sock_addr_local_hf, sizeof(sco_sock_addr_local_hf)) < 0) {
			printf("ERROR: bind failed: %s\n", strerror(errno));
			assert(0);
		}

		/* Listen for connections */
		if (listen(sco_sock_hf_listening_fd, 10)) {
			printf("ERROR: listen failed: %s\n", strerror(errno));
			assert(0);
		}
	}

	sleep(2);

	if (bdaddr_ag) {
		/* Connect SCO between local AG and Relay HF */
		sco_sock_ag_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_SCO);
		assert(sco_sock_ag_fd >= 0);

		memset(&sco_sock_addr_local_ag, 0, sizeof(sco_sock_addr_local_ag));
		sco_sock_addr_local_ag.sco_family = AF_BLUETOOTH;
		str2ba(bdaddr_ag, &sco_sock_addr_local_ag.sco_bdaddr);

		if (bind(sco_sock_ag_fd, (struct sockaddr *) &sco_sock_addr_local_ag, sizeof(sco_sock_addr_local_ag)) < 0) {
			printf("Can't bind socket: %s (%d)\n", strerror(errno), errno);
			assert(0);
		}

		voice_opts_ag.setting = BT_VOICE_CVSD_16BIT;
		ret = setsockopt(sco_sock_ag_fd, SOL_BLUETOOTH, BT_VOICE, &voice_opts_ag, sizeof(voice_opts_ag));
		assert(ret != -1);

		memset(&sco_sock_addr_relay, 0, sizeof(sco_sock_addr_relay));
		sco_sock_addr_relay.sco_family = AF_BLUETOOTH;
		str2ba(bdaddr_relay, &sco_sock_addr_relay.sco_bdaddr);

		ret = connect(sco_sock_ag_fd, (struct sockaddr *)&sco_sock_addr_relay, sizeof(sco_sock_addr_relay));
		assert(ret != -1);

		ret = getsockopt(sco_sock_ag_fd, SOL_SCO, SCO_OPTIONS, &sco_opts_ag, &sco_opts_len_ag);
		assert(ret != -1);

		printf("Local AG SCO socket connected\n");
		ag.sco_fd = sco_sock_ag_fd;
	} else
		ag.sco_fd = -1;

	if (bdaddr_hf) {
		/* Accept incoming SCO socket connection */
		addr_len = sizeof(sco_sock_addr_relay);
		sco_sock_hf_accepted_fd = accept(sco_sock_hf_listening_fd, (struct sockaddr *) &sco_sock_addr_relay, &addr_len);
		if (sco_sock_hf_accepted_fd < 0) {
			printf("Accept failed: %s (%d)", strerror(errno), errno);
			assert(0);
		}
		printf("Local HF SCO socket connection accepted from Relay AG\n");
		hf.sco_fd = sco_sock_hf_accepted_fd;
	} else
		hf.sco_fd = -1;

	transfer_sco_data(&ag, &hf);

	printf("Number of packets received, local HF: %d\n", hf.pkts_rcvd);
	printf("Number of packets sent, local HF: %d\n", hf.pkts_sent);
	printf("Number of packets received, local AG: %d\n", ag.pkts_rcvd);
	printf("Number of packets sent, local AG: %d\n", ag.pkts_sent);
	printf("Press ENTER to exit program!\n");
	getchar();

	if (sco_sock_hf_accepted_fd != -1)
		close(sco_sock_hf_accepted_fd);

	if (sco_sock_ag_fd != -1)
		close(sco_sock_ag_fd);

	if (sco_sock_hf_listening_fd != -1)
		close(sco_sock_hf_listening_fd);

	if (rc_sock_ag_fd != -1)
		close(rc_sock_ag_fd);

	if (rc_sock_hf_fd != -1)
		close(rc_sock_hf_fd);

	ret = 0;
exit:
	return ret;
}
