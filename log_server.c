#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <poll.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>

#include "hfp_sco_relay.h"

#define LOG_MSG_MAX_LEN	1024
#define NUM_STREAMS	4	/* TODO: Dynamic nr of streams */
#define FILE_NAME_LEN	64

struct sco_data_stream {
	bdaddr_t src;
	bdaddr_t dst;
	char src_str[18];
	char dst_str[18];
	uint32_t sequence;
	FILE *pcm_file;
};

struct sco_data_stream sco_streams[NUM_STREAMS];

static uint8_t log_msg_buf[LOG_MSG_MAX_LEN];

const char * const level_text[] = {
	"NONE",
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG"
};

char *csv_file_name;
FILE *csv_file;
unsigned int log_serv_port = 4445;

static const struct option long_options[] = {
	{"csv", required_argument, 0, 'c'},
	{"port", required_argument, 0, 'p'},
	{0, 0, 0, 0}
};

void txt_msg_rcvd(void)
{
	struct txt_msg *msg = (struct txt_msg *)log_msg_buf;

	msg->log_level = ntohs(msg->log_level);
	msg->txt_len = ntohs(msg->txt_len);
	printf("[%" PRIu64 "] %s: %s", msg->header.timestamp, level_text[msg->log_level], msg->txt);
}

void sco_data_rcvd(void)
{
	int i;
	int j;

	struct sco_data_packet *packet = (struct sco_data_packet *)log_msg_buf;

	packet->sequence = ntohl(packet->sequence);

	for (i = 0; i < NUM_STREAMS; i++) {
		if (!bacmp(&sco_streams[i].src, BDADDR_ANY)) {
			bacpy(&sco_streams[i].src, &packet->src);
			bacpy(&sco_streams[i].dst, &packet->dst);
			break;
		} else if (!bacmp(&packet->src, &sco_streams[i].src) && !bacmp(&packet->dst, &sco_streams[i].dst)) {
			break;
		}
	}
	if (i == NUM_STREAMS) {
		printf("ERROR: Too many sco_streams\n");
		goto exit;
	}

	/* Check for new stream */
	if ((sco_streams[i].sequence == 0) || (sco_streams[i].sequence > packet->sequence)) {
		char pcm_file_name[FILE_NAME_LEN];

		if (sco_streams[i].pcm_file)
			fclose(sco_streams[i].pcm_file);

		/* Open pcm file for recording raw sample data*/
		ba2str(&sco_streams[i].src, sco_streams[i].src_str);
		ba2str(&sco_streams[i].dst, sco_streams[i].dst_str);
		snprintf(pcm_file_name, FILE_NAME_LEN, "sco_stream__%s__%s.pcm", sco_streams[i].src_str, sco_streams[i].dst_str);
		for (int j = 0; j < FILE_NAME_LEN; j++)
			if (pcm_file_name[j] == ':')
				pcm_file_name[j] = '_';

		sco_streams[i].pcm_file = fopen(pcm_file_name, "w");
		if (!sco_streams[i].pcm_file) {
			printf("ERROR: Failed to open file: %s\n", pcm_file_name);
			bacpy(&sco_streams[i].src, BDADDR_ANY);
			bacpy(&sco_streams[i].dst, BDADDR_ANY);
			goto exit;
		}
	}
	if (csv_file) {
		fprintf(csv_file, "%" PRIu64 ",%s,%s,%" PRIu32,
			packet->header.timestamp, sco_streams[i].src_str, sco_streams[i].dst_str, packet->sequence);
		for (j = 0; j < SCO_DATA_LEN; j += 2)
			fprintf(csv_file, ",%d", (int16_t)bt_get_le16(&packet->data[j]));

		fprintf(csv_file, "\n");
	}

	fwrite(packet->data, packet->data_len, 1, sco_streams[i].pcm_file);

	sco_streams[i].sequence = packet->sequence;

exit:
	;	/* exit label can't be last statement in function */
}

int main(int argc, char **argv)
{
	int i;
	int result = -1;
	int log_sock_fd;
	struct sockaddr_in log_client_addr = {0};
	struct sockaddr_in log_serv_addr = {0};
	unsigned int log_client_addr_len;
	struct pollfd fds[2];
	int ch;
	int option_index = 0;

	while ((ch = getopt_long (argc, argv, "c:p:", long_options, &option_index)) != -1) {
		switch (ch) {
		case 'c':
			csv_file_name = optarg;
			break;

		case 'p':
			sscanf(optarg, "%u", &log_serv_port);
			break;

		default:
			goto exit;
		}
	}

	if (csv_file_name) {
		csv_file = fopen(csv_file_name, "w");
		if (!csv_file) {
			printf("ERROR: Couldn't open csv file %s for logging, %s\n", csv_file_name, strerror(errno));
			goto exit;
		}
		fprintf(csv_file, "Timestamp,Source,Destination,Sequence");
		for (i = 0; i < SCO_DATA_LEN / 2; i++)
			fprintf(csv_file, ",Sample[%d]", i);

		fprintf(csv_file, "\n");
	}

	log_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (log_sock_fd < 0) {
		perror("ERROR: socket() failed");
		result = -1;
		goto exit;
	}

	fds[0].fd = log_sock_fd;
	fds[0].events = POLLIN;
	fds[0].revents = 0;
	fds[1].fd = STDIN_FILENO;
	fds[1].events = POLLIN;
	fds[1].revents = 0;

	log_serv_addr.sin_family = AF_INET;
	log_serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	log_serv_addr.sin_port = htons(log_serv_port);

	if (bind(log_sock_fd, (struct sockaddr *)&log_serv_addr, sizeof(log_serv_addr)) < 0) {
		perror("ERROR: bind() failed");
		result = -1;
		goto close_dbg_sock_fd;
	}

	printf("Log server started, listening on port %d\n", log_serv_port);
	printf("Press ENTER to exit\n");
	while (1) {
		struct log_message_header *header = (struct log_message_header *)log_msg_buf;

		log_client_addr_len = sizeof(struct sockaddr_in);

		result = poll(fds, 2, -1);
		if (result >= 0) {
			if (fds[0].revents & POLLIN) {
				recvfrom(log_sock_fd, log_msg_buf, LOG_MSG_MAX_LEN, 0, (struct sockaddr *)&log_client_addr, &log_client_addr_len);

				header->msg_type = ntohs(header->msg_type);
				header->timestamp = ntohll(header->timestamp);
				header->msg_len_after_header = ntohs(header->msg_len_after_header);

				switch (header->msg_type) {
				case sco_data_packet_type:
					sco_data_rcvd();
					break;

				case txt_msg_type:
					txt_msg_rcvd();
					break;

				default:
					printf("ERROR: Received packet with unknown msg_type (%d)\n", header->msg_type);
					break;
				}
			} else if (fds[1].revents & POLLIN) {
				result = 0;
				goto close_files;
			}
		} else {
			perror("ERROR: poll() failed");
			result = -1;
			goto close_files;
		}
	}
close_files:
	for (int i = 0; i < NUM_STREAMS; i++) {
		if (sco_streams[i].pcm_file)
			fclose(sco_streams[i].pcm_file);
	}
close_dbg_sock_fd:
	close(log_sock_fd);
exit:
	return result;
}

