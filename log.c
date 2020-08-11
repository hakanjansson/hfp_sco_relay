#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>

#include "hfp_sco_relay.h"

const char * const level_text[] = {
	"NONE",
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG"
};

static struct txt_msg log_txt_msg;
static struct sockaddr_in log_serv_addr = {0};
static FILE *log_file;
static int log_sock_fd;
static int log_level;

uint64_t log_timestamp_us(void)
{
	int64_t us;
	struct timespec ts;

	timespec_get(&ts, TIME_UTC);

	us = ts.tv_sec * 1000000;
	us += ts.tv_nsec / 1000;

	return us;
}

void log_init(unsigned int level, FILE *file, char *address, uint16_t port)
{
	log_level = level;
	log_file = file;
	log_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	log_serv_addr.sin_family = AF_INET;
	inet_aton(address, &log_serv_addr.sin_addr);
	log_serv_addr.sin_port = htons(port);
}

int log_sco_data_pkt(struct sco_data_packet *packet, bdaddr_t *src, bdaddr_t *dst, uint32_t sequence)
{
	packet->header.timestamp = htonll(log_timestamp_us());
	bacpy(&packet->src, src);
	bacpy(&packet->dst, dst);
	packet->sequence = htonl(sequence);

	return sendto(log_sock_fd, packet, sizeof(*packet), 0, (struct sockaddr *) &log_serv_addr, sizeof(log_serv_addr));
}

void log_print(unsigned int level, const char *fmt, ...)
{
	va_list args;
	unsigned int msg_len;

	log_txt_msg.header.timestamp = log_timestamp_us();

	if (log_level >= level) {
		va_start(args, fmt);
		log_txt_msg.txt_len = vsnprintf(log_txt_msg.txt, MAX_LOG_TXT_LEN, fmt, args);
		va_end(args);

		log_txt_msg.txt_len = (log_txt_msg.txt_len < MAX_LOG_TXT_LEN - 1 ? log_txt_msg.txt_len : MAX_LOG_TXT_LEN - 1);
		log_txt_msg.txt[MAX_LOG_TXT_LEN - 1] = 0; /* Assure NULL termination */

		msg_len = sizeof(struct txt_msg) - MAX_LOG_TXT_LEN + log_txt_msg.txt_len + 1;
		log_txt_msg.header.msg_len_after_header =  msg_len - sizeof(struct log_message_header);

		if (log_file)
			fprintf(log_file, "[%" PRIu64 "] %s: %s", log_txt_msg.header.timestamp, level_text[level], log_txt_msg.txt);

		log_txt_msg.header.msg_type = htons(txt_msg_type);
		log_txt_msg.header.timestamp = htonll(log_txt_msg.header.timestamp);
		log_txt_msg.header.msg_len_after_header = htons(log_txt_msg.header.msg_len_after_header);
		log_txt_msg.log_level = htons(level);
		log_txt_msg.txt_len = htons(log_txt_msg.txt_len);

		sendto(log_sock_fd, &log_txt_msg, msg_len, 0, (struct sockaddr *) &log_serv_addr, sizeof(log_serv_addr));
	}
}

void log_perror(const char *s)
{
	log_print(LOG_LEVEL_ERROR, "%s: %s\n", s, strerror(errno));
}
