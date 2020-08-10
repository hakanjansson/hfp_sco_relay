#ifndef HFP_RELAY_H
#define HFP_RELAY_H

#include <bluetooth/bluetooth.h>

#define SCO_DATA_LEN 60

#define MAX_LOG_TXT_LEN	512

#define LOG_LEVEL_NONE		0
#define LOG_LEVEL_ERROR		1
#define LOG_LEVEL_WARNING	2
#define LOG_LEVEL_INFO		3
#define LOG_LEVEL_DEBUG		4

#define htonll(x) ((htonl(1) == 1) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((ntohl(1) == 1) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

enum pkt_types {sco_data_packet_type = 0x01, txt_msg_type = 0x10};

struct __attribute__((__packed__)) log_message_header {
	uint16_t msg_type;
	uint64_t timestamp;
	uint16_t msg_len_after_header;
};

struct __attribute__((__packed__)) txt_msg {
	struct log_message_header header;
	uint16_t log_level;
	uint16_t txt_len;
	char txt[MAX_LOG_TXT_LEN];
};

struct __attribute__((__packed__)) sco_data_packet {
	struct log_message_header header;
	bdaddr_t src;
	bdaddr_t dst;
	uint8_t data_len;
	uint8_t has_data;
	uint32_t sequence;
	uint8_t data[SCO_DATA_LEN];
};

uint64_t log_timestamp_us(void);
void log_init(unsigned int level, FILE *file, char *address, uint16_t port);
int log_sco_data_pkt(struct sco_data_packet *packet, bdaddr_t *src, bdaddr_t *dst, uint32_t sequence);
void log_print(unsigned int level, const char *fmt, ...);
void log_perror(const char *s);

#endif
