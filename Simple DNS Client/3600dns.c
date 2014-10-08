/*
 * CS3600, Spring 2014
 * Project 3 Starter Code
 * (c) 2013 Alan Mislove
 *
 */

#include <math.h>
#include <ctype.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "3600dns.h"

// Helper method to pack memory
void quick_pack(void **restrict dst, const void *restrict src, size_t size) {
	memcpy(*dst, src, size);
	*dst = (char *)*dst + size;
}
// Unpacks data specified location in memory
void quick_unpack(void *restrict dst, void **restrict src, size_t size) {
	memcpy(dst, *src, size);
	*src = (char *)*src + size;
}


//Packs the header to be used in write_packet
void pack_header(void **pkt, DNSHeader hdr) {
	uint16_t misc = ((hdr.qr << 15) & 0x8000) | // 1000000000000000
		((hdr.opcode << 11) & 0x7800) |         // 0111100000000000
		((hdr.aa << 10) & 0x400) |              // 0000010000000000
		((hdr.tc << 9) & 0x200) |               // 0000001000000000
		((hdr.rd << 8) & 0x100) |               // 0000000100000000
		((hdr.ra << 7) & 0x80) |                // 0000000010000000
		((hdr.z << 4) & 0x70) |                 // 0000000001110000
		(hdr.rcode & 0xF);                      // 0000000000001111

	uint16_t pack_id = htons(hdr.id);
	uint16_t pack_misc = htons(misc);
	uint16_t pack_qdcount = htons(hdr.qdcount);
	uint16_t pack_ancount = htons(hdr.ancount);
	uint16_t pack_nscount = htons(hdr.nscount);
	uint16_t pack_arcount = htons(hdr.arcount);

	quick_pack(pkt, &pack_id, sizeof(uint16_t));
	quick_pack(pkt, &pack_misc, sizeof(uint16_t));
	quick_pack(pkt, &pack_qdcount, sizeof(uint16_t));
	quick_pack(pkt, &pack_ancount, sizeof(uint16_t));
	quick_pack(pkt, &pack_nscount, sizeof(uint16_t));
	quick_pack(pkt, &pack_arcount, sizeof(uint16_t));
}

// Gets DNSHeader data from a packet
DNSHeader get_header(void **pkt) {
	DNSHeader *header = malloc(sizeof(DNSHeader)); // Allocate mem for the header

	uint16_t get_id,
		get_misc,
		get_qdcount,
		get_ancount,
		get_nscount,
		get_arcount;

	quick_unpack(&get_id, pkt, sizeof(uint16_t));
	quick_unpack(&get_misc, pkt, sizeof(uint16_t));
	quick_unpack(&get_qdcount, pkt, sizeof(uint16_t));
	quick_unpack(&get_ancount, pkt, sizeof(uint16_t));
	quick_unpack(&get_nscount, pkt, sizeof(uint16_t));
	quick_unpack(&get_arcount, pkt, sizeof(uint16_t));

	get_id = ntohs(get_id);
	get_misc = ntohs(get_misc);
	get_qdcount = ntohs(get_qdcount);
	get_ancount = ntohs(get_ancount);
	get_nscount = ntohs(get_nscount);
	get_arcount = ntohs(get_arcount);

	header->id = get_id;
	header->qdcount = get_qdcount;
	header->ancount = get_ancount;
	header->nscount = get_nscount;
	header->arcount = get_arcount;

	header->qr = ((get_misc >> 15) & 0x1);
	header->opcode = ((get_misc >> 11) & 0xF);
	header->aa = ((get_misc >> 10) & 0x1);
	header->tc = ((get_misc >> 9) & 0x1);
	header->rd = ((get_misc >> 8) & 0x1);
	header->ra = ((get_misc >> 7) & 0x1);
	header->z = ((get_misc >> 4) & 0x7);
	header->rcode = (get_misc & 0xF);

	return *header;
}

// Gets name data for a DNSQuestion from a packet
char *get_name(void **ptr, void *pkt) {
	char *name = malloc(256);  // 255 domain name + null byte.
	char *packer = name;

	uint16_t head = ntohs(*(uint16_t *)*ptr);
	if ((head & 0xC000) == 0xC000) {
		*(char *)ptr += 2;
		unsigned int offset = head & 0x3FFF;

		void *compressed_ptr = (char *)pkt + offset;
		char *part = get_name(&compressed_ptr, pkt);
		strcpy(packer, part);
		free(part);
	}
	else {
		char label_len;
		quick_unpack(&label_len, ptr, sizeof(char));
		for (int i = 0; i < label_len; i++) {
			quick_unpack(packer++, ptr, sizeof(char));
		}

		if (*(char *)*ptr == 0) {
			quick_unpack(packer, ptr, sizeof(char));
		}
		else {
			char period = '.';
			memcpy(packer++, &period, sizeof(char));
			char *part = get_name(ptr, pkt);
			strcpy(packer, part);
			free(part);
		}
	}

	return name;
}

// Packs the question to be used in write_packet
void pack_question(void **pkt, DNSQuestion qstn) {
	uint16_t pack_qtype = htons(qstn.qtype);
	uint16_t pack_qclass = htons(qstn.qclass);

	quick_pack(pkt, qstn.qname, strlen(qstn.qname) + 1);
	quick_pack(pkt, &pack_qtype, sizeof(uint16_t));
	quick_pack(pkt, &pack_qclass, sizeof(uint16_t));
}

// Gets the DNSQuestion data from a packet
DNSQuestion get_question(void **ptr, void *pkt) {
	DNSQuestion *question = malloc(sizeof(DNSQuestion));

	question->qname = get_name(ptr, pkt);

	uint16_t get_qtype, get_qclass;

	quick_unpack(&get_qtype, ptr, sizeof(uint16_t));
	quick_unpack(&get_qclass, ptr, sizeof(uint16_t));

	question->qtype = ntohs(get_qtype);
	question->qclass = ntohs(get_qclass);

	return *question;
}


/*
Allocates memory for the packet and packs the header and question
from the given data into it. Then return the size of the byte array
used (in bytes)
*/
size_t write_packet(unsigned char **pkt, DNSData data) {
	size_t packet_size = sizeof(DNSHeader)+strlen(data.question.qname)
		+ 1 + (sizeof(uint16_t)* 2);
	*pkt = malloc(packet_size);
	void *packer = *pkt;

	pack_header(&packer, data.header);
	pack_question(&packer, data.question);

	return packet_size;
}

// Gets the answers from the byte data
DNSAnswer *get_answers(void **ptr, void *pkt, size_t size) {
	DNSAnswer *answers;
	if (size <= 0) {
		answers = NULL;
	}
	else {
		answers = malloc(size * sizeof(DNSAnswer));
	}

	for (int i = 0; i < (int)size; i++) {
		DNSAnswer answer;

		// Name
		answer.name = get_name(ptr, pkt);

		// Middle Fields
		uint16_t get_type, get_class, get_rdlength;
		uint32_t get_ttl;

		quick_unpack(&get_type, ptr, sizeof(uint16_t));
		quick_unpack(&get_class, ptr, sizeof(uint16_t));
		quick_unpack(&get_ttl, ptr, sizeof(uint32_t));
		quick_unpack(&get_rdlength, ptr, sizeof(uint16_t));

		answer.type = ntohs(get_type);
		answer.class = ntohs(get_class);
		answer.ttl = ntohl(get_ttl);
		answer.rdlength = ntohs(get_rdlength);


		if (answer.type == 0x0001) {
			uint32_t *get_rdata = malloc(sizeof(uint32_t));
			quick_unpack(get_rdata, ptr, sizeof(uint32_t));
			*get_rdata = ntohl(*get_rdata);

			answer.rdata = *get_rdata;
		}
		else if (answer.type == 0x0005 ||
			answer.type == 0x0002) {
			answer.rdata = get_name(ptr, pkt);
		}

		answers[i] = answer;
	}

	return answers;
}

// Helper method to unpack from a byte array into DNSData
DNSData get_response(unsigned char *pkt) {
	DNSData *mydata = malloc(sizeof(DNSData));
	void *ptr = pkt;

	mydata->header = get_header(&ptr);
	mydata->question = get_question(&ptr, pkt);
	mydata->answers = get_answers(&ptr, pkt, mydata->header.ancount);

	return *mydata;
}



/**
 * This function will print a hex dump of the provided packet to the screen
 * to help facilitate debugging.  In your milestone and final submission, you
 * MUST call dump_packet() with your packet right before calling sendto().
 * You're welcome to use it at other times to help debug, but please comment those
 * out in your submissions.
 *
 * DO NOT MODIFY THIS FUNCTION
 *
 * data - The pointer to your packet buffer
 * size - The length of your packet
 */
static void dump_packet(unsigned char *data, int size) {
	unsigned char *p = data;
	unsigned char c;
	int n;
	char bytestr[4] = { 0 };
	char addrstr[10] = { 0 };
	char hexstr[16 * 3 + 5] = { 0 };
	char charstr[16 * 1 + 5] = { 0 };
	for (n = 1; n <= size; n++) {
		if (n % 16 == 1) {
			/* store address for this line */
			snprintf(addrstr, sizeof(addrstr), "%.4x",
				((unsigned int)p - (unsigned int)data));
		}

		c = *p;
		if (isprint(c) == 0) {
			c = '.';
		}

		/* store hex str (for left side) */
		snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
		strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr) - 1);

		/* store char str (for right side) */
		snprintf(bytestr, sizeof(bytestr), "%c", c);
		strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr) - 1);

		if (n % 16 == 0) {
			/* line completed */
			printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
			hexstr[0] = 0;
			charstr[0] = 0;
		}
		else if (n % 8 == 0) {
			/* half line: add whitespaces */
			strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr) - 1);
			strncat(charstr, " ", sizeof(charstr)-strlen(charstr) - 1);
		}
		p++; /* next byte */
	}

	if (strlen(hexstr) > 0) {
		/* print rest of buffer if not empty */
		printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
	}
}

// Our main:
int main(int argc, char *argv[]) {
	/**
	 * I've included some basic code for opening a socket in C, sending
	 * a UDP packet, and then receiving a response (or timeout).  You'll
	 * need to fill in many of the details, but this should be enough to
	 * get you started.
	 */
	short port = 53;
	char *name = strdup(argv[argc - 1]);
	char *token;
	char *ip;

	// Process the arguments
	if (argv[argc - 2][0] == '@') {
		char *raw_address = strdup(argv[argc - 2] + 1);
		int i = 0;
		while ((token = strsep(&raw_address, ":")) != NULL) {
			if (i == 0) {
				ip = token;
			}
			else{
				port = (short)strtol(token, NULL, 10);
			}
			i++;
		}
		free(raw_address);
	}

	// Construct the DNS request
	DNSData mydata = DEFAULT_DNSDATA;

	// Create QNAME from input info
	mydata.question.qname = malloc(strlen(name) + 2);
	void *tmp = mydata.question.qname;

	while ((token = strsep(&name, ".")) != NULL) {
		char len = strlen(token);

		memcpy(tmp, &len, 1);
		tmp = (char *)tmp + 1;

		memcpy(tmp, token, len);
		tmp = (char *)tmp + len;

	}
	char endbyte = 0x00;
	memcpy(tmp, &endbyte, sizeof(char));
	tmp = (char *)tmp + 1;
	free(name);
	mydata.question.qtype = 0x0001;

	// Write a packet for the data
	unsigned char *packet;
	size_t packet_size = write_packet(&packet, mydata);

	// Send the DNS request (and call dump_packet with your request)
	dump_packet(packet, packet_size);

	// First, open a UDP socket
	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	// Next, construct the destination address
	struct sockaddr_in out;
	out.sin_family = AF_INET;
	out.sin_port = htons(port);
	out.sin_addr.s_addr = inet_addr(ip);

	// Check if an error occurred
	if (sendto(sock, packet, packet_size, 0, &out, sizeof(out)) < 0) {
		printf("ERROR:\tError in socket construction.\n");
		exit(1);
	}

	// Wait for the DNS reply (timeout: 5 seconds)
	struct sockaddr_in in;
	socklen_t in_len;

	// Construct the socket set
	fd_set socks;
	FD_ZERO(&socks);
	FD_SET(sock, &socks);

	// Construct the timeout
	struct timeval t;
	t.tv_sec = 5;
	t.tv_usec = 0;


	size_t buff_size = 1024;
	unsigned char *buff = calloc(buff_size, sizeof(unsigned char));

	// Wait to receive (or for a timeout)
	if (select(sock + 1, &socks, NULL, NULL, &t)) {
		if (recvfrom(sock, buff, buff_size, 0, &in, &in_len) < 0) {
			// Error occured:
			printf("ERROR:\tCouldn't receive from the socket.\n");
			exit(1);
		}
	}
	else {
		// Timeout occurred:
		printf("NORESPONSE\n");
		exit(1);
	}

	// Construct the response
	DNSData response = get_response(buff);

	if (response.header.id != mydata.header.id ||
		response.header.qr != 1 ||
		response.header.opcode != 0 ||
		response.header.rd != 1 ||
		response.header.qdcount != 1) {
		printf("ERROR\tMalformed Response Header.\n");
		exit(1);
	}
	else if (response.question.qtype != mydata.question.qtype ||
		response.question.qclass != mydata.question.qclass ||
		strcmp(response.question.qname, argv[argc - 1]) != 0) {
		printf("ERROR\tResponse Question mismatch.\n");
		exit(1);
	}
	if (response.header.ancount == 0) {
		printf("NOTFOUND\n");
		exit(1);
	}
	for (int i = 0; i < response.header.ancount; i++) {
		DNSAnswer ans = response.answers[i];

		switch (ans.type) {
		case 0x0001:
			printf("IP\t");
			printf("%d.%d.%d.%d",
				(((uint32_t)ans.rdata) >> 24) & 0xFF,
				(((uint32_t)ans.rdata) >> 16) & 0xFF,
				(((uint32_t)ans.rdata) >> 8) & 0xFF,
				((uint32_t)ans.rdata) & 0xFF);

			if (response.header.aa) {
				printf("\tauth\n");
			}
			else {
				printf("\tnonauth\n");
			}
			break;
		case 0x0002:
			printf("NS\t%s", ans.rdata);
			if (response.header.aa) {
				printf("\tauth\n");
			}
			else {
				printf("\tnonauth\n");
			}
			break;
		case 0x0005:
			printf("CNAME\t%s", ans.rdata);
			if (response.header.aa) {
				printf("\tauth\n");
			}
			else {
				printf("\tnonauth\n");
			}
			break;
		case 0x000f:
			printf("MX\t%s", ans.rdata + 2);
			printf("\t%i", (uint16_t)*ans.rdata);
			if (response.header.aa) {
				printf("\tauth\n");
			}
			else {
				printf("\tnonauth\n");
			}
			break;
		}
	}


	return 0;
}
