#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "apputils.h"
#include "uclient.h"
#include "ns_turn_utils.h"
#include "apputils.h"
#include "session.h"
#include "stun_buffer.h"

int clmessage_length = (int) sizeof(message_info);
uint8_t g_uname[STUN_MAX_USERNAME_SIZE + 1];
password_t g_password;
app_ur_session **all_session = NULL;

void usage()
{
	fprintf(stderr, "%s\n", "usage: turn_relay_client [-v] [-u username -w password] turn_server_address");
	exit(1);
}

int main(int argc, char **argv)
{
	int port = 0;
	int output_verbose = 0;
	char *server_addr;
	char msg_buffer[65536];
	const char *msg_to_send = "nat penatration test message";

	set_system_parameters(0);

	while ((c = getopt(argc, argv, "p:u:vw:")) != -1) {
		switch (c) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			STRCPY(g_password, optarg);
			break;
		case 'v':
			output_verbose = 1;
			break;
		case 'w':
		STRCPY(g_uname, optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage();
	}

	server_addr = argv[0];
	if (port == 0) {
		port = DEFAULT_STUN_PORT
	}

	// if (make_ioa_addr((const uint8_t*) peer_address, peer_port, &peer_addr) < 0) {
	// 	return -1;
	// }

	// if(peer_addr.ss.sa_family == AF_INET6) {
	// 	default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
	// } else if(peer_addr.ss.sa_family == AF_INET) {
	// 	default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
	// }



}

void start_myclient()
{
	all_session = (app_ur_session **)malloc(
			sizeof(app_ur_session) * ((mclient * 2) + 1) + sizeof(void *));

	
}