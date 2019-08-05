#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <err.h>

#include "apputils.h"
#include "uclient.h"
#include "ns_turn_utils.h"
#include "apputils.h"
#include "session.h"
#include "stun_buffer.h"
#include "startuclient.h"

#define SLEEP_INTERVAL (200)

int clmessage_length = (int) sizeof(message_info);
uint8_t g_uname[STUN_MAX_USERNAME_SIZE + 1];
password_t  g_upwd;
app_ur_session **all_session = NULL;

//int clmessage_length=100;
int do_not_use_channel=0;
int c2c=0;
int clnet_verbose=TURN_VERBOSE_NONE;
int use_tcp=0;
int use_sctp=0;
int use_secure=0;
int hang_on=0;
ioa_addr peer_addr;
int no_rtcp = 1;
int default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_DEFAULT;
int dont_fragment = 0;
//uint8_t g_uname[STUN_MAX_USERNAME_SIZE+1];
password_t g_upwd;
char g_auth_secret[1025]="\0";
int g_use_auth_secret_with_timestamp = 0;
int use_fingerprints = 1;

//static char ca_cert_file[1025]="";
//static char cipher_suite[1025]="";
char cert_file[1025]="";
char pkey_file[1025]="";
SSL_CTX *root_tls_ctx[32];
int root_tls_ctx_num = 0;

uint8_t relay_transport = STUN_ATTRIBUTE_TRANSPORT_UDP_VALUE;
unsigned char client_ifname[1025] = "";
int passive_tcp = 0;
int mandatory_channel_padding = 0;
int negative_test = 0;
int negative_protocol_test = 0;
int dos = 0;
int random_disconnect = 0;
int is_verbose = 0;

SHATYPE shatype = SHATYPE_DEFAULT;

int mobility = 0;

int no_permissions = 0;

int extra_requests = 0;

char origin[STUN_MAX_ORIGIN_SIZE+1] = "\0";

band_limit_t bps = 0;

int dual_allocation = 0;

int oauth = 0;
oauth_key okey_array[3];

/*
static oauth_key_data_raw okdr_array[3] = {
       	{"north","MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEK",0,0,"A256GCM","crinna.org"},
	{"union","MTIzNDU2Nzg5MDEyMzQ1Ngo=",0,0,"A128GCM","north.gov"},
	{"oldempire","MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIK",0,0,"A256GCM",""}
};
*/

void usage(void);
void start_myclient(const char *server_address, int port,
		const unsigned char *ifname, const char *local_address);
static app_ur_session *create_new_ss(void);
static int refresh_channel(app_ur_session* elem, uint16_t method, uint32_t lt);
static int clnet_allocate(int verbose, app_ur_conn_info *clnet_info,
    ioa_addr *relay_addr, int af, char *turn_addr, uint16_t *turn_port);
static int clnet_connect(uint16_t clnet_remote_port, const char *remote_address,
    const unsigned char* ifname, const char *local_address, int verbose,
    app_ur_conn_info *clnet_info);
int s2c_start(uint16_t clnet_remote_port0, const char *remote_address0,
		const char *local_address, int verbose, app_ur_conn_info *clnet_info_probe,
		app_ur_conn_info *clnet_info);
static int turn_channel_bind(int verbose, uint16_t *chn,
     app_ur_conn_info *clnet_info, ioa_addr *peer_addr);
//static SSL* tls_connect(ioa_socket_raw fd, ioa_addr *remote_addr, int *try_again, int connect_cycle);

int main(int argc, char **argv)
{
	int port = 0;
	int messagenumber = 5;
	char *server_addr;
	char local_addr[256] = {0};
	char peer_address[129] = {0};
	int peer_port = PEER_DEFAULT_PORT;

	//const char *msg_to_send = "nat penatration test message";
	
	set_system_parameters(0);

	char c;
	while ((c = getopt(argc, argv, "vp:u:vw:L:n:")) != -1) {
		switch (c) {
		case 'v':
			is_verbose = 1;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			STRCPY(g_uname, optarg);
			break;
		case 'w':
			STRCPY(g_upwd, optarg);
			break;
		case 'L':
			STRCPY(local_addr, optarg);
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
		port = DEFAULT_STUN_PORT;
	}

	//TODO: this code is not usefull in c2c mode
//	if (make_ioa_addr((const uint8_t*) peer_address, peer_port, &peer_addr) < 0) {
//		return -1;
//	}
//
//	if(peer_addr.ss.sa_family == AF_INET6) {
//		default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
//	} else if(peer_addr.ss.sa_family == AF_INET) {
//		default_address_family = STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
//	}
//

	printf("start myclient\n");
	start_myclient(server_addr, port, client_ifname, local_addr);
}

static char msg_buffer[65536] = {0};
app_ur_session *curr_session;
static uint64_t current_time = 0;
static uint64_t current_mstime = 0;
static int show_statistics = 0;
static int current_clients_number = 0;
static uint32_t tot_messages = 0;
static int start_full_timer = 0;

//static uint64_t tot_send_bytes = 0;
//static uint64_t tot_recv_bytes = 0;
static uint32_t tot_recv_messages = 0;
//static uint32_t tot_send_messages = 0;
//static uint32_t tot_send_dropped = 0;
static uint64_t current_reservation_token = 0;

static uint64_t total_latency = 0;
static uint64_t total_jitter = 0;
static uint64_t total_loss = 0;

//static uint64_t min_latency = 0xFFFFFFFF;
//static uint64_t max_latency = 0;
//static uint64_t min_jitter = 0xFFFFFFFF;
//static uint64_t max_jitter = 0;
//
void usage(void)
{
	fprintf(stderr, "%s\n",
	    "usage: turn_relay_client [-v] [-u username -w password] turn_server_address");
	exit(1);
}

static app_ur_session *create_new_ss(void)
{
	++current_clients_number;
	app_ur_session *tmp = (app_ur_session *)malloc(sizeof(app_ur_session));
	if (tmp) {
		bzero(tmp, sizeof(app_ur_session));
		tmp->pinfo.fd = -1;
	}
	return tmp;
}

static int refresh_channel(app_ur_session* elem, uint16_t method, uint32_t lt)
{
	stun_buffer message;
	app_ur_conn_info *clnet_info = &(elem->pinfo);

	if(clnet_info->is_peer)
		return 0;

	if (!method || (method == STUN_METHOD_REFRESH)) {
		stun_init_request(STUN_METHOD_REFRESH, &message);
		lt = htonl(lt);
		stun_attr_add(&message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);

		if(dual_allocation && !mobility) {
			int t = ((uint8_t)random())%3;
			if(t) {
				uint8_t field[4];
				field[0] = (t==1) ?
				    (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 
				    : (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
				field[1]=0;
				field[2]=0;
				field[3]=0;
				stun_attr_add(
				    &message,
				    STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY,
				    (const char*) field, 4);
			}
		}

		add_origin(&message);
		if(add_integrity(clnet_info, &message)<0) return -1;
		if(use_fingerprints)
			stun_attr_add_fingerprint_str(message.buf, (size_t*) &(message.len));
		send_buffer(clnet_info, &message, 0,0);
	}

	if (lt && !addr_any(&(elem->pinfo.peer_addr))) {
		if(!no_permissions) {
			if (!method || (method == STUN_METHOD_CREATE_PERMISSION)) {
				stun_init_request(STUN_METHOD_CREATE_PERMISSION, &message);
				stun_attr_add_addr(&message,
				    STUN_ATTRIBUTE_XOR_PEER_ADDRESS,
				    &(elem->pinfo.peer_addr));
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
				       	stun_attr_add_fingerprint_str(
					    message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message, 0,0);
			}
		}

		if (!method || (method == STUN_METHOD_CHANNEL_BIND)) {
			if (STUN_VALID_CHANNEL(elem->chnum)) {
				stun_set_channel_bind_request(&message,
				    &(elem->pinfo.peer_addr), elem->chnum);
				add_origin(&message);
				if(add_integrity(clnet_info, &message)<0) return -1;
				if(use_fingerprints)
				       	stun_attr_add_fingerprint_str(
					    message.buf, (size_t*) &(message.len));
				send_buffer(&(elem->pinfo), &message,1,0);
			}
		}
	}

	elem->refresh_time = current_mstime + 30 * 1000;
	return 0;
}

static int clnet_allocate(int verbose,
		app_ur_conn_info *clnet_info,
		ioa_addr *relay_addr,
		int af,
		char *turn_addr, uint16_t *turn_port)
{

	int af_cycle = 0;
	int reopen_socket = 0;

	int allocate_finished;

	stun_buffer request_message, response_message;

	beg_allocate:

	allocate_finished=0;

	while (!allocate_finished && af_cycle++ < 32) {
		printf("allocate while loop\n");

		int allocate_sent = 0;

		if(reopen_socket && !use_tcp) {
			socket_closesocket(clnet_info->fd);
			clnet_info->fd = -1;
			if (clnet_connect(addr_get_port(&(clnet_info->remote_addr)), clnet_info->rsaddr, (uint8_t*)clnet_info->ifname, clnet_info->lsaddr,
					verbose, clnet_info) < 0) {
				exit(-1);
			}
			reopen_socket = 0;
		}

		int af4 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4);
		int af6 = dual_allocation || (af == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6);

		uint64_t reservation_token = 0;
		char* rt = NULL;
		//int ep = !no_rtcp && !dual_allocation;
		int ep = 0; /* We do not need even port */

//		if(!no_rtcp) {
//			if (!never_allocate_rtcp && allocate_rtcp) {
//				reservation_token = ioa_ntoh64(current_reservation_token);
//				rt = (char*) (&reservation_token);
//			}
//		}
//
		if(is_TCP_relay()) {
			ep = -1;
		} else if(rt) {
			ep = -1;
		} else if(!ep) {
			ep = (((uint8_t)random()) % 2);
			ep = ep-1;
		}

		if(!dos)
			/* request_message, lifetime, af4, af6, relay_tranport, mobility, reservation_token, even_port */
			stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME, af4, af6, relay_transport, mobility, rt, ep);
		else
			stun_set_allocate_request(&request_message, UCLIENT_SESSION_LIFETIME/3, af4, af6, relay_transport, mobility, rt, ep);

		if(bps)
			stun_attr_add_bandwidth_str(request_message.buf, (size_t*)(&(request_message.len)), bps);

		if(dont_fragment)
			stun_attr_add(&request_message, STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!allocate_sent) {

			int len = send_buffer(clnet_info, &request_message,0,0);

			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "allocate sent\n");
				}
				allocate_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}

		////////////<<==allocate send

		////////allocate response==>>
		{
			int allocate_received = 0;
			while (!allocate_received) {

				int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);

				printf("len: %d\n", len);
				if (len > 0) {
					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								"allocate response received: \n");
					}
					response_message.len = len;
					int err_code = 0;
					uint8_t err_msg[129];
					if (stun_is_success_response(&response_message)) {
						printf("success response\n");
						allocate_received = 1;
						allocate_finished = 1;

						if(clnet_info->nonce[0]) {
							if(check_integrity(clnet_info, &response_message)<0)
								return -1;
						}

						if (verbose) {
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
						}
						{
							int found = 0;

							stun_attr_ref sar = stun_attr_get_first(&response_message);
							while (sar) {

								int attr_type = stun_attr_get_type(sar);
								if(attr_type == STUN_ATTRIBUTE_XOR_RELAYED_ADDRESS) {

									if (stun_attr_get_addr(&response_message, sar, relay_addr, NULL) < 0) {
										TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
											"%s: !!!: relay addr cannot be received (1)\n",
											__FUNCTION__);
										return -1;
									} else {
										if (verbose) {
											ioa_addr raddr;
											memcpy(&raddr, relay_addr,sizeof(ioa_addr));
											addr_debug_print(verbose, &raddr,"Received relay addr");
										}

										if(!addr_any(relay_addr)) {
											if(relay_addr->ss.sa_family == AF_INET) {
												if(default_address_family != STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
													found = 1;
													addr_cpy(&(clnet_info->relay_addr),relay_addr);
													break;
												}
											}
											if(relay_addr->ss.sa_family == AF_INET6) {
												if(default_address_family == STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6) {
													found = 1;
													addr_cpy(&(clnet_info->relay_addr),relay_addr);
													break;
												}
											}
										}
									}
								}

								sar = stun_attr_get_next(&response_message,sar);
							}

							if(!found) {
								TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
										"%s: !!!: relay addr cannot be received (2)\n",
										__FUNCTION__);
								return -1;
							}
						}

						stun_attr_ref rt_sar = stun_attr_get_first_by_type(
								&response_message, STUN_ATTRIBUTE_RESERVATION_TOKEN);
						uint64_t rtv = stun_attr_get_reservation_token_value(rt_sar);
						current_reservation_token = rtv;
						if (verbose)
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
								      "%s: rtv=%llu\n", __FUNCTION__, (long long unsigned int)rtv);

						read_mobility_ticket(clnet_info, &response_message);

					} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
									&err_code,err_msg,sizeof(err_msg),
									clnet_info->realm,clnet_info->nonce,
									clnet_info->server_name, &(clnet_info->oauth))) {
						printf("challenge response\n");
						goto beg_allocate;
					} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
						printf("error response\n");

						allocate_received = 1;
						printf("errcode: %d\n", err_code);

						if(err_code == 300) {
							printf("300: %d\n", err_code);

							if(clnet_info->nonce[0]) {
								if(check_integrity(clnet_info, &response_message)<0)
									return -1;
							}

							ioa_addr alternate_server;
							if(stun_attr_get_first_addr(&response_message, STUN_ATTRIBUTE_ALTERNATE_SERVER, &alternate_server, NULL)==-1) {
								//error
							} else if(turn_addr && turn_port){
								addr_to_string_no_port(&alternate_server, (uint8_t*)turn_addr);
								*turn_port = (uint16_t)addr_get_port(&alternate_server);
							}

						}

						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n",
								      err_code,(char*)err_msg);
						if (err_code != 437) {
							printf("437: %d\n", err_code);
							allocate_finished = 1;
							current_reservation_token = 0;
							return -1;
						} else {
							printf("other: %d\n", err_code);
							TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"trying allocate again %d...\n", err_code);
							sleep(1);
							reopen_socket = 1;
						}
					} else {
						printf("other\n");
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
									"unknown allocate response\n");
						/* Try again ? */
					}
				} else {
					perror("recv");
					exit(-1);
					break;
				}
			}
		}
	}
	////////////<<== allocate response received

	if(!allocate_finished) {
		  TURN_LOG_FUNC(TURN_LOG_LEVEL_ERROR,
			"Cannot complete Allocation\n");
		  exit(-1);
	}

	//allocate_rtcp = !allocate_rtcp;

	af_cycle = 0;

//	if(clnet_info->s_mobile_id[0]) {
//		int fd = clnet_info->fd;
//		SSL* ssl = clnet_info->ssl;
//		int close_now = (int)(random()%2);
//
//		  if(close_now) {
//			  int close_socket = (int)(random()%2);
//			  if(ssl && !close_socket) {
//				  SSL_shutdown(ssl);
//				  SSL_free(ssl);
//				  fd = -1;
//			  } else if(fd>=0) {
//				  close(fd);
//				  fd = -1;
//				  ssl = NULL;
//			  }
//		  }
//
//		  app_ur_conn_info ci;
//		  bcopy(clnet_info,&ci,sizeof(ci));
//		  ci.fd = -1;
//		  ci.ssl = NULL;
//		  clnet_info->fd = -1;
//		  clnet_info->ssl = NULL;
//		  //Reopen:
//		  if(clnet_connect(addr_get_port(&(ci.remote_addr)), ci.rsaddr,
//				(unsigned char*)ci.ifname, ci.lsaddr, clnet_verbose,
//				clnet_info)<0) {
//			  exit(-1);
//		  }
//
//		  if(ssl) {
//			  SSL_shutdown(ssl);
//			  SSL_free(ssl);
//		  } else if(fd>=0) {
//			  close(fd);
//		  }
//	}

	return 0;
}

void refresh_callback(int fd, short ev, void *arg)
{

	UNUSED_ARG(fd);
	UNUSED_ARG(ev);
	UNUSED_ARG(arg);

	int refresh_sent = 0;
	stun_buffer request_message, response_message;
	app_ur_conn_info *clnet_info = &curr_session->pinfo;

beg_refresh:
	//==>>refresh request, for an example only:

	stun_init_request(STUN_METHOD_REFRESH, &request_message);
	uint32_t lt = htonl(UCLIENT_SESSION_LIFETIME);
	stun_attr_add(&request_message, STUN_ATTRIBUTE_LIFETIME, (const char*) &lt, 4);

	if(clnet_info->s_mobile_id[0]) {
		stun_attr_add(&request_message, STUN_ATTRIBUTE_MOBILITY_TICKET, (const char*)clnet_info->s_mobile_id, strlen(clnet_info->s_mobile_id));
	}

	if(dual_allocation && !mobility) {
		int t = ((uint8_t)random())%3;
		if(t) {
			uint8_t field[4];
			field[0] = (t==1) ? (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4 : (uint8_t)STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV6;
			field[1]=0;
			field[2]=0;
			field[3]=0;
			stun_attr_add(&request_message, STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY, (const char*) field, 4);
		}
	}

	add_origin(&request_message);

	if(add_integrity(clnet_info, &request_message)<0) return;

	stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

	while (!refresh_sent) {

		int len = send_buffer(clnet_info, &request_message, 0,0);

		if (len > 0) {
			if (is_verbose)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "refresh sent\n");
			refresh_sent = 1;

			if(clnet_info->s_mobile_id[0]) {
				usleep(10000);
				send_buffer(clnet_info, &request_message, 0,0);
			}
		} else {
			perror("send");
			exit(1);
		}
	}

////////refresh response==>>
	int refresh_received = 0;
	while (!refresh_received) {

		int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);

		if(clnet_info->s_mobile_id[0]) {
			len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
		}

		if (len > 0) {
			if (is_verbose)
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				    "refresh response received: \n");
			response_message.len = len;
			int err_code = 0;
			uint8_t err_msg[129];
			if (stun_is_success_response(&response_message)) {
				read_mobility_ticket(clnet_info, &response_message);
				refresh_received = 1;
				if (is_verbose)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
			} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
								&err_code,err_msg,sizeof(err_msg),
								clnet_info->realm,clnet_info->nonce,
								clnet_info->server_name, &(clnet_info->oauth))) {
				goto beg_refresh;
			} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
				refresh_received = 1;
				if (is_verbose)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "error %d (%s)\n",
					    err_code,(char*)err_msg);
				return;
			} else {
				if (is_verbose)
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown refresh response\n");
				/* Try again ? */
			}
		} else {
			perror("recv");
			exit(-1);
			break;
		}
	}
}
//static SSL* tls_connect(ioa_socket_raw fd, ioa_addr *remote_addr, int *try_again, int connect_cycle)
//{
//	int ctxtype = (int)(((unsigned long)random())%root_tls_ctx_num);
//	SSL *ssl;
//	ssl = SSL_new(root_tls_ctx[ctxtype]);
//
//#if ALPN_SUPPORTED
//	SSL_set_alpn_protos(ssl, kALPNProtos, kALPNProtosLen);
//#endif
//
//	if(use_tcp) {
//		SSL_set_fd(ssl, fd);
//	} else {
//#if !DTLS_SUPPORTED
//	  UNUSED_ARG(remote_addr);
//	  fprintf(stderr,"ERROR: DTLS is not supported.\n");
//	  exit(-1);
//#else
//		/* Create BIO, connect and set to already connected */
//		BIO *bio = BIO_new_dgram(fd, BIO_CLOSE);
//		//bio = BIO_new_socket(fd, BIO_CLOSE);
//
//		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr->ss);
//
//		SSL_set_bio(ssl, bio, bio);
//
//		{
//			struct timeval timeout;
//			/* Set and activate timeouts */
//			timeout.tv_sec = DTLS_MAX_CONNECT_TIMEOUT;
//			timeout.tv_usec = 0;
//			BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
//		}
//
//		set_mtu_df(ssl, fd, remote_addr->ss.sa_family, SOSO_MTU, !use_tcp, clnet_verbose);
//#endif
//	}
//
//	SSL_set_max_cert_list(ssl, 655350);
//
//	if (clnet_verbose)
//		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "call SSL_connect...\n");
//
//	int rc = 0;
//
//	do {
//		do {
//			rc = SSL_connect(ssl);
//		} while (rc < 0 && errno == EINTR);
//		int orig_errno = errno;
//		if (rc > 0) {
//		  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: client session connected with cipher %s, method=%s\n",__FUNCTION__,
//				  SSL_get_cipher(ssl),turn_get_ssl_method(ssl,NULL));
//		  if(clnet_verbose && SSL_get_peer_certificate(ssl)) {
//			  TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "------------------------------------------------------------\n");
//		  	X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)), 1,
//		  						XN_FLAG_MULTILINE);
//		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n Cipher: %s\n", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
//		  	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n------------------------------------------------------------\n\n");
//		  }
//		  break;
//		} else {
//			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot connect: rc=%d, ctx=%d\n",
//					__FUNCTION__,rc,ctxtype);
//
//			switch (SSL_get_error(ssl, rc)) {
//			case SSL_ERROR_WANT_READ:
//			case SSL_ERROR_WANT_WRITE:
//				if(!dos) usleep(1000);
//				continue;
//			default: {
//				char buf[1025];
//				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "errno=%d, err=%d, %s (%d)\n",orig_errno,
//								(int)ERR_get_error(), ERR_error_string(ERR_get_error(), buf), (int)SSL_get_error(ssl, rc));
//				if(connect_cycle<MAX_TLS_CYCLES) {
//					if(try_again) {
//						SSL_free(ssl);
//						*try_again = 1;
//						return NULL;
//					}
//				}
//				exit(-1);
//			}
//			};
//		}
//	} while (1);
//
//	if (clnet_verbose && SSL_get_peer_certificate(ssl)) {
//		if(use_tcp) {
//			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//				"------TLS---------------------------------------------------\n");
//		} else {
//			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//				"------DTLS---------------------------------------------------\n");
//		}
//		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(
//				SSL_get_peer_certificate(ssl)), 1, XN_FLAG_MULTILINE);
//		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "\n\n Cipher: %s\n",
//				SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
//		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//				"\n------------------------------------------------------------\n\n");
//	}
//
//	return ssl;
//}

/**
	try to setup a socket and use the socket info to fill ou clnet_info
	On sucess, it'll return 0, -1 otherwise
	Parameters:
		clnet_remote_port: remote port
		remote_address: TURN server address
		ifname: local interface name
		local_address: local address
		verbose:
		clnet_info: per connection info
*/
static int clnet_connect(uint16_t clnet_remote_port, const char *remote_address,
		const unsigned char* ifname, const char *local_address, int verbose,
		app_ur_conn_info *clnet_info)
{

	ioa_addr local_addr;
	evutil_socket_t clnet_fd;
	int connect_err;
	int connect_cycle = 0;

	ioa_addr remote_addr;

 start_socket:

	clnet_fd = -1;
	connect_err = 0;

	bzero(&remote_addr, sizeof(ioa_addr));
	if (make_ioa_addr((const uint8_t*) remote_address, clnet_remote_port,
			&remote_addr) < 0)
		return -1;

	bzero(&local_addr, sizeof(ioa_addr));

	clnet_fd = socket(remote_addr.ss.sa_family,
			use_sctp ? SCTP_CLIENT_STREAM_SOCKET_TYPE : (use_tcp ? CLIENT_STREAM_SOCKET_TYPE : CLIENT_DGRAM_SOCKET_TYPE),
			use_sctp ? SCTP_CLIENT_STREAM_SOCKET_PROTOCOL : (use_tcp ? CLIENT_STREAM_SOCKET_PROTOCOL : CLIENT_DGRAM_SOCKET_PROTOCOL));
	if (clnet_fd < 0) {
		perror("socket");
		exit(-1);
	}

	if (sock_bind_to_device(clnet_fd, ifname) < 0) {
		TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
				"Cannot bind client socket to device %s\n", ifname);
	}

	set_sock_buf_size(clnet_fd, UR_CLIENT_SOCK_BUF_SIZE);

	set_raw_socket_tos(clnet_fd, remote_addr.ss.sa_family, 0x22);
	set_raw_socket_ttl(clnet_fd, remote_addr.ss.sa_family, 47);

	printf("client_info_is_peer\n");
	if(clnet_info->is_peer && (*local_address==0)) {

		/* if ipv6, set local_address to ::1 (ipv6 loopback).
			if ipv4, set local_address to 127.0.0.1 (ipv4 loopback) */
		if(remote_addr.ss.sa_family == AF_INET6) {
			if (make_ioa_addr((const uint8_t*) "::1", 0, &local_addr) < 0) {
			    return -1;
			}
		} else {
			if (make_ioa_addr((const uint8_t*) "127.0.0.1", 0, &local_addr) < 0) {
			    return -1;
			}
		}

		addr_bind(clnet_fd, &local_addr, 0, 1, get_socket_type());

	} else if (strlen(local_address) > 0) {

		if (make_ioa_addr((const uint8_t*) local_address, 0,
			    &local_addr) < 0)
			return -1;

		addr_bind(clnet_fd, &local_addr,0,1,get_socket_type());
	}


	if(clnet_info->is_peer) {
		;
	} else if(socket_connect(clnet_fd, &remote_addr, &connect_err)>0)
		goto start_socket;

	if (clnet_info) {
		addr_cpy(&(clnet_info->remote_addr), &remote_addr);
		printf(".\n");
		addr_cpy(&(clnet_info->local_addr), &local_addr);
		printf(".\n");
		clnet_info->fd = clnet_fd;
		printf(".\n");
		addr_get_from_sock(clnet_fd, &(clnet_info->local_addr));
		printf(".\n");
		STRCPY(clnet_info->lsaddr,local_address);
		printf(".\n");
		STRCPY(clnet_info->rsaddr,remote_address);
		printf(".\n");
		if (ifname) {
			STRCPY(clnet_info->ifname,(const char*)ifname);
		}
		printf(".\n");
	}

	/*
	if (use_secure) {
		int try_again = 0;
		clnet_info->ssl = tls_connect(clnet_info->fd, &remote_addr,&try_again,connect_cycle++);
		if (!clnet_info->ssl) {
			if(try_again) {
				goto start_socket;
			}
			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "%s: cannot SSL connect to remote addr\n", __FUNCTION__);
			exit(-1);
		}
	}
	*/

	if(verbose && clnet_info) {
		addr_debug_print(verbose, &(clnet_info->local_addr), "Connected from");
		addr_debug_print(verbose, &remote_addr, "Connected to");
	}

	if(!dos) usleep(500);

	return 0;
}

/**
 * send a turn channel bind request, and recv the response
 *
 *
 */
static int turn_channel_bind(int verbose, uint16_t *chn,
     app_ur_conn_info *clnet_info, ioa_addr *peer_addr)
{

	stun_buffer request_message, response_message;

	beg_bind:

	{
		int cb_sent = 0;

		if(negative_test) {
			*chn = stun_set_channel_bind_request(&request_message, peer_addr, (uint16_t)random());
		} else {
			*chn = stun_set_channel_bind_request(&request_message, peer_addr, *chn);
		}

		add_origin(&request_message);

		if(add_integrity(clnet_info, &request_message)<0) return -1;

		stun_attr_add_fingerprint_str(request_message.buf,(size_t*)&(request_message.len));

		while (!cb_sent) {

			int len = send_buffer(clnet_info, &request_message, 0,0);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind sent\n");
				}
				cb_sent = 1;
			} else {
				perror("send");
				exit(1);
			}
		}
	}

	////////////<<==channel bind send

	////////channel bind response==>>

	{
		int cb_received = 0;
		while (!cb_received) {

			int len = recv_buffer(clnet_info, &response_message, 1, 0, NULL, &request_message);
			if (len > 0) {
				if (verbose) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
							"cb response received: \n");
				}
				int err_code = 0;
				uint8_t err_msg[129];
				if (stun_is_success_response(&response_message)) {

					cb_received = 1;

					if(clnet_info->nonce[0]) {
						if(check_integrity(clnet_info, &response_message)<0)
							return -1;
					}

					if (verbose) {
						TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success: 0x%x\n",
								(int) (*chn));
					}
				} else if (stun_is_challenge_response_str(response_message.buf, (size_t)response_message.len,
										&err_code,err_msg,sizeof(err_msg),
										clnet_info->realm,clnet_info->nonce,
										clnet_info->server_name, &(clnet_info->oauth))) {
					goto beg_bind;
				} else if (stun_is_error_response(&response_message, &err_code,err_msg,sizeof(err_msg))) {
					cb_received = 1;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "channel bind: error %d (%s)\n",
							      err_code,(char*)err_msg);
					return -1;
				} else {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "unknown channel bind response\n");
					/* Try again ? */
				}
			} else {
				perror("recv");
				exit(-1);
				break;
			}
		}
	}

	return 0;
}

static void run_events(struct event_base *base, int short_burst)
{
	struct timeval timeout;
	if(short_burst) {
		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;
	} else {
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
	}

	event_base_loopexit(base, &timeout);
	event_base_dispatch(base);
}

/* 修改current_time 已运行时间 && current_mstime */
static void __turn_getMSTime(void)
{
	static uint64_t start_sec = 0;
	struct timespec tp={0,0};
#if defined(CLOCK_REALTIME)
	clock_gettime(CLOCK_REALTIME, &tp);
#else
	tp.tv_sec = time(NULL);
#endif
	// cause start_sec is a static, we have to initialize it this way
	if(!start_sec)
		start_sec = tp.tv_sec;
	// print log message every 1 second, show_stattistics is use to control log msgs
	if(current_time != (uint64_t)((uint64_t)(tp.tv_sec)-start_sec))
		show_statistics = 1;
	current_time = (uint64_t)((uint64_t)(tp.tv_sec)-start_sec);
	current_mstime = (uint64_t)((current_time * 1000) + (tp.tv_nsec/1000000));
}

int s2c_start(uint16_t clnet_remote_port0, const char *remote_address0,
		const char *local_address, int verbose, app_ur_conn_info *clnet_info_probe,
		app_ur_conn_info *clnet_info)
{
	ioa_addr relay_addr;

	/* probe , 可能是用来探测可选端口的 */
	if (clnet_connect(clnet_remote_port0, remote_address0, NULL, local_address,
	    verbose, clnet_info_probe) < 0) {
		exit(-1);
	}
	printf("probe sent\n");

	uint16_t clnet_remote_port = clnet_remote_port0;
	char remote_address[1025];
	STRCPY(remote_address,remote_address0);

	clnet_allocate(verbose, clnet_info_probe, &relay_addr, 
	    default_address_family, remote_address, &clnet_remote_port);

	if (clnet_connect(clnet_remote_port, remote_address, NULL, local_address,
			verbose, clnet_info) < 0) {
	  exit(-1);
	}
	printf("real sent\n");

	int af =  STUN_ATTRIBUTE_REQUESTED_ADDRESS_FAMILY_VALUE_IPV4;
//	int af = default_address_family ? default_address_family :
//	    get_allocate_address_family(&peer_addr);

	if (clnet_allocate(verbose, clnet_info, &relay_addr, af, NULL,NULL) < 0) {
	  exit(-1);
	}

	addr_cpy(&clnet_info->relay_addr, &relay_addr);
	//if (!do_not_use_channel) {
	//	if (turn_channel_bind(verbose, chn, clnet_info, &peer_addr_rtcp) < 0) {
	//		exit(-1);
	//	}
	//} else {

	//}
	
	printf("fin s2c start\n");
	return 0;
}

void stdin_callback(int fd, short ev, void *arg)
{
	UNUSED_ARG(ev);
	UNUSED_ARG(arg);

#define MAX_LEN 256
	char buff[MAX_LEN] = {0};
	int err;
	char addr[MAX_LEN] = {0};
	char port[MAX_LEN] = {0};

	err = read(fd, buff, sizeof(buff));
	if (err < 0)
		exit(-1);
	if (err == 0)
		return;

	char *tp;
	char *start = buff;
	for (tp = start; *tp != 0 && *tp != ':'; tp++)
		;

	strncpy(addr, buff, tp - start);
	
	if (*tp)
		start = tp + 1;
	for (tp = start; *tp != '\0' && *tp != '\n'; tp++)
		;

	strncpy(port, start, tp - start);
	int iport = atoi(port);

	if (make_ioa_addr((const uint8_t *)addr, iport, &curr_session->pinfo.peer_addr) < 0) {
		return;
	}
	addr_debug_print(1, &curr_session->pinfo.peer_addr, "peer address: ");

	if (turn_channel_bind(is_verbose, &curr_session->chnum,
	    &curr_session->pinfo, &curr_session->pinfo.peer_addr) < 0) {
		exit(-1);
	}

	event_del((struct event *)arg[0]);
	event_add((struct event *)arg[1], NULL);
	//event_add((struct event *)arg, NULL);
}

void message_input_callback(int fd, short ev, void *arg) 
{
	int err;
	char buff[65536];

	while ((err = read(fd, buff, sizeof(buff))) > 0) {
		if(!curr_session)
			return -1;
		if(curr_session->state != UR_STATE_READY)
			return -1;

		curr_session->ctime = current_time;

		app_tcp_conn_info *atc = NULL;

		if (is_TCP_relay()) {
			memcpy(curr_session->out_buffer.buf, buff, err);
			curr_session->out_buffer.len = err;

			if(curr_session->pinfo.is_peer) {
				if(send(curr_session->pinfo.fd, curr_session->out_buffer.buf, err, 0)>=0) {
					++curr_session->wmsgnum;
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "success\n");->to_send_timems += RTP_PACKET_INTERVAL;
					tot_send_messages++;
					tot_send_bytes += err;
				}
				return 0;
			}

			if (!(curr_session->pinfo.tcp_conn) || !(curr_session->pinfo.tcp_conn_number)) {
				return -1;
			}

			int i = (unsigned int)(random()) % curr_session->pinfo.tcp_conn_number;
			atc = curr_session->pinfo.tcp_conn[i];
			if(!atc->tcp_data_bound) {
				printf("%s: Uninitialized atc: i=%d, atc=0x%lx\n", __FUNCTION__, i, (long)atc);
				return -1;
			}

		} else if(!do_not_use_channel) {
			  /* Let's always do padding: */
			stun_init_channel_message(curr_session->chnum, buff, err, mandatory_channel_padding || use_tcp);
			memcpy(curr_session->out_buffer.buf + 4, buff, err);
		} else {
			stun_init_indication(STUN_METHOD_SEND, &(curr_session->out_buffer));
			stun_attr_add(&(curr_session->out_buffer), STUN_ATTRIBUTE_DATA, buff, err);
			stun_attr_add_addr(&(curr_session->out_buffer), STUN_ATTRIBUTE_XOR_PEER_ADDRESS, &(curr_session->pinfo.peer_addr));
			if(dont_fragment)
			    stun_attr_add(&(curr_session->out_buffer), STUN_ATTRIBUTE_DONT_FRAGMENT, NULL, 0);

			if(use_fingerprints)
			    stun_attr_add_fingerprint_str(curr_session->out_buffer.buf, (size_t*)&(curr_session->out_buffer.len));
		}

		if (curr_session->out_buffer.len > 0) {
			if (clnet_verbose && verbose_packets) {
				TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "before write ...\n");
			}

			int rc = send_buffer(&(elem->pinfo),&(elem->out_buffer),1,atc);

			++curr_session->wmsgnum;
			curr_session->to_send_timems += RTP_PACKET_INTERVAL;

			if(rc >= 0) {
				if (clnet_verbose && verbose_packets) {
					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "wrote %d bytes\n", (int) rc);
				}
				tot_send_messages++;
				tot_send_bytes += clmessage_length;
			} else {
				return -1;
			}
		}
	}

	if (err < 0) {
		err(1, "error reading");
	} else if(err = 0) {
		return;
	}

	return;
}

void p2p_input_handler(int fd, short ev, void *arg)
{

	UNUSED_ARG(fd);
	UNUSED_ARG(ev);
	UNUSED_ARG(arg);
}

/**
 * main method, start a client connection and usee that info to fill curr_session
 * Paramters:
 * 	remote_address: server_address
 * 	port: server port
 * 	ifname: local interface name
 * 	local_address: 本机地址
 * 	messagenumber:
 * 	i: the index of the session in session array **deprecated**
 */
static int start_client(const char *remote_address, int port,
		const unsigned char* ifname, const char *local_address)
	       	//int messagenumber,
	       	//int i)
{
 	// 创建一个session
  	app_ur_session* ss = create_new_ss();

 	app_ur_conn_info clnet_info_probe; /* for load balancing probe */
 	bzero(&clnet_info_probe, sizeof(clnet_info_probe));
 	clnet_info_probe.fd = -1;

 	/* clnet is a per connection info struct */
 	app_ur_conn_info *clnet_info=&(ss->pinfo);

 	uint16_t chnum = 0;

 	//***这个很关键***
	//allocate, bind request are in this function
// 	start_connection(port, remote_address, ifname, local_address, clnet_verbose,
//		       	&clnet_info_probe, clnet_info, &chnum,
//			NULL, &chnum_rtcp);
	printf("s2c start\n");
	s2c_start(port, remote_address, local_address, clnet_verbose, &clnet_info_probe,
			clnet_info);
	
	addr_debug_print(1, &clnet_info->relay_addr, "relay address: ");

 	if(clnet_info_probe.ssl) {
 		SSL_free(clnet_info_probe.ssl);
 		clnet_info_probe.fd = -1;
 	} else if(clnet_info_probe.fd != -1) {
	 	socket_closesocket(clnet_info_probe.fd);
	 	clnet_info_probe.fd = -1;
 	}

 	socket_set_nonblocking(clnet_info->fd);

 	struct event* ev = event_new(client_event_base,clnet_info->fd, 
			EV_READ|EV_PERSIST,p2p_input_handler, ss);
 	event_add(ev, NULL);

 	ss->state = UR_STATE_READY;
 	ss->input_ev = ev;
 	ss->recvmsgnum = -1;
 	ss->chnum = chnum;

	curr_session = ss;

	// refresh allocation && send create permission, channel bind request
	refresh_channel(ss, 0, 600);

	return 0;
}

//static int client_shutdown(app_ur_session *elem) {
//
//  if(!elem) return -1;
//
//  elem->state=UR_STATE_DONE;
//
//  elem->ctime=current_time;
//
//  remove_all_from_ss(elem);
//  
//  if (clnet_verbose)
//    TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"done, connection 0x%lx closed.\n",(long)elem);
//  
//  return 0;
//}
//
//static inline int client_timer_handler(app_ur_session* elem, int *done)
//{
//	if (elem) {
//		if (!turn_time_before(current_mstime, elem->refresh_time)) {
//			refresh_channel(elem, 0, 600);
//		}
//
//		if(hang_on && elem->completed)
//			return 0;
//
//		int max_num = 50;
//		int cur_num = 0;
//
//		/* 循环中修改elem to_send_time，控制发包 */
//		while (!turn_time_before(current_mstime, elem->to_send_timems)) {
//			printf("current time: %u, to_send_timems: %u", (unsigned int)current_mstime, elem->to_send_timems);
//		  	if(cur_num++>=max_num)
//		    	break;
//			if (elem->wmsgnum >= elem->tot_msgnum) {
//				if (!turn_time_before(current_mstime, elem->finished_time) ||
//				 (tot_recv_messages>=tot_messages)) {
//					/*
//					TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//					    "%s: elem=0x%x: 111.111: c=%d, t=%d, r=%d, w=%d\n",
//					    __FUNCTION__,(int)elem,elem->wait_cycles,
//					    elem->tot_msgnum,elem->rmsgnum,elem->wmsgnum);
//					*/
//					/*
//					 TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,"%s: 111.222: ly=%llu, ls=%llu, j=%llu\n",__FUNCTION__,
//					 (unsigned long long)elem->latency,
//					 (unsigned long long)elem->loss,
//					 (unsigned long long)elem->jitter);
//					*/
//					total_loss += elem->loss;
//					elem->loss=0;
//					total_latency += elem->latency;
//					elem->latency=0;
//					total_jitter += elem->jitter;
//					elem->jitter=0;
//					elem->completed = 1;
//					if (!hang_on) {
//						refresh_channel(elem,0,0);
//						client_shutdown(elem);
//						return 1;
//					} else {
//						return 0;
//					}
//				}
//			} else {
//				//发送数据包
//				*done += 1;
//				client_write(elem);
//				elem->finished_time = current_mstime + STOPPING_TIME*1000;
//			}
//		}
//	}
//
//	return 0;
//}
//
//static void timer_handler(evutil_socket_t fd, short event, void *arg)
//{
//	UNUSED_ARG(fd);
//	UNUSED_ARG(event);
//	UNUSED_ARG(arg);
//
//	__turn_getMSTime();
//
//	if(start_full_timer) {
//		int done = 0;
//
//		if (curr_session) {
//			int finished = client_timer_handler(curr_session, &done);
//			if (finished) {
//				curr_session = NULL;
//			}
//
//		}
//	}
//}
//

/**
 * start the client!
 * Parameters:
 * 	server_address: address of the server, in ip or hostname
 * 	port: server port
 * 	ifname: local interface name
 * 	local_address: local bind address
 * 	messagenumber:
 */
void start_myclient(const char *server_address, int port,
		const unsigned char *ifname, const char *local_address)
{
	//int mclient = 1, i = 0;
	curr_session = (app_ur_session *)malloc(
	    sizeof(app_ur_session) + sizeof(void *));

	memset(msg_buffer, 7, clmessage_length);

	client_event_base = turn_event_base_new();

	//usleep(SLEEP_INTERVAL);
	printf("start client\n");
	if (start_client(server_address, port, ifname, local_address) < 0) {
		err(1, "error starting client.");
	}

	/* refresh packets */
	struct event *ev_refresh = event_new(client_event_base, -1,
	    EV_TIMEOUT|EV_PERSIST, refresh_callback, NULL);
	struct timeval tv;
	tv.tv_sec = 15;
	tv.tv_usec = 0;
	evtimer_add(ev_refresh, &tv);


	struct event *ev_send = event_new(client_event_base, 1,
	    EV_READ|EV_PERSIST, message_input_callback, NULL);

	struct event *ev_stdin = (struct event *)malloc(event_get_struct_event_size());
	struct event *stdin_events[2];
	stdin_events[0] = ev_stdin;
	stdin_events[1] = ev_send;

	event_assign(ev_stdin, client_event_base, 1, EV_READ|EV_PERSIST, stdin_callback, (void *)stdin_events);
	event_add(ev_stdin, NULL);

	event_base_dispatch(client_event_base);

	event_free(ev_refresh);
	event_free(ev_stdin);

	// 下面还没看呢
//	struct event *ev = event_new(client_event_base, -1,
//			EV_TIMEOUT | EV_PERSIST, timer_handler, NULL);
//	struct timeval tv;
//	tv.tv_sec = 0;
//	tv.tv_usec = 1000;
//
//	evtimer_add(ev, &tv);
//	
//	__turn_getMSTime();	
//	uint32_t stime = current_time;
//	
//	/* TODO: what is this ? */
//	curr_session->to_send_timems = current_mstime + 1000 +
//	    ((uint32_t)random()) % 5000;
//
//	tot_messages = curr_session->tot_msgnum;
//
//	start_full_timer = 1;
//
//	while (1) {
//		run_events(client_event_base, 1);
//		int msz = (int)current_clients_number;
//		if (msz < 1) {
//			break;
//		}
//
//		// this message is printed once per second
//		if(show_statistics) {
//			TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//			    "%s: msz=%d, tot_send_msgs=%lu, tot_recv_msgs=%lu,"
//			    "tot_send_bytes ~ %llu, tot_recv_bytes ~ %llu\n",
//			    __FUNCTION__, msz, (unsigned long) tot_send_messages,
//			    (unsigned long) tot_recv_messages,
//			    (unsigned long long) tot_send_bytes,
//			    (unsigned long long) tot_recv_bytes);
//		       	show_statistics=0;
//		}
//	}
//
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//		      "%s: tot_send_msgs=%lu, tot_recv_msgs=%lu\n",
//		      __FUNCTION__,
//		      (unsigned long) tot_send_messages,
//		      (unsigned long) tot_recv_messages);
//
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//		      "%s: tot_send_bytes ~ %lu, tot_recv_bytes ~ %lu\n",
//		      __FUNCTION__,
//		      (unsigned long) tot_send_bytes,
//		      (unsigned long) tot_recv_bytes);
//
//	/* deallocated resources && print log messages */
//	if (client_event_base)
//		event_base_free(client_event_base);
//
//	if(tot_send_messages<tot_recv_messages)
//		tot_recv_messages=tot_send_messages;
//
//	total_loss = tot_send_messages-tot_recv_messages;
//
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total transmit time is %u\n",
//	    ((unsigned int)(current_time - stime)));
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Total lost packets %llu (%f%c),"
//	    "total send dropped %llu (%f%c)\n",
//	    (unsigned long long)total_loss,
//	    (((double)total_loss/(double)tot_send_messages)*100.00),'%',
//	    (unsigned long long)tot_send_dropped, 
//	    (((double)tot_send_dropped/(double)(tot_send_messages+tot_send_dropped))*100.00),'%');
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO,
//	    "Average round trip delay %f ms; min = %lu ms, max = %lu ms\n",
//	    ((double)total_latency/(double)((tot_recv_messages<1) ? 1 : tot_recv_messages)),
//	    (unsigned long)min_latency,
//	    (unsigned long)max_latency);
//	TURN_LOG_FUNC(TURN_LOG_LEVEL_INFO, "Average jitter %f ms; min = %lu ms, max = %lu ms\n",
//	    ((double)total_jitter/(double)tot_recv_messages),
//	    (unsigned long)min_jitter,
//	    (unsigned long)max_jitter);
//
	free(curr_session);
}
