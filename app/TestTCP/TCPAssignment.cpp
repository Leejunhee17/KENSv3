/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

#define	initial_buffer_size 51200

#define MSS 512


namespace E
{

enum STATE{
	CLOSED, LISTENED, ESTAB,				// States for server socket (server_sock)
	SYNSENT, SYNRCVD,						// States for connection socket of server (client_sock)
	FINSENT, FINRCVD
};

struct tcp_socket{
	int pid;
	UUID uuid;
	int fd;

	sockaddr_in *src_addr;
	sockaddr_in *dest_addr;

	int isBound;
	int state;
	int backlog;
	int is_accept;

	sockaddr *param2_ptr;
	tcp_socket *parent;

	uint32_t init_seq_num;
	uint32_t fin_seq_num;

	uint32_t seq_num; // about read
	uint32_t ack_num; // about write

	std::vector<struct unordered_seq *> cumulated_seq;

	std::vector<struct tcp_socket *> wait_packet;
	std::vector<struct tcp_socket *> child_list;

	void *write_buffer;
	uint16_t write_buffer_filled; /// Unit = Byte

	char *read_buffer;
	uint16_t read_buffer_remain;

	uint16_t peer_cwnd;

	UUID blocked_write_uuid;
	void *blocked_write_ptr;
	uint16_t blocked_write_size;

	UUID blocked_read_uuid;
	void *blocked_read_ptr;
	uint16_t blocked_read_size;

	uint16_t cwnd;
	std::vector<struct unacked_packet *> unacked_packet_list;
	int unacked_data;

	Time RTT;		// unit : ms
	Time RTTVAR;
	Time RTO;

	UUID timer_uuid;
	int is_Timer;

	int dup_ack_count;
	uint32_t last_ack_num;

	int is_slow_start;
	uint32_t acked_cwnd_data;
	uint32_t ssthresh;
};

struct unordered_seq{
	uint32_t seq_num;
	uint32_t data_size;
	void *ptr;
};

struct unacked_packet{
	uint32_t expect_ack_num;

	Time sendtime;	
};

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}


int TCPAssignment::find_socket_by_fd(int fd, int pid){
	for (std::vector<struct tcp_socket *>::size_type i = 0; i < sock_vec.size(); ++i){
		if((sock_vec[i]->fd == fd) && (sock_vec[i]->pid == pid)){
			return i;
		}
	}
	return -1;
}

int TCPAssignment::find_socket_by_addr(sockaddr_in *src, sockaddr_in *dest){
	for (std::vector<struct tcp_socket *>::size_type i = 0; i < sock_vec.size(); ++i){
		if((sock_vec[i]->state != LISTENED) && (sock_vec[i]->isBound == 1)){
			if(comp_sockaddr_in(sock_vec[i]->src_addr, src)){
				if(comp_sockaddr_in(sock_vec[i]->dest_addr, dest)){
					return i;
				}
			}
		}
	}
	return -1;
}

int TCPAssignment::comp_sockaddr_in(sockaddr_in *target1, sockaddr_in *target2){
	if(target1->sin_family == target2->sin_family){
		if(target1->sin_port == target2->sin_port){
			if(target1->sin_addr.s_addr == target2->sin_addr.s_addr){
				return 1;	
			}
			if(target1->sin_addr.s_addr == inet_addr("0.0.0.0")){
				return 1;
			}
			if(target2->sin_addr.s_addr == inet_addr("0.0.0.0")){
				return 1;
			}
		}
	}

	return 0;
}

sockaddr_in* TCPAssignment::make_sockaddr_in(uint32_t ip, uint16_t port){
	sockaddr_in *target;

	target = (sockaddr_in *) malloc(sizeof(sockaddr_in));
	target->sin_family = AF_INET;
	target->sin_addr.s_addr = ip;
	target->sin_port = port;

	return target;
}

int TCPAssignment::assign_random_port(){
	int rand_port, flag;
	flag = 1;
	while(flag) {
		flag = 0;
		rand_port = (rand() % 65536 + 1024) % 65536;
		for (std::vector<struct tcp_socket *>::size_type i = 0; i < sock_vec.size(); ++i){
			if(sock_vec[i]->isBound == 1) {
				if(sock_vec[i]->src_addr->sin_port == rand_port){
					printf("Random Port is Overlapped!!\n");
					flag = 1;
				}
			}
		}
	}
	return rand_port;
}

Packet* TCPAssignment::make_packet(Packet *packet_ptr, sockaddr_in *src, sockaddr_in *dest, uint8_t flags, uint8_t offset, uint16_t window_size){
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dest_ip;
	uint16_t dest_port;

	src_ip = src->sin_addr.s_addr;
	src_port = src->sin_port;
	dest_ip = dest->sin_addr.s_addr;
	dest_port = dest->sin_port;

	packet_ptr->writeData(14 + 12, &src_ip, 4);
	packet_ptr->writeData(14 + 16, &dest_ip, 4);
	packet_ptr->writeData(34, &src_port, 2);
	packet_ptr->writeData(34 + 2, &dest_port, 2);

	packet_ptr->writeData(34 + 12, &offset, 1);
	packet_ptr->writeData(34 + 13, &flags, 1);
	packet_ptr->writeData(34 + 14, &window_size, 2);

	uint16_t checksum;
	uint8_t tcp_header[20];

	packet_ptr->readData(34, tcp_header, 20);
	checksum = ~htons(E::NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_header, 20));
	packet_ptr->writeData(34 + 16, &checksum, 2);

	return packet_ptr;
}

void TCPAssignment::free_socket(tcp_socket *sock){
	free(sock->src_addr);
	free(sock->dest_addr);
	free(sock->param2_ptr);
	free(sock->parent);

	free(sock->read_buffer);
	free(sock->write_buffer);

	free(sock);
}

void TCPAssignment::erase_part_of_data(void *ptr, int original_size, int erase_size){
	void *temp;
	temp = calloc(initial_buffer_size, 1);
	memcpy(temp, (uint8_t *) ptr + erase_size, original_size - erase_size);

	memset(ptr, 0, initial_buffer_size);
	memcpy(ptr, temp, original_size - erase_size);
	free(temp);
}

int TCPAssignment::min(int x, int y){
	if(x < y){
		return x;
	}else{
		return y;
	}
}

int TCPAssignment::max(int x, int y){
	if(x > y){
		return x;
	}else{
		return y;
	}
}

int TCPAssignment::abs(int x){
	if(x > 0){
		return x;
	}else{
		return -x;
	}
}

tcp_socket* TCPAssignment::make_socket(int pid, UUID uuid, int fd){
	tcp_socket *sock;

	sock = (tcp_socket *) calloc(sizeof(struct tcp_socket), 1);

	sock->pid = pid;
	sock->uuid = uuid;
	sock->fd = fd;
	
	sock->isBound = 0;
	sock->state = CLOSED;
	sock->is_accept = 0;

	sock->init_seq_num = 0x98;

	sock->seq_num = 0;
	sock->ack_num = sock->init_seq_num;

	sock->write_buffer_filled = 0;
	sock->write_buffer = calloc(initial_buffer_size, 1);
	
	sock->read_buffer_remain = initial_buffer_size;
	sock->read_buffer = (char *) calloc(initial_buffer_size, 1);

	sock->peer_cwnd = 0;

	sock->blocked_write_size = 0;
	sock->blocked_read_size = 0;

	sock->cwnd = MSS;

	sock->is_Timer = 0;

	sock->unacked_data = 0;

	sock->RTT = 100 * 1000 * 1000;
	sock->RTTVAR = sock->RTT / 2;
	sock->RTO = sock->RTT + 4 * sock->RTTVAR; 

	sock->dup_ack_count = 0;
	sock->last_ack_num = 0;

	sock->is_slow_start = 1;
	sock->acked_cwnd_data = 0;
	sock->ssthresh = initial_buffer_size;

	return sock;
}

void TCPAssignment::make_packet_ack_seq(Packet *packet_ptr, sockaddr_in *src, sockaddr_in *dest, uint8_t flags, uint8_t offset, uint16_t window_size, uint32_t seq_num, uint32_t ack_num){
	uint32_t src_ip;
	uint16_t src_port;
	uint32_t dest_ip;
	uint16_t dest_port;

	src_ip = src->sin_addr.s_addr;
	src_port = src->sin_port;
	dest_ip = dest->sin_addr.s_addr;
	dest_port = dest->sin_port;

	packet_ptr->writeData(14 + 12, &src_ip, 4);
	packet_ptr->writeData(14 + 16, &dest_ip, 4);
	packet_ptr->writeData(34, &src_port, 2);
	packet_ptr->writeData(34 + 2, &dest_port, 2);

	packet_ptr->writeData(34 + 12, &offset, 1);
	packet_ptr->writeData(34 + 13, &flags, 1);
	packet_ptr->writeData(34 + 14, &window_size, 2);

	uint32_t n_seq_num, n_ack_num;
	n_seq_num = htonl(seq_num);
	n_ack_num = htonl(ack_num);

	packet_ptr->writeData(34 + 4, &n_seq_num, 4);
	packet_ptr->writeData(34 + 8, &n_ack_num, 4);

	uint16_t checksum;
	uint8_t tcp_header[20];

	packet_ptr->readData(34, tcp_header, 20);
	checksum = ~htons(E::NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_header, 20));
	packet_ptr->writeData(34 + 16, &checksum, 2);
}

void TCPAssignment::fill_checksum(Packet *packet_ptr, uint16_t data_size){
	uint32_t src_ip, dest_ip;
	uint16_t checksum = 0;
	uint8_t tcp_header[20 + data_size];

	packet_ptr->readData(14 + 12, &src_ip, 4);
	packet_ptr->readData(14 + 16, &dest_ip, 4);
	packet_ptr->writeData(34 + 16, &checksum, 2); // make checksum = 0
	packet_ptr->readData(34, tcp_header, 20 + data_size);

	checksum = ~htons(E::NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_header, 20 + data_size));
	packet_ptr->writeData(34 + 16, &checksum, 2);
}

void TCPAssignment::m_send_packet_with_data(tcp_socket *w_sock, uint32_t startpoint, uint32_t send_size, int is_retransmit){
	/////////////////////////// Update acknum and unacked_data //////////////////
	uint8_t flags = 0x10;
	uint8_t offset = 0x50;

	void *copy_ptr, *copied_data_ptr;
	uint16_t copy_size = 0;
	uint32_t calculated_ack_num = (w_sock->ack_num - w_sock->unacked_data) + startpoint; //also become seq_num of packet

	copy_ptr = (uint8_t *) w_sock->write_buffer + startpoint;
	copied_data_ptr = calloc(MSS, 1);

	while(send_size > 0){
		if(send_size >= MSS){
			copy_size = MSS;
		}else{
			copy_size = send_size;
		}

		Packet *myPacket = this->allocatePacket(54 + copy_size);
		uint16_t cwnd = htons(w_sock->read_buffer_remain);

		make_packet_ack_seq(myPacket, w_sock->src_addr, w_sock->dest_addr, flags, offset, cwnd, calculated_ack_num, w_sock->seq_num);
		calculated_ack_num += copy_size;

		memcpy(copied_data_ptr, copy_ptr, copy_size);
		myPacket->writeData(54, copied_data_ptr, copy_size);
		fill_checksum(myPacket, copy_size);

		if(is_retransmit == 0){
			unacked_packet *new_unack_packet;
			new_unack_packet = (unacked_packet *) calloc(sizeof(unacked_packet), 1);

			new_unack_packet->expect_ack_num = calculated_ack_num;
			w_sock->unacked_packet_list.push_back(new_unack_packet);
			new_unack_packet->sendtime = this->getHost()->getSystem()->getCurrentTime();
		}
		
		
		this->sendPacket("IPv4", myPacket);

		w_sock->unacked_data += copy_size;

		send_size -= copy_size;
		copy_ptr = (uint8_t *)copy_ptr + copy_size;
	}

	w_sock->ack_num = calculated_ack_num; //ack_num is last_sent_message
	free(copied_data_ptr);
}

void TCPAssignment::RTT_estimating(tcp_socket *sock, uint32_t ack_num, Time currenttime){
	while(sock->unacked_packet_list.size() > 0){
		if(sock->unacked_packet_list[0]->expect_ack_num < ack_num){
			//pass
		}else if(sock->unacked_packet_list[0]->expect_ack_num == ack_num){
			Time new_RTT;
			new_RTT = currenttime - sock->unacked_packet_list[0]->sendtime; //calculated RTT

			sock->RTTVAR = (3 * sock->RTTVAR / 4) + (abs(sock->RTT - new_RTT) / 4);
			sock->RTT = (7 * sock->RTT / 8) + (new_RTT / 8);
			sock->RTO = max(sock->RTT + 4 * sock->RTTVAR, 1000 * 1000 * 1000);
			break;
		}else{
			break;
		}
		free(sock->unacked_packet_list[0]);
		sock->unacked_packet_list.erase(sock->unacked_packet_list.begin()); // erase the packet
	}
}

void TCPAssignment::hexdump(void *ptr, int buflen) {
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;
	for (i=0; i<buflen; i+=16) {
		printf("%06x: ", i);
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%02x ", buf[i+j]);
			else
				printf("   ");
		printf(" ");
		for (j=0; j<16; j++) 
			if (i+j < buflen)
				printf("%c", isprint(buf[i+j]) ? buf[i+j] : '.');
		printf("\n");
	}
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int sock_index;
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		int fd;
		tcp_socket *sock;

		fd = this->createFileDescriptor(pid);

		sock = make_socket(pid, syscallUUID, fd);
		sock_vec.push_back(sock);

		//printf("sock added, sock vec lenght is %d\n", sock_vec.size());
		this->returnSystemCall(syscallUUID, fd);
		break;
	case CLOSE:
	{
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		//printf("<CLOSED> CLOSED CALLED\n");
		sock_index = find_socket_by_fd(param.param1_int, pid);

		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		tcp_socket *sock;
		sock = sock_vec[sock_index];

		if(sock->blocked_read_size > 0){
			this->returnSystemCall(sock->blocked_read_uuid, -1);
		}

		if(sock->is_Timer == 1){
			this->cancelTimer(sock->timer_uuid);
			//printf("timer canceled with uuid %lu\n", sock->timer_uuid);
		}

		if((sock->state == LISTENED) || (sock->isBound == 0) || (sock->state == CLOSED)){ //If litening socket or not bound or already closed
			sock->state = CLOSED;	
			sock_vec.erase(sock_vec.begin() + sock_index);

			free(sock->write_buffer);
			free(sock->read_buffer);

			this->removeFileDescriptor(pid, param.param1_int);
			this->returnSystemCall(syscallUUID, 0);
			//printf("<CLOSED>sock vec length is %d sock index is %d, fd was %d and CLOSED FINISHED Earlier\n", sock_vec.size(), sock_index, param.param1_int);
			break;
		}

		uint8_t flags = 0x01;
		uint8_t offset = 0x50;
		uint16_t cwnd = htons(51200);

		Packet *finPacket = this->allocatePacket(54);

		uint32_t n_seq_num, n_ack_num;
		n_seq_num = htonl(sock->ack_num - sock->unacked_data + sock->write_buffer_filled);
		n_ack_num = htonl(0);

		sock->fin_seq_num = sock->ack_num - sock->unacked_data + sock->write_buffer_filled;
		
		finPacket->writeData(34 + 4, &n_seq_num, 4);
		finPacket->writeData(34 + 8, &n_ack_num, 4);

		finPacket = make_packet(finPacket, sock->src_addr, sock->dest_addr, flags, offset, cwnd);

		this->sendPacket("IPv4", finPacket);

		if(sock->state == FINRCVD){
			sock->state = CLOSED;
			free(sock_vec[sock_index]);
			sock_vec.erase(sock_vec.begin() + sock_index);

			this->removeFileDescriptor(pid, param.param1_int);
			this->returnSystemCall(syscallUUID, 0);
		}else{
			sock->state = FINSENT;
		}
		//printf("<CLOSED> CLOSED FINISHED\n");

		// free(sock_vec[sock_index]);
		// sock_vec.erase(sock_vec.begin() + sock_index);

		//this->removeFileDescriptor(pid, param.param1_int);
		//this->returnSystemCall(syscallUUID, 0);
		break;
	}
	case READ:
	{
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		// param.param1_int = fd
		// param.param2_ptr = buffer pointer
		// param.param3_int = given size for copying data

		//printf("<READ> READ CALLED\n");
		sock_index = find_socket_by_fd(param.param1_int, pid);

		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		tcp_socket *read_sock;
		read_sock = sock_vec[sock_index];

		if(read_sock->state != ESTAB){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		uint32_t read_buffer_filled = initial_buffer_size - read_sock->read_buffer_remain;
		if(read_buffer_filled == 0){
			//printf("<READ> READ BLOCKED\n");
			read_sock->blocked_read_uuid = syscallUUID;
			read_sock->blocked_read_ptr = param.param2_ptr;
			read_sock->blocked_read_size = param.param3_int;
		}else{
			uint16_t read_size = min(param.param3_int, read_buffer_filled);

			memcpy(param.param2_ptr, read_sock->read_buffer, read_size);
			erase_part_of_data(read_sock->read_buffer, read_buffer_filled, read_size);

			read_sock->read_buffer_remain += read_size;

			this->returnSystemCall(syscallUUID, read_size);
		}
		break;
	}
	case WRITE:
	{	
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		// param.param1_int = fd
		// param.param2_ptr = given data
		// param.param3_int = give datat size
		//printf("<WRITE> WRITE CALLED by size of %d byte\n", param.param3_int);
		sock_index = find_socket_by_fd(param.param1_int, pid);
		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		tcp_socket *write_sock;
		write_sock = sock_vec[sock_index];
		if(write_sock->state != ESTAB){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}
		
		uint32_t empty_field = write_sock->peer_cwnd - write_sock->write_buffer_filled;
		if(empty_field == 0){ //block write
			//printf("<WRITE> No empty space in buffer, write blocked\n");
			write_sock->blocked_write_uuid = syscallUUID;
			write_sock->blocked_write_ptr = param.param2_ptr;
			write_sock->blocked_write_size = param.param3_int;
		}else{
			////////////// Write data in data buffer /////////////////
			uint16_t write_size = min(param.param3_int, empty_field);
			memcpy((uint8_t *)write_sock->write_buffer + write_sock->write_buffer_filled, param.param2_ptr, write_size);
			write_sock->write_buffer_filled += write_size;
			this->returnSystemCall(syscallUUID, write_size);
			//printf("%d byte data successfully written!\n", write_size);

			////////////// Send data if cwnd allow ///////////////////
			uint16_t send_size = min(write_size, write_sock->cwnd - write_sock->unacked_data);
			if(send_size > 0){
				m_send_packet_with_data(write_sock, write_sock->unacked_data, send_size, 0); 
				if(write_sock->is_Timer == 0){
					write_sock->timer_uuid = this->addTimer(write_sock, write_sock->RTO);
					//printf("Timer is added for %lu sec, uuid %lu\n", write_sock->RTO, write_sock->timer_uuid);
					write_sock->is_Timer = 1;
				}
			}

			
		}
		break;
	}
	case CONNECT:
	{
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		//printf("<CONNECT> CONNECT CALLED\n");
		struct sockaddr_in *server_addr;
		server_addr = static_cast<struct sockaddr_in *>(param.param2_ptr);

		sock_index = find_socket_by_fd(param.param1_int, pid);
		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		uint32_t src_ip;
		uint16_t src_port;

		tcp_socket *client;
		client = sock_vec[sock_index];
		if(client->isBound == 1){
			// printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Explicit Bind\n");
			src_ip = client->src_addr->sin_addr.s_addr;
			src_port = client->src_addr->sin_port;
		} else {
			// printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@Implicit Bind\n");
			this->getHost()->getIPAddr((uint8_t *) &src_ip, 0);
			src_port = (rand() % 65536 + 1024) % 65536;
			sockaddr_in *src_addr;
			src_addr = make_sockaddr_in(src_ip, src_port);
			client->src_addr = src_addr;
			client->isBound = 1;
		}

		Packet *synPacket = this->allocatePacket(54);

		sockaddr_in *src, *dest;
		src = make_sockaddr_in(src_ip, src_port);
		dest = make_sockaddr_in(server_addr->sin_addr.s_addr, server_addr->sin_port);
		uint8_t flags = 0x02;
		uint8_t offset = 0x50;
		uint16_t cwnd = htons(client->read_buffer_remain);

		uint32_t n_seq_num = htonl(client->ack_num);
		client->ack_num += 1;
		synPacket->writeData(34 + 4, &n_seq_num, 4);

		synPacket = make_packet(synPacket, src, dest, flags, offset, cwnd);

		client->state = SYNSENT;
		client->dest_addr = server_addr;
		client->uuid = syscallUUID;


		this->sendPacket("IPv4", synPacket);
		//printf("<CONNECT> CONNECT FINISHED\n");
		break;
	}
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		//printf("<LISTEN> LISTEN CALLED\n");
		int sock_index;
		sock_index = find_socket_by_fd(param.param1_int, pid);
		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
		}else{
			sock_vec[sock_index]->state = LISTENED;
			sock_vec[sock_index]->backlog = param.param2_int;
			sock_vec[sock_index]->uuid = syscallUUID;

			this->returnSystemCall(syscallUUID, 0);
			//printf("<LISTEN> LISTEN complete with backlog %d\n", sock_vec[sock_index]->backlog);
		}
		//printf("<LISTEN> LISTEN FINISHED\n");
		break;
	case ACCEPT:
	{		
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		//printf("<ACCEPT> ACCEPT CALLED\n");
		sock_index = find_socket_by_fd(param.param1_int, pid);

		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		tcp_socket *server_sock;
		tcp_socket* child;

		server_sock = sock_vec[sock_index];

		if(server_sock->state != LISTENED){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		
		if(server_sock->child_list.size() > 0){
			// accept the packet already came
			child = server_sock->child_list[0];
			server_sock->child_list.erase(server_sock->child_list.begin());
			child->fd = this->createFileDescriptor(pid);

			child->is_accept = 1;

			memcpy(param.param2_ptr, child->dest_addr, sizeof(struct sockaddr_in));
			this->returnSystemCall(syscallUUID, child->fd);
		}else{
			// wait for the packet
			//printf("<ACCEPT> Wait for packet\n");

			child = make_socket(pid, syscallUUID, this->createFileDescriptor(pid));
			child->is_accept = 1;

			child->param2_ptr = (sockaddr *) param.param2_ptr;
			child->parent = server_sock;

			child->peer_cwnd = 0;

			sock_vec.push_back(child);
			server_sock->wait_packet.push_back(child);
		}
		
		//printf("<ACCEPT> ACCEPT FINISHED\n");
		break;
	}
	case BIND:
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		//printf("<BIND> BIND CALLED\n");
		int flag; 			// flag for double bind
		sockaddr_in *addr;

		flag = 0;
		addr = (struct sockaddr_in *) malloc(param.param3_int);
		memcpy(addr, param.param2_ptr, param.param3_int); // copy the addr

		sock_index = find_socket_by_fd(param.param1_int, pid);
		if(sock_index == -1){ // There is no socket
			flag = 1; 
		}
		if(sock_vec[sock_index]->isBound == 1){ // The socket is already bounded
			flag = 1;
		}

		for(std::vector<struct tcp_socket *>::size_type i = 0; i<sock_vec.size(); ++i){
			if(sock_vec[i]->isBound == 1){
				if(addr->sin_port == sock_vec[i]->src_addr->sin_port){
					if (addr->sin_addr.s_addr == inet_addr("0.0.0.0")){
						flag = 1;
						break;
					}else if (sock_vec[i]->src_addr->sin_addr.s_addr == inet_addr("0.0.0.0")){
						flag = 1;
						break;
					}else if (addr->sin_addr.s_addr == sock_vec[i]->src_addr->sin_addr.s_addr){
						flag = 1;
						break;
					}
				}
			}
		}

		if(flag == 1){
			this->returnSystemCall(syscallUUID, -1);
		}else{
			sock_vec[sock_index]->uuid = syscallUUID;
			sock_vec[sock_index]->src_addr = addr;
			sock_vec[sock_index]->isBound = 1;
			//state is still closed
			this->returnSystemCall(syscallUUID, 0);
		}
		// printf("<BIND> BIND FINISHEDED\n");
		break;
	case GETSOCKNAME:
		//this->syscall_getsockname(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		{
			socklen_t *addrlen = static_cast<socklen_t*>(param.param3_ptr);

			sock_index = find_socket_by_fd(param.param1_int, pid);

			if(sock_index == -1){ // There is no such socket
				this->returnSystemCall(syscallUUID, -1);
			}else{
				memcpy(param.param2_ptr, sock_vec[sock_index]->src_addr, *addrlen);
				this->returnSystemCall(syscallUUID, 0);
			}
			break;
		}
	case GETPEERNAME:
	{
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//static_cast<struct sockaddr *>(param.param2_ptr),
		//static_cast<socklen_t*>(param.param3_ptr));
		socklen_t *addrlen = static_cast<socklen_t*>(param.param3_ptr);

		sock_index = find_socket_by_fd(param.param1_int, pid);

		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
		}else{
			memcpy(param.param2_ptr, sock_vec[sock_index]->dest_addr, *addrlen);
			this->returnSystemCall(syscallUUID, 0);
		}
		break;
	}
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	// Recieved Packet Analysis
	uint32_t src_ip, dest_ip;
	packet->readData(14 + 12, &src_ip, 4);
	packet->readData(14 + 16, &dest_ip, 4);

	uint16_t src_port, dest_port;
	uint32_t seq_num, ack_num;
	uint8_t flags, my_flags;
	uint16_t peer_cwnd;
	uint16_t checksum, my_checksum;
	uint8_t tcp_header[20];
	uint16_t data_size;

	sockaddr_in *client_addr;
	sockaddr_in *server_addr;

	// Check Recieved Packet Checksum
	packet->readData(34 + 16, &checksum, 2);

	data_size = packet->getSize() - 54;
	//printf("<PACKET> data_size: %hu\n", data_size);

	packet->readData(34, &src_port, 2);
	packet->readData(34 + 2, &dest_port, 2);
	packet->readData(34 + 4, &seq_num, 4);
	packet->readData(34 + 8, &ack_num, 4);
	packet->readData(34 + 13, &flags, 1);
	packet->readData(34 + 14, &peer_cwnd, 2);
	peer_cwnd = ntohs(peer_cwnd);

	Packet *myPacket = this->clonePacket(packet);
	client_addr = make_sockaddr_in(src_ip, src_port);
	server_addr = make_sockaddr_in(dest_ip, dest_port);
	this->freePacket(packet);

	// Make  myPacket
	myPacket->writeData(14 + 12, &dest_ip, 4);
	myPacket->writeData(14 + 16, &src_ip, 4);
	myPacket->writeData(34, &dest_port, 2);
	myPacket->writeData(34 + 2, &src_port, 2);
	my_checksum = 0;
	myPacket->writeData(34 + 16, &my_checksum, 2); // make checksum = 0

	my_flags = flags & 0x13; //Copy the flags
	flags = flags & 0x13; // mask 00010011 AKC-0-0-SYN-FIN

	int sock_index;
	sock_index = find_socket_by_addr(server_addr, client_addr);

	if(flags == 0x02){ // Only SYN
		for (std::vector<struct tcp_socket *>::size_type i = 0; i < sock_vec.size(); ++i){
			if(sock_vec[i]->state == LISTENED){
				//printf("maybe compare problem %d\n", comp_sockaddr_in(sock_vec[i]->src_addr, client_addr));
				if(comp_sockaddr_in(sock_vec[i]->src_addr, server_addr)){
					tcp_socket *server_sock;
					tcp_socket *child;

					server_sock = sock_vec[i];
					if(server_sock->backlog > 0){
						
						if(sock_index != -1){
							printf("There is already a socket with same 4-tuple");
						}else{
							server_sock->backlog--;
							if(server_sock->wait_packet.size() > 0){ // There is an accept, use that socket
								child = server_sock->wait_packet[0];
								server_sock->wait_packet.erase(server_sock->wait_packet.begin());

								memcpy(child->param2_ptr, client_addr, sizeof(struct sockaddr_in));
							}else{
								int fd = this->createFileDescriptor(server_sock->pid);
								child = make_socket(server_sock->pid, server_sock->uuid, fd);

								sock_vec.push_back(child);
							}

							child->src_addr = server_addr;
							child->dest_addr = client_addr;
							child->peer_cwnd = peer_cwnd;

							child->isBound = 1;
							child->state = SYNRCVD;
							child->backlog = 0;

							child->parent = server_sock;

							child->seq_num = ntohl(seq_num); //1000
							child->ack_num += 1; // 10->11

							uint32_t n_seq_num, n_ack_num;

							n_seq_num = htonl(child->init_seq_num);
							n_ack_num = htonl(ntohl(seq_num) + 1); // 1001
							myPacket->writeData(34 + 4, &n_seq_num, 4);
							myPacket->writeData(34 + 8, &n_ack_num, 4);

							my_flags = my_flags | 0x12; // SYN bit = 1 ACK bit = 1
							myPacket->writeData(34 + 13, &my_flags, 1);

							my_checksum = 0;
							myPacket->writeData(34 + 16, &my_checksum, 2); // make checksum = 0

							myPacket->readData(34, tcp_header, 20);
							my_checksum = ~htons(NetworkUtil::tcp_sum(dest_ip, src_ip, tcp_header, 20));
							myPacket->writeData(34 + 16, &my_checksum, 2);

							//printf("Message send at packetarrived->syn=1\n");
							this->sendPacket("IPv4", myPacket);
						}
					}
					break;
				}
				
			}
		}
	}
	else if(flags == 0x12){ // SYN & ACK
		//printf("SYNACK\n");

		if(sock_index == -1){
			printf("@@@@@@@@@@@@@@@@@@@@@@@@ Drop it!!!\n");
		}
		tcp_socket *sock;
		sock = sock_vec[sock_index];
		if(sock->state != SYNSENT){
			this->returnSystemCall(sock->uuid, -1);
		}

		// Response Packet
		
		if(ntohl(ack_num) != sock->init_seq_num + 1){
			printf("the acknum for synack is not proper, drop it!\n");
		}else{

			sock->peer_cwnd = peer_cwnd;
			//printf("peer_cwnd was %u byte(normal), %x (hex original), %u (htons), %x (hex htons), %u (htonl)\n", peer_cwnd, peer_cwnd, htons(peer_cwnd), htons(peer_cwnd), htonl(peer_cwnd));
			// printf("peer_cwnd is %u byte\n", peer_cwnd);
			sock->init_seq_num = 0; //reset it, so after packet will not be considered as a ack for syn

			sock->seq_num = ntohl(seq_num) + 1;
			sock->ack_num = ntohl(ack_num);

			uint32_t n_seq_num, n_ack_num;

			n_seq_num = ack_num; // htonl(sock->ack_num)
			n_ack_num = htonl(ntohl(seq_num) + 1);

			myPacket->writeData(34 + 4, &n_seq_num, 4);
			myPacket->writeData(34 + 8, &n_ack_num, 4);


			my_flags = my_flags & 0xFD;
			myPacket->writeData(34 + 13, &my_flags, 1);
			checksum = 0;
			myPacket->writeData(34 + 16, &checksum, 2);
			myPacket->readData(34, tcp_header, 20);
			checksum = ~htons(E::NetworkUtil::tcp_sum(dest_ip, src_ip, tcp_header, 20));
			myPacket->writeData(34 + 16, &checksum, 2);

			this->sendPacket("IPv4", myPacket);

			sock->state = ESTAB;
			//printf("@@@@@@@@@@@@@@@@@@@@@@@@ Unblocked\n");
			this->returnSystemCall(sock->uuid, 0);
		}
	}
	else if(flags == 0x10){ // only ACK
		//printf("ONLY ACK\n");
		int child_index;
		tcp_socket *child;

		child_index = sock_index;
		//printf("child index is %d\n", child_index);
		if(child_index != -1){
			child = sock_vec[child_index];
			child->peer_cwnd = peer_cwnd;
			
			if(ntohl(ack_num) == child->fin_seq_num + 1){ //If ACK is about FIN
				//printf("<PacketArrived>Send fin is acked\n");
				// child->unacked_data -= 1;
				// child->fin_seq_num = 0;
				
				// child->ack_num += 1;
				// if(child->state == FIN_WAIT_1){
				// 	child->state = FIN_WAIT_2;
				// }else if(child->state == LAST_ACK){
				// 	child->state = CLOSED;
				// 	this->removeFileDescriptor(child->pid, child->fd);
				// 	this->returnSystemCall(child->uuid, 0);
					
				// 	free(sock_vec[child_index]);
				// 	sock_vec.erase(sock_vec.begin() + child_index);
				// }else{
				// 	printf("state must be in two\n");
				// }
			}
			else if(ntohl(ack_num) == child->init_seq_num + 1){
				//The last packet for handshaking
				//printf("<PacketArrived>ACK for handshake\n");
				child->init_seq_num = 0;
				child->parent->backlog++;

				child->seq_num = ntohl(seq_num);

				child->state = ESTAB;

				if(child->is_accept == 1){
					this->returnSystemCall(child->uuid, child->fd);
				}else{
					child->parent->child_list.push_back(child);
				}
			}
			else{
				//normal sign
				tcp_socket *write_sock;
				write_sock = child;

				seq_num = ntohl(seq_num);
				ack_num = ntohl(ack_num);

				uint32_t unacked_data_response = write_sock->ack_num - ack_num;
				uint32_t acked_size = write_sock->unacked_data - unacked_data_response;


				if(acked_size > 0){
					write_sock->dup_ack_count = 1;
					write_sock->last_ack_num = ack_num;
					if(write_sock->is_Timer == 1){
						this->cancelTimer(write_sock->timer_uuid);
						//printf("timer canceled with uuid %lu\n", write_sock->timer_uuid);
					}
					write_sock->is_Timer = 0;
					RTT_estimating(write_sock, ack_num, this->getHost()->getSystem()->getCurrentTime());

					//////////// Erase buffer and take pending write ////////////////
					erase_part_of_data(write_sock->write_buffer, write_sock->write_buffer_filled, acked_size);
					write_sock->write_buffer_filled -= acked_size;

					uint32_t empty_field = write_sock->peer_cwnd - write_sock->write_buffer_filled;
					// printf("peer cwnd is %u, buffer_filled is %u, empty field is %u\n", write_sock->peer_cwnd, write_sock->write_buffer_filled, empty_field);
					if(peer_cwnd > write_sock->write_buffer_filled){
						if(write_sock->blocked_write_size > 0){ // If there is a pending wrtie
							uint32_t write_size = min(write_sock->blocked_write_size, empty_field);

							memcpy((uint8_t *)write_sock->write_buffer + write_sock->write_buffer_filled, write_sock->blocked_write_ptr, write_size);
							write_sock->write_buffer_filled += write_size;

							this->returnSystemCall(write_sock->blocked_write_uuid, write_size);
							write_sock->blocked_write_size = 0;
						}
					}
		
					
					if(ack_num > write_sock->ack_num){
						write_sock->ack_num = ack_num; 	// update with the bigger ack num
						write_sock->unacked_data = 0; 	// the already unacked_data will be deleted
					}else{
						write_sock->unacked_data = unacked_data_response;
					}

					/////////////////////////// UPDATE CWND .////////////////////////
					write_sock->acked_cwnd_data += acked_size;
					/////////// AIMD
					// if(write_sock->acked_cwnd_data > write_sock->cwnd){
					// 	write_sock->cwnd = min(write_sock->cwnd + MSS, write_sock->peer_cwnd);
					// 	write_sock->acked_cwnd_data = 0;
					// }

					/////////// MIMD
					// if(write_sock->acked_cwnd_data > write_sock->cwnd){
					// 	write_sock->cwnd = min(write_sock->cwnd * 2, write_sock->peer_cwnd);
					// 	write_sock->acked_cwnd_data = 0;
					// }

					/////////// AIMD + slow start
					if(write_sock->is_slow_start == 1){
						write_sock->cwnd = min(write_sock->cwnd + MSS, write_sock->peer_cwnd);
						if(write_sock->cwnd > write_sock->ssthresh){
							write_sock->is_slow_start = 0;
						}
					}else{
						if(write_sock->acked_cwnd_data > write_sock->cwnd){
							write_sock->cwnd = min(write_sock->cwnd + MSS, write_sock->peer_cwnd);
							write_sock->acked_cwnd_data = 0;
						}
					}

					// write_sock->cwnd = min(write_sock->cwnd * 2, write_sock->peer_cwnd);

					//////////////// Send data ///////////////////
					uint32_t send_size = min(write_sock->write_buffer_filled, write_sock->cwnd) - write_sock->unacked_data;
					if(send_size > 0){ 
						//uint32_t startpoint = 0;
						m_send_packet_with_data(write_sock, write_sock->unacked_data, send_size, 0);
						if(write_sock->is_Timer == 0){
							write_sock->timer_uuid = this->addTimer(write_sock, write_sock->RTO);
							//printf("Timer is added for %lu sec, uuid %lu\n", write_sock->RTO, write_sock->timer_uuid);
							write_sock->is_Timer = 1;
						}
					}

				}else{
					if((ack_num == write_sock->last_ack_num) && (write_sock->unacked_data > 0)){
						
						write_sock->dup_ack_count += 1;
						//printf("dup_ack_count is %d\n", write_sock->dup_ack_count);

						if(write_sock->dup_ack_count == 4){
							//printf("welcome to fast retransmission\n");

							write_sock->dup_ack_count = 1;
							write_sock->cwnd = max((write_sock->cwnd / MSS) / 2, 1) * MSS;
							write_sock->acked_cwnd_data = 0;
							write_sock->is_slow_start = 0;
							//printf("cwnd decrease to %u\n", write_sock->cwnd);

							uint32_t startpoint = 0;
							write_sock->ack_num = write_sock->ack_num - write_sock->unacked_data; //set to the send_base   
							write_sock->unacked_data = 0;
							m_send_packet_with_data(write_sock, startpoint, write_sock->cwnd, 1);
							//printf("new ack num is %u\n", call_sock->ack_num);
							//call_sock->ack_num -= call_sock->cwnd;

							if(write_sock->is_Timer == 1){
								this->cancelTimer(write_sock->timer_uuid);
								//printf("timer canceled with uuid %lu\n", write_sock->timer_uuid);
							}
							write_sock->timer_uuid = this->addTimer(write_sock, write_sock->RTO);

						}
					}
					write_sock->last_ack_num = ack_num;
				}
				write_sock->last_ack_num = ack_num;
				///////////////////////////////////////////////////////////////////////////////////////////////

				if(data_size > 0){
					void *read_ptr;
					uint32_t read_buffer_filled;

					read_ptr = calloc(data_size, 1);
					myPacket->readData(54, read_ptr, data_size);
					//hexdump(read_ptr, data_size);
					if(seq_num == child->seq_num){
						// proper data
						read_buffer_filled = initial_buffer_size - child->read_buffer_remain;
						memcpy((uint8_t *) child->read_buffer + read_buffer_filled, read_ptr, data_size);
						//hexdump(child->read_buffer, read_buffer_filled);

						child->read_buffer_remain -= data_size;
						child->seq_num += data_size;
						read_buffer_filled += data_size;

						unordered_seq *target;
						while(child->cumulated_seq.size() > 0){
							target = child->cumulated_seq[0];
							if(target->seq_num == child->seq_num){
								memcpy((uint8_t *) child->read_buffer + read_buffer_filled, target->ptr, target->data_size);

								child->read_buffer_remain -= target->data_size;
								child->seq_num += target->data_size;
								read_buffer_filled += target->data_size;

								child->cumulated_seq.erase(child->cumulated_seq.begin());
							}else{
								break;
							}
						}

					}else if(seq_num > child->seq_num){ // seq_num > child->seq_num
						// unordered seq
						unordered_seq *new_seq;
						new_seq = (unordered_seq *) calloc(sizeof(struct unordered_seq), 1);
						
						new_seq->seq_num = seq_num;
						new_seq->data_size = data_size;
						new_seq->ptr = read_ptr;

						for(std::vector<struct unordered_seq *>::size_type i = 0; i < child->cumulated_seq.size(); ++i){
							if(child->cumulated_seq[i]->seq_num > new_seq->seq_num){
								child->cumulated_seq.insert(child->cumulated_seq.begin() + i, new_seq);
								break;
							}
						}
					} //else seq_num < child->seq_num : already known packet

					uint8_t flags = 0x10;
					uint8_t offset = 0x50;
					Packet *ackPacket = this->allocatePacket(54);
					uint16_t cwnd = htons(child->read_buffer_remain);

					make_packet_ack_seq(ackPacket, child->src_addr, child->dest_addr, flags, offset, cwnd, child->ack_num, child->seq_num);
					this->sendPacket("IPv4", ackPacket);

					if(child->blocked_read_size > 0){
						//printf("there was pending read\n");
						read_buffer_filled = initial_buffer_size - child->read_buffer_remain;

						uint16_t read_size = min(child->blocked_read_size, read_buffer_filled);

						memcpy(child->blocked_read_ptr, child->read_buffer, read_size);
						erase_part_of_data(child->read_buffer, read_buffer_filled, read_size);

						child->read_buffer_remain += read_size;

						this->returnSystemCall(child->blocked_read_uuid, read_size);
						child->blocked_read_size = 0;
					}
				}
			}
		} //if child_index = -1, there is no socket for packet
	}
	else if(flags == 0x01){ // FIN
		//printf("FIN\n");

		int child_index;
		tcp_socket *child;

		child_index = sock_index;
	
		if(child_index != -1){
			//printf("I found the socket\n");
			child = sock_vec[child_index];
			child->peer_cwnd = peer_cwnd;

			my_flags = (my_flags & 0xFE) | 0x10; //activate ACK
			myPacket->writeData(34 + 13, &my_flags, 1);

			child->seq_num = ntohl(seq_num);

			uint32_t n_seq_num, n_ack_num;
			//n_seq_num = ack_num; // htonl(child->ack_num);
			n_seq_num = htonl(child->ack_num);
			n_ack_num = htonl(ntohl(seq_num) + 1); //need to plus data_size

			myPacket->writeData(34 + 4, &n_seq_num, 4);
			myPacket->writeData(34 + 8, &n_ack_num, 4);

			checksum = 0;
			myPacket->writeData(34 + 16, &checksum, 2);
			myPacket->readData(34, tcp_header, 20);
			checksum = ~htons(E::NetworkUtil::tcp_sum(dest_ip, src_ip, tcp_header, 20));
			myPacket->writeData(34 + 16, &checksum, 2);
			//printf("<PacketArrived>Send ACK of FIN\n");
			this->sendPacket("IPv4", myPacket);

			if(child->state == FINSENT){
				child->state = CLOSED;
				//printf("<CLOSED> CLOSED RETURN\n");
				this->removeFileDescriptor(child->pid, child->fd);
				this->returnSystemCall(child->uuid, 0);

				free(sock_vec[child_index]);
				sock_vec.erase(sock_vec.begin() + child_index);
			}else{
				child->state = FINRCVD;
			}

		}

		
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	tcp_socket *call_sock;
	call_sock = (tcp_socket *) payload;

	//printf("TIMER EXPIRED at %lu!!!!!!!!!!!!!!\n", this->getHost()->getSystem()->getCurrentTime());

	if(call_sock->is_Timer == 1){
		call_sock->ssthresh = ((call_sock->cwnd / MSS) / 2) * MSS;
		call_sock->cwnd = MSS;
		call_sock->acked_cwnd_data = 0;
		call_sock->is_slow_start = 1;

		uint32_t startpoint = 0;
		//printf("original ack num is %u and unacked data is %u\n", call_sock->ack_num, call_sock->unacked_data);
		call_sock->ack_num = call_sock->ack_num - call_sock->unacked_data; //set to the send_base
		call_sock->unacked_data = 0;
		call_sock->dup_ack_count = 0;
		m_send_packet_with_data(call_sock, startpoint, call_sock->cwnd, 1);

		call_sock->timer_uuid = this->addTimer(call_sock, call_sock->RTO);
		//printf("Timer is added for %lu sec, uuid %lu\n", call_sock->RTO, call_sock->timer_uuid);
	}
}

}
