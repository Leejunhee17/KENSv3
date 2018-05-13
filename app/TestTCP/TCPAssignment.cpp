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

#define	initial_write_buffer_size 51200
#define initial_read_buffer_size 51200




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

	uint32_t init_seq_num;
	uint32_t fin_seq_num;

	uint32_t seq_num; // about read
	uint32_t ack_num; // about write

	std::vector<struct unordered_seq *> cumulated_seq;

	sockaddr *param2_ptr;
	tcp_socket *parent;

	std::vector<struct tcp_socket *> wait_packet;
	std::vector<struct tcp_socket *> child_list;

	void *write_buffer;
	void *read_buffer;

	uint32_t write_buffer_remain; /// Unit = Byte
	uint32_t read_buffer_remain;



	int peer_cwnd;

	std::vector<struct blocked_read *> read_pending;
	std::vector<struct blocked_write *> write_pending;
};

struct blocked_read{
	UUID uuid;
	void *buf;
	size_t len;
};

struct blocked_write{
	UUID uuid;
	void *ptr;
	size_t len;
};

struct unordered_seq{
	int seq_num;
	int data_size;
	void *ptr;
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
	printf("@@@@@@@@@@@@@@@@@@@@@ Assigned Random Port: %d\n", rand_port);
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
	free(sock);
}

void TCPAssignment::erase_part_of_data(void *ptr, int original_size, int erase_size){
	void *temp;
	temp = calloc(original_size - erase_size, 1);
	memcpy(temp, ptr, original_size - erase_size);
	free(ptr);
	ptr = temp;
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

tcp_socket* make_socket(int pid, UUID uuid, int fd){
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

	sock->write_buffer_remain = initial_write_buffer_size;
	sock->write_buffer = calloc(initial_write_buffer_size, 1);
	sock->read_buffer_remain = initial_read_buffer_size;
	sock->read_buffer = calloc(initial_read_buffer_size, 1);

	sock->peer_cwnd = 0;
	return sock;
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	int sock_index;
	int data_amount;
	switch(param.syscallNumber)
	{
	case SOCKET:
		//this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		int fd;
		tcp_socket *sock;

		fd = this->createFileDescriptor(pid);

		sock = make_socket(pid, syscallUUID, fd);
		sock_vec.push_back(sock);

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

		for (std::vector<struct blocked_read *>::size_type i = 0; i < sock->read_pending.size(); ++i){ 
			this->returnSystemCall(sock->read_pending[i]->uuid, -1); //return -1 for every pending read call
		}


		if((sock->state == LISTENED) || (sock->isBound == 0) || (sock->state == CLOSED)){ //If litening socket or not bound or already closed
			sock->state = CLOSED;															// Do not send fin bit and end
			free(sock_vec[sock_index]);
			sock_vec.erase(sock_vec.begin() + sock_index);

			this->removeFileDescriptor(pid, param.param1_int);
			this->returnSystemCall(syscallUUID, 0);
			//printf("<CLOSED> CLOSED FINISHED Earlier\n");
			break;
		}

		uint8_t flags = 0x01;
		uint8_t offset = 0x50;
		uint16_t cwnd = htons(51200);

		Packet *finPacket = this->allocatePacket(54);
		
		// uint32_t my_seq_num;
		// //my_seq_num = htonl(0x98);
		// my_seq_num = htons(sock->last_ack_num);
		// sock->fin_seq_num = my_seq_num;
		// finPacket->writeData(34 + 4, &my_seq_num, 4);

		uint32_t n_seq_num, n_ack_num;
		n_seq_num = htonl(sock->ack_num);
		n_ack_num = htonl(sock->seq_num);

		sock->fin_seq_num = sock->ack_num;
		sock->ack_num += 1;
		
		finPacket->writeData(34 + 4, &n_seq_num, 4);
		finPacket->writeData(34 + 8, &n_ack_num, 4);

		finPacket = make_packet(finPacket, sock->src_addr, sock->dest_addr, flags, offset, cwnd);

		printf("<CLOSED> Send packet on closed called\n");
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
		printf("<CLOSED> CLOSED FINISHED\n");

		// free(sock_vec[sock_index]);
		// sock_vec.erase(sock_vec.begin() + sock_index);

		//this->removeFileDescriptor(pid, param.param1_int);
		//this->returnSystemCall(syscallUUID, 0);
		break;
	}
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		// param.param1_int = fd
		// param.param2_ptr = buffer pointer
		// param.param3_int = given size for copying data

		printf("<READ> READ CALLED\n");
		sock_index = find_socket_by_fd(param.param1_int, pid);

		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		tcp_socket *my_sock;
		my_sock = sock_vec[sock_index];

		if(my_sock->state != ESTAB){
			this->returnSystemCall(syscallUUID, -1);
			break;
		}

		data_amount = initial_read_buffer_size - my_sock->read_buffer_remain;

		if(data_amount == 0){ //The situation is not proper
			printf("<READ> BUFFER IS EMPTY, READ BLOCKED\n");
			
			blocked_read *newblock;
			newblock = (struct blocked_read *) calloc(sizeof(struct blocked_read), 1);

			newblock->uuid = syscallUUID;
			newblock->buf = param.param2_ptr;
			newblock->len = param.param3_int;

			my_sock->read_pending.push_back(newblock);
		}else{
			printf("<READ> BUFFER IS ENOUGH, TAKE DATA\n");
			int copy_amount;
			copy_amount = min(param.param3_int, data_amount);
			my_sock->read_buffer_remain += copy_amount;

			memcpy(param.param2_ptr, my_sock->read_buffer, copy_amount);
			erase_part_of_data(my_sock->read_buffer, data_amount, copy_amount);

			this->returnSystemCall(syscallUUID, copy_amount);
		}
		printf("<READ> READ FINISHED\n");
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		// param.param1_int = fd
		// param.param2_ptr = given data
		// param.param3_int = give datat size

		printf("<WRITE> WRITE CALLED\n");
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

		data_amount = initial_write_buffer_size - write_sock->write_buffer_remain;

		if(data_amount + param.param3_int < write_sock->peer_cwnd){
			printf("<WRITE> BUFFER IS EMPTY, Send message immediately\n");

			uint8_t flags = 0x00;
			uint8_t offset = 0x50;
			uint16_t cwnd = write_sock->read_buffer_remain;

			Packet *myPacket = this->allocatePacket(54 + param.param3_int);
			myPacket = make_packet(myPacket, write_sock->src_addr, write_sock->dest_addr, flags, offset, cwnd);

			myPacket->writeData(54, write_sock->write_buffer, param.param3_int);
			this->sendPacket("IPv4", myPacket);

			write_sock->write_buffer_remain -= param.param3_int;
			erase_part_of_data(write_sock->write_buffer, data_amount, param.param3_int);
		
			this->returnSystemCall(syscallUUID, param.param3_int);
		}else{
			printf("<WRITE> BUFFER IS FILLED, write is blocked\n");
			blocked_write *newblock;
			newblock = (struct blocked_write *) calloc(sizeof(struct blocked_write), 1);

			newblock->uuid = syscallUUID;
			newblock->ptr = param.param2_ptr;
			newblock->len = param.param3_int;

			write_sock->write_pending.push_back(newblock);
		}
		printf("<WRITE> WRITE FINISHED\n");
		break;
	case CONNECT:
	{
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		printf("<CONNECT> CONNECT CALLED\n");
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
		uint16_t cwnd = htons(client->write_buffer_remain);

		uint32_t n_seq_num = htonl(client->ack_num);
		client->ack_num += 1;
		synPacket->writeData(34 + 4, &n_seq_num, 4);

		synPacket = make_packet(synPacket, src, dest, flags, offset, cwnd);

		client->state = SYNSENT;
		client->dest_addr = server_addr;
		client->uuid = syscallUUID;

		// printf("@@@@@@@@@@ Connect src_ip: %x\n", client->src_addr->sin_addr.s_addr);
		// printf("@@@@@@@@@@ Connect src_port: %x\n", client->src_addr->sin_port);
		// printf("@@@@@@@@@@ Connect dest_ip: %x\n", client->dest_addr->sin_addr.s_addr);
		// printf("@@@@@@@@@@ Connect dest_port: %x\n", client->dest_addr->sin_port);

		printf("<CONNECT> Packet send on connect\n");
		this->sendPacket("IPv4", synPacket);
		printf("<CONNECT> CONNECT FINISHED\n");
		break;
	}
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		printf("<LISTEN> LISTEN CALLED\n");
		int sock_index;
		sock_index = find_socket_by_fd(param.param1_int, pid);
		if(sock_index == -1){
			this->returnSystemCall(syscallUUID, -1);
		}else{
			sock_vec[sock_index]->state = LISTENED;
			sock_vec[sock_index]->backlog = param.param2_int;
			sock_vec[sock_index]->uuid = syscallUUID;

			this->returnSystemCall(syscallUUID, 0);
			printf("<LISTEN> LISTEN complete with backlog %d\n", sock_vec[sock_index]->backlog);
		}
		printf("<LISTEN> LISTEN FINISHED\n");
		break;
	case ACCEPT:
	{		
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		printf("<ACCEPT> ACCEPT CALLED\n");
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
			printf("<ACCEPT> There is packet, let's accept and\n");

			child = server_sock->child_list[0];
			server_sock->child_list.erase(server_sock->child_list.begin());
			child->fd = this->createFileDescriptor(pid);

			child->is_accept = 1;

			memcpy(param.param2_ptr, child->dest_addr, sizeof(struct sockaddr_in));
			this->returnSystemCall(syscallUUID, child->fd);
		}else{
			// wait for the packet
			printf("<ACCEPT> Wait for packet\n");

			child = make_socket(pid, syscallUUID, this->createFileDescriptor(pid));
			child->is_accept = 1;

			child->param2_ptr = (sockaddr *) param.param2_ptr;
			child->parent = server_sock;

			child->peer_cwnd = 0;

			sock_vec.push_back(child);
			server_sock->wait_packet.push_back(child);
		}
		
		printf("<ACCEPT> ACCEPT FINISHED\n");
		break;
	}
	case BIND:
		//this->syscall_bind(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		(socklen_t) param.param3_int);
		printf("<BIND> BIND CALLED\n");
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
		printf("<BIND> BIND FINISHEDED\n");
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
	uint16_t checksum, my_checksum;
	uint8_t tcp_header[20];

	uint16_t datagram_length;
	uint16_t data_size;

	sockaddr_in *client_addr;
	sockaddr_in *server_addr;

	// Check Recieved Packet Checksum
	packet->readData(34 + 16, &checksum, 2);

	// if(E::NetworkUtil::tcp_sum(src_ip, dest_ip, tcp_header, 20) != 0){
	// 	this->freePacket(packet);
	// 	printf("Wrong checksum packet!\n");
	// 	return;
	// }

	packet->readData(34, &src_port, 2);
	packet->readData(34 + 2, &dest_port, 2);
	packet->readData(34 + 4, &seq_num, 4);
	packet->readData(34 + 8, &ack_num, 4);
	packet->readData(34 + 13, &flags, 1);

	Packet *myPacket = this->clonePacket(packet);
	client_addr = make_sockaddr_in(src_ip, src_port);
	server_addr = make_sockaddr_in(dest_ip, dest_port);
	this->freePacket(packet);

	// Make  myPacket
	myPacket->readData(14 + 2, &datagram_length, 2);
	data_size = ntohl(datagram_length) - 40;

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

							printf("Message send at packetarrived->syn=1\n");
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

		// printf("@@@@@@@@@@ packet src_ip: %x\n", src_ip);
		// printf("@@@@@@@@@@ packet src_port: %x\n", src_port);
		// printf("@@@@@@@@@@ packet dest_ip: %x\n", dest_ip);
		// printf("@@@@@@@@@@ packet dest_port: %x\n", dest_port);
		if(sock_index == -1){
			printf("@@@@@@@@@@@@@@@@@@@@@@@@ Drop it!!!\n");
		}
		tcp_socket *sock;
		sock = sock_vec[sock_index];
		if(sock->state != SYNSENT){
			this->returnSystemCall(sock->uuid, -1);
		}

		// printf("@@@@@@@@@@ Found src_ip: %x\n", sock_vec[sock_index]->src_addr->sin_addr.s_addr);
		// printf("@@@@@@@@@@ Found src_port: %x\n", sock_vec[sock_index]->src_addr->sin_port);
		// printf("@@@@@@@@@@ Found dest_ip: %x\n", sock_vec[sock_index]->dest_addr->sin_addr.s_addr);
		// printf("@@@@@@@@@@ Found dest_port: %x\n", sock_vec[sock_index]->dest_addr->sin_port);

		// Response Packet
		
		sock->seq_num = ntohl(seq_num);
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

		printf("Message send at packetarrived->syn=1,ack=1\n");
		this->sendPacket("IPv4", myPacket);

		sock->state = ESTAB;
		printf("@@@@@@@@@@@@@@@@@@@@@@@@ Unblocked\n");
		this->returnSystemCall(sock->uuid, 0);
	}else if(flags == 0x10){ // only ACK
		printf("ONLY ACK\n");
		int child_index;
		tcp_socket *child;

		child_index = sock_index;
		//printf("child index is %d\n", child_index);
		if(child_index != -1){
			child = sock_vec[child_index];
			
			if(ntohl(ack_num) == child->fin_seq_num + 1){ //If ACK is about FIN
				printf("ack of fin signal\n");
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
			}else if(ntohl(ack_num) == child->init_seq_num + 1){
				//The last packet for handshaking
				child->parent->backlog++;

				child->state = ESTAB;
				if(child->is_accept == 1){
					this->returnSystemCall(child->uuid, child->fd);
				}else{
					child->parent->child_list.push_back(child);
				}
			}else{
				//normal sign
			}
		} //if child_index = -1, there is no socket for packet


	}else if(flags == 0x01){ // FIN
		//printf("FIN\n");

		int child_index;
		tcp_socket *child;

		child_index = sock_index;
	
		if(child_index != -1){
			//printf("I found the socket\n");
			child = sock_vec[child_index];

			my_flags = (my_flags & 0xFE) | 0x10; //activate ACK
			myPacket->writeData(34 + 13, &my_flags, 1);

			child->seq_num = ntohl(seq_num);
			child->ack_num = ntohl(ack_num);

			uint32_t n_seq_num, n_ack_num;
			n_seq_num = ack_num; // htonl(child->ack_num);
			n_ack_num = htonl(ntohl(seq_num) + 1); //need to plus data_size

			myPacket->writeData(34 + 4, &n_seq_num, 4);
			myPacket->writeData(34 + 8, &n_ack_num, 4);

			checksum = 0;
			myPacket->writeData(34 + 16, &checksum, 2);
			myPacket->readData(34, tcp_header, 20);
			checksum = ~htons(E::NetworkUtil::tcp_sum(dest_ip, src_ip, tcp_header, 20));
			myPacket->writeData(34 + 16, &checksum, 2);
			printf("Send ACK of FIN\n");
			this->sendPacket("IPv4", myPacket);

			if(child->state == FINSENT){
				child->state = CLOSED;
				printf("<CLOSED> CLOSED RETURN\n");
				this->removeFileDescriptor(child->pid, child->fd);
				this->returnSystemCall(child->uuid, 0);

				free(sock_vec[child_index]);
				sock_vec.erase(sock_vec.begin() + child_index);
			}else{
				child->state = FINRCVD;
			}

		}

		
	}


	// if((sock_index != - 1) && (data_size > 0)){
	// 	tcp_socket *match_sock;
	// 	match_sock = sock_vec[sock_index];

	// 	printf("Oh there's %d byte of data\n", data_size);
	// 	void *data_ptr;

	// 	data_ptr = calloc(data_size , 1);
	// 	myPacket->readData(54, &data_ptr, data_size);
	// 	seq_num = ntohl(seq_num);

	// 	if(seq_num == ntohl(match_sock->read_buffer_last_byte)){

	// 		memcpy(match_sock->read_buffer + (initial_read_buffer_size - match_sock->read_buffer_remain), data_ptr, data_size);
	// 		match_sock->read_buffer_last_byte += data_size;
	// 		match_sock->read_buffer_remain -= data_size;

	// 		//send ack

	// 		acket *ackPacket = this->allocatePacket(54);
	
	// 		uint8_t flags = 0x10;
	// 		uint8_t offset = 0x50;
	// 		uint16_t cwnd = htons(match_sock->read_buffer_remain);

	// 		ackPacket->writeData(34 + 4, &my_seq_num, 4);

	// 		ackPacket = make_packet(ackPacket, match_sock->src_addr, match_sock->dest_addr, flags, offset, cwnd);

	// 	}else{
	// 		unordered_seq *new_seq;


	// 		new_seq = (unordered_seq *) calloc(sizeof(struct unordered_seq), 1);

	// 		new_seq->seq_num = seq_num; // seq_num of packet
	// 		new_seq->data_size = data_size;
	// 		new_seq->ptr = data_ptr;
	// 	}

	// }
	

}

void TCPAssignment::timerCallback(void* payload)
{

}

}