/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <algorithm>


#include <E/E_TimerModule.hpp>

#define MAX_BUFF	1024

namespace E
{
	
class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	std::vector<struct tcp_socket *> sock_vec;
private:
	virtual void timerCallback(void* payload) final;
	int find_socket_by_fd(int fd, int pid);
	int find_socket_by_addr(sockaddr_in *src, sockaddr_in *dest);
	int comp_sockaddr_in(sockaddr_in *target1, sockaddr_in *target2);
	sockaddr_in* make_sockaddr_in(uint32_t ip, uint16_t port);
	int assign_random_port();
	Packet* make_packet(Packet *packet_ptr, sockaddr_in *src, sockaddr_in *dest, uint8_t flags, uint8_t offset, uint16_t window_size);
	void free_socket(tcp_socket *sock);
	void erase_part_of_data(void *ptr, int original_size, int erase_size);

	int min(int x, int y);
	int max(int x, int y);

	tcp_socket* make_socket(int pid, UUID uuid, int fd);
	void fill_checksum(Packet *packet_ptr, uint16_t data_size);
	void make_packet_ack_seq(Packet *packet_ptr, sockaddr_in *src, sockaddr_in *dest, uint8_t flags, uint8_t offset, uint16_t window_size, uint32_t seq_num, uint32_t ack_num);
	void send_packet_with_data(tcp_socket *w_sock, uint32_t original_data, uint32_t write_size);
	void m_send_packet_with_data(tcp_socket *w_sock, uint32_t startpoint, uint32_t send_size);

	void hexdump(void *ptr, int buflen);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
