/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ipdump.h                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: skuppers <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/02/14 10:01:35 by skuppers          #+#    #+#             */
/*   Updated: 2020/02/14 11:34:17 by skuppers         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

# ifndef H_IPDUMP_H
#define H_IPDUMP_H

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#define ETHER_ADDR_LEN	6
#define ETHER_HDR_LEN	14

struct				ether_hdr
{
	unsigned char	ether_dest_addr[ETHER_ADDR_LEN];
	unsigned char	ether_src_addr[ETHER_ADDR_LEN];
	unsigned short	ether_type;
};

#define ICMP_CODE	1
#define TCP_CODE	6
#define UDP_CODE	17

struct				ip_hdr
{
	unsigned char	ip_version_and_header_length;
	unsigned char	ip_tos;
	unsigned short	ip_len;
	unsigned short	ip_id;
	unsigned short	ip_frag_offset;
	unsigned char 	ip_ttl;
	unsigned char	ip_type;
	unsigned short	ip_checksum;
	unsigned int	ip_src_addr;
	unsigned int	ip_dst_addr;
};

struct				icmp_hdr
{
	unsigned char	icmp_type;
	unsigned char	icmp_code;
	unsigned short	icmp_checksum;
	unsigned short	icmp_id;
	unsigned short	icmp_sequence;
};

struct				tcp_hdr
{
	unsigned short	tcp_src_port;
	unsigned short	tcp_dest_port;
	unsigned int	tcp_seq;
	unsigned int	tcp_ack;
	unsigned char	reserved:4;
	unsigned char	tcp_offset:4;

	unsigned char	tcp_flags;
#define TCP_FIN		0x01
#define TCP_SYN		0x02
#define TCP_RST		0x04
#define TCP_PUSH	0x10
#define TCP_ACK		0x20
#define TCP_URG		0x40
	unsigned short	tcp_window;
	unsigned short	tcp_checksum;
	unsigned short	tcp_urgent;
};

#endif
