/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ipdump.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: skuppers <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2020/02/14 10:01:37 by skuppers          #+#    #+#             */
/*   Updated: 2020/02/14 11:34:22 by skuppers         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "ipdump.h"

void	pcap_fatal(const char *failed_in, const char *errbuf)
{
	printf("Fatal error in %s: %s\n",failed_in, errbuf);
	exit(1);
}

void	decode_ethernet_packet(const u_char *header_start)
{
	int						i;
	const struct ether_hdr	*ethernet_header;

	ethernet_header = (const struct ether_hdr *)header_start;
	printf("[[ Layer 2 :: Ethernet Header ]]\n");
	printf("[ Source: %02x", ethernet_header->ether_src_addr[0]);
	for (i = 1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_src_addr[i]);

	printf("\tDest: %02x", ethernet_header->ether_dest_addr[0]);
	for (i = 1; i < ETHER_ADDR_LEN; i++)
		printf(":%02x", ethernet_header->ether_dest_addr[i]);
	printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void	decode_ip_packet(const u_char *header_start)
{
	const struct ip_hdr		*ip_header;

	ip_header = (const struct ip_hdr*)header_start;
	printf("\t((  Layer 3 ::: IP Header  ))\n");

	printf("\t( Source: %s\t", inet_ntoa(*(struct in_addr*)&(ip_header->ip_src_addr)));
	printf("Dest: %s )\n", inet_ntoa(*(struct in_addr*)&(ip_header->ip_dst_addr)));
	printf("\t( Type: %u\t", (u_int) ip_header->ip_type);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

u_int	decode_tcp_packet(const u_char *header_start)
{
	(void)header_start;
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header,
				const u_char *packet)
{
	(void) user_args;
//	int		tcp_header_length, total_header_size, pkt_data_len;
//	u_char	*pkt_data;

	printf("=== Got a %d byte packet ===\n", cap_header->len);
	decode_ethernet_packet(packet);
	decode_ip_packet(packet + ETHER_HDR_LEN);
//	tcp_header_length = decode_tcp_packet(packet + ETHER_HDR_LEN + sizeof(struct ip_hdr));

//	total_header_size = ETHER_HDR_LEN + sizeof(struct ip_hdr) + tcp_header_length;

//	pkt_data = (u_char *)packet + total_header_size;
//	pkt_data_len = cap_header->len - total_header_size;

//	if (pkt_data_len > 0) {
//		printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
//		dump(pkt_data, pkt_data_len);
//	}
//	else
//		printf("\t\t\tNo packet Data.\n");
}

int main(void)
{
	pcap_t				*pcap_handle;
//	struct pcap_pkthdr	header;
//	const u_char		*packet;
//	const u_char		*pkt_data;

	char errbuff[PCAP_ERRBUF_SIZE];
	char *device;

	device = pcap_lookupdev(errbuff);
	if (device == NULL)
		pcap_fatal("pcap_lookupdevice()", errbuff);
	printf("Sniffing on device %s\n", device);

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuff);
	if (pcap_handle == NULL)
		pcap_fatal("pcap_open_live", errbuff);

	pcap_loop(pcap_handle, 3, caught_packet, NULL);
	pcap_close(pcap_handle);
}
