/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

static const uint8_t broadcast_mac[ETHER_ADDR_LEN] =
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void sr_handle_arp(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface);
static void sr_handle_ip(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface);
static void sr_handle_ip_for_us(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface);
static void sr_send_echo_reply(struct sr_instance* sr, uint8_t* packet,
        unsigned int len);
static int sr_is_our_ip(struct sr_instance* sr, uint32_t ip);
static void sr_send_arp(struct sr_instance* sr, struct sr_if* iface,
        unsigned short op, const uint8_t* target_mac, uint32_t target_ip);
static void sr_send_frame(struct sr_instance* sr, uint8_t* frame,
        unsigned int len, const uint8_t* dst_mac, struct sr_if* out_iface);
static struct sr_packet* sr_reverse_packets(struct sr_packet* head);
static struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr,
        uint32_t ip);
static void sr_send_to_next_hop(struct sr_instance* sr, uint8_t* frame,
        unsigned int len, struct sr_rt* route);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  struct sr_if* iface = sr_get_interface(sr, interface);
  if (!iface || len < sizeof(sr_ethernet_hdr_t)) {
    return;
  }

  switch (ethertype(packet)) {
    case ethertype_arp:
      sr_handle_arp(sr, packet, len, iface);
      break;
    case ethertype_ip:
      sr_handle_ip(sr, packet, len, iface);
      break;
    default:
      /* Anything else (e.g. IPv6 router solicitations) is not ours to route. */
      break;
  }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_handle_arp
 *
 * Answers ARP requests for the receiving interface's IP, and turns ARP
 * replies into cache entries, flushing any packets queued on them.
 *---------------------------------------------------------------------*/
static void sr_handle_arp(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface)
{
  sr_arp_hdr_t* arp_hdr;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    return;
  }
  arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet ||
      ntohs(arp_hdr->ar_pro) != ethertype_ip) {
    return;
  }
  /* We only speak for our own address on the link the frame came in on. */
  if (arp_hdr->ar_tip != iface->ip) {
    return;
  }

  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    sr_send_arp(sr, iface, arp_op_reply, arp_hdr->ar_sha, arp_hdr->ar_sip);
  }
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    /* insert() also unlinks the matching request from the queue, so the
       sweeper thread can no longer see it and we own it from here on. */
    struct sr_arpreq* req = sr_arpcache_insert(&sr->cache,
        arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (req) {
      struct sr_packet* pkt;
      /* queuereq() pushes onto the head; reverse to send in arrival order. */
      req->packets = sr_reverse_packets(req->packets);
      for (pkt = req->packets; pkt; pkt = pkt->next) {
        sr_send_frame(sr, pkt->buf, pkt->len, arp_hdr->ar_sha,
            sr_get_interface(sr, pkt->iface));
      }
      sr_arpreq_destroy(&sr->cache, req);
    }
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip
 *
 * Sanity-checks an IPv4 packet, then either answers it (if it is for one
 * of our addresses) or forwards it one hop closer to its destination.
 *---------------------------------------------------------------------*/
static void sr_handle_ip(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface)
{
  sr_ip_hdr_t* ip_hdr;
  unsigned int hdr_len;
  struct sr_rt* route;

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return;
  }
  ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  hdr_len = ip_hdr->ip_hl * 4;
  if (ip_hdr->ip_v != 4 || hdr_len < sizeof(sr_ip_hdr_t) ||
      ntohs(ip_hdr->ip_len) < hdr_len ||
      sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len) > len) {
    return;
  }

  /* A correct header, its own checksum included, sums to 0xffff, for which
     cksum() returns 0xffff. Don't instead zero the field, recompute and
     compare: cksum() never returns 0, so a valid stored 0x0000 would fail. */
  if (cksum(ip_hdr, hdr_len) != 0xffff) {
    return;
  }

  if (sr_is_our_ip(sr, ip_hdr->ip_dst)) {
    sr_handle_ip_for_us(sr, packet, len, iface);
    return;
  }

  /* Forwarding. Check both failure cases before touching the header, so the
     error quotes the packet exactly as the sender sent it. */
  if (ip_hdr->ip_ttl <= 1) {
    sr_send_icmp_error(sr, packet, len, icmp_type_time_exceeded, 0,
        iface->ip);
    return;
  }
  route = sr_longest_prefix_match(sr, ip_hdr->ip_dst);
  if (!route) {
    sr_send_icmp_error(sr, packet, len, icmp_type_dest_unreach,
        icmp_code_net_unreach, iface->ip);
    return;
  }

  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, hdr_len);
  sr_send_to_next_hop(sr, packet, len, route);
}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_for_us
 *
 * The packet is addressed to one of our interfaces: answer pings, refuse
 * TCP/UDP with port unreachable (this is what ends a traceroute), and
 * ignore everything else.
 *---------------------------------------------------------------------*/
static void sr_handle_ip_for_us(struct sr_instance* sr, uint8_t* packet,
        unsigned int len, struct sr_if* iface)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  if (ip_hdr->ip_p == ip_protocol_icmp) {
    sr_send_echo_reply(sr, packet, len);
  }
  else if (ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
    /* Like the reference sr_solution, answer from the interface the probe
       arrived on (RFC 792 allows any of our addresses). */
    sr_send_icmp_error(sr, packet, len, icmp_type_dest_unreach,
        icmp_code_port_unreach, iface->ip);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_send_echo_reply
 *
 * If packet is a valid ICMP echo request, sends back a copy of it with the
 * addresses swapped and the type changed to echo reply. Identifier,
 * sequence number and payload stay as they were, which is what lets ping
 * match the reply to its request.
 *---------------------------------------------------------------------*/
static void sr_send_echo_reply(struct sr_instance* sr, uint8_t* packet,
        unsigned int len)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  unsigned int hdr_len = ip_hdr->ip_hl * 4;
  /* Use the IP length, not the frame length: short frames are padded on
     the wire and that padding is not part of the ICMP message. */
  unsigned int icmp_len = ntohs(ip_hdr->ip_len) - hdr_len;
  unsigned int frame_len = sizeof(sr_ethernet_hdr_t) + ntohs(ip_hdr->ip_len);
  sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)((uint8_t*)ip_hdr + hdr_len);
  struct sr_rt* route;
  uint8_t* reply;
  sr_ip_hdr_t* reply_ip;
  sr_icmp_hdr_t* reply_icmp;

  if (icmp_len < sizeof(sr_icmp_hdr_t) ||
      icmp_hdr->icmp_type != icmp_type_echo_request) {
    return;
  }
  /* Same check as for the IP header in sr_handle_ip. */
  if (cksum(icmp_hdr, icmp_len) != 0xffff) {
    return;
  }

  route = sr_longest_prefix_match(sr, ip_hdr->ip_src);
  if (!route) {
    return;
  }

  reply = malloc(frame_len);
  memcpy(reply, packet, frame_len);
  reply_ip = (sr_ip_hdr_t*)(reply + sizeof(sr_ethernet_hdr_t));
  reply_icmp = (sr_icmp_hdr_t*)((uint8_t*)reply_ip + hdr_len);

  reply_icmp->icmp_type = icmp_type_echo_reply;
  reply_icmp->icmp_code = 0;
  reply_icmp->icmp_sum = 0;
  reply_icmp->icmp_sum = cksum(reply_icmp, icmp_len);

  reply_ip->ip_src = ip_hdr->ip_dst;
  reply_ip->ip_dst = ip_hdr->ip_src;
  reply_ip->ip_ttl = 64;
  reply_ip->ip_sum = 0;
  reply_ip->ip_sum = cksum(reply_ip, hdr_len);

  sr_send_to_next_hop(sr, reply, frame_len, route);
  free(reply);
}

static int sr_is_our_ip(struct sr_instance* sr, uint32_t ip)
{
  struct sr_if* if_walker;
  for (if_walker = sr->if_list; if_walker; if_walker = if_walker->next) {
    if (if_walker->ip == ip) {
      return 1;
    }
  }
  return 0;
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp_request
 *
 * Broadcasts "who has req->ip?" out of the interface the waiting packets
 * will leave from (they all share one next hop, hence one interface).
 *---------------------------------------------------------------------*/
void sr_send_arp_request(struct sr_instance* sr, struct sr_arpreq* req)
{
  struct sr_if* iface;

  if (!req->packets) {
    return;
  }
  iface = sr_get_interface(sr, req->packets->iface);
  if (iface) {
    sr_send_arp(sr, iface, arp_op_request, NULL, req->ip);
  }
}

/*---------------------------------------------------------------------
 * Method: sr_send_arp
 *
 * Builds and sends one ARP frame from iface. For a request target_mac is
 * NULL: the frame is broadcast and the target hardware address left zero.
 * target_ip is in network byte order.
 *---------------------------------------------------------------------*/
static void sr_send_arp(struct sr_instance* sr, struct sr_if* iface,
        unsigned short op, const uint8_t* target_mac, uint32_t target_ip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t* buf = calloc(1, len);
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)buf;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

  arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_hdr->ar_pro = htons(ethertype_ip);
  arp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_hdr->ar_pln = sizeof(uint32_t);
  arp_hdr->ar_op = htons(op);
  memcpy(arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_hdr->ar_sip = iface->ip;
  if (target_mac) {
    memcpy(arp_hdr->ar_tha, target_mac, ETHER_ADDR_LEN);
  }
  arp_hdr->ar_tip = target_ip;

  eth_hdr->ether_type = htons(ethertype_arp);
  sr_send_frame(sr, buf, len, target_mac ? target_mac : broadcast_mac, iface);
  free(buf);
}

/*---------------------------------------------------------------------
 * Method: sr_send_frame
 *
 * Fills in the Ethernet addresses of an already-built frame and sends it
 * out of out_iface. The frame stays owned by the caller.
 *---------------------------------------------------------------------*/
static void sr_send_frame(struct sr_instance* sr, uint8_t* frame,
        unsigned int len, const uint8_t* dst_mac, struct sr_if* out_iface)
{
  sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)frame;

  if (!out_iface) {
    return;
  }
  memcpy(eth_hdr->ether_dhost, dst_mac, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  sr_send_packet(sr, frame, len, out_iface->name);
}

static struct sr_packet* sr_reverse_packets(struct sr_packet* head)
{
  struct sr_packet* prev = NULL;
  while (head) {
    struct sr_packet* next = head->next;
    head->next = prev;
    prev = head;
    head = next;
  }
  return prev;
}

/*---------------------------------------------------------------------
 * Method: sr_longest_prefix_match
 *
 * Returns the routing entry whose prefix matches ip (network byte order)
 * with the longest mask, or NULL if none matches.
 *---------------------------------------------------------------------*/
static struct sr_rt* sr_longest_prefix_match(struct sr_instance* sr,
        uint32_t ip)
{
  struct sr_rt* best = NULL;
  struct sr_rt* rt;

  for (rt = sr->routing_table; rt; rt = rt->next) {
    uint32_t mask = rt->mask.s_addr;
    if ((ip & mask) != (rt->dest.s_addr & mask)) {
      continue;
    }
    /* Masks are contiguous, so in host order a longer prefix is a bigger
       number. */
    if (!best || ntohl(mask) > ntohl(best->mask.s_addr)) {
      best = rt;
    }
  }
  return best;
}

/*---------------------------------------------------------------------
 * Method: sr_send_to_next_hop
 *
 * Sends an IP-carrying frame along route. If the next hop's MAC is cached
 * the frame goes out now; otherwise a copy is queued on the ARP request
 * for that next hop. The frame stays owned by the caller.
 *---------------------------------------------------------------------*/
static void sr_send_to_next_hop(struct sr_instance* sr, uint8_t* frame,
        unsigned int len, struct sr_rt* route)
{
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(frame + sizeof(sr_ethernet_hdr_t));
  struct sr_if* out_iface = sr_get_interface(sr, route->interface);
  /* A zero gateway means the destination is directly on that link. */
  uint32_t next_hop_ip = route->gw.s_addr ? route->gw.s_addr : ip_hdr->ip_dst;
  struct sr_arpentry* entry;
  struct sr_arpreq* req;

  if (!out_iface) {
    return;
  }
  ((sr_ethernet_hdr_t*)frame)->ether_type = htons(ethertype_ip);

  entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (entry) {
    sr_send_frame(sr, frame, len, entry->mac, out_iface);
    free(entry);
    return;
  }

  /* Hold the lock so the sweeper thread can't destroy req between
     queueing and using it. */
  pthread_mutex_lock(&sr->cache.lock);
  req = sr_arpcache_queuereq(&sr->cache, next_hop_ip, frame, len,
      out_iface->name);
  /* Only kick off brand-new requests here; retries and giving up are left
     to the sweeper, so a request is never destroyed under its feet. */
  if (req->times_sent == 0) {
    sr_handle_arpreq(sr, req);
  }
  pthread_mutex_unlock(&sr->cache.lock);
}

/*---------------------------------------------------------------------
 * Method: sr_send_icmp_error
 *
 * Sends an ICMP error (type 3 or 11) about orig_frame back to its source,
 * quoting the original IP header plus the first 8 bytes of its payload.
 * src_ip (network byte order) is the address to send from; 0 means use
 * the interface the error leaves through.
 *---------------------------------------------------------------------*/
void sr_send_icmp_error(struct sr_instance* sr, uint8_t* orig_frame,
        unsigned int orig_len, uint8_t type, uint8_t code, uint32_t src_ip)
{
  unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) +
      sizeof(sr_icmp_t3_hdr_t);
  unsigned int quote_len;
  sr_ip_hdr_t* orig_ip;
  struct sr_rt* route;
  struct sr_if* out_iface;
  uint8_t* buf;
  sr_ip_hdr_t* ip_hdr;
  sr_icmp_t3_hdr_t* icmp_hdr;

  if (orig_len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
    return;
  }
  orig_ip = (sr_ip_hdr_t*)(orig_frame + sizeof(sr_ethernet_hdr_t));

  /* Never answer an ICMP error with another ICMP error (RFC 1122 3.2.2),
     or two routers could bounce errors at each other forever. */
  if (orig_ip->ip_p == ip_protocol_icmp &&
      orig_len >= sizeof(sr_ethernet_hdr_t) + orig_ip->ip_hl * 4 +
                  sizeof(sr_icmp_hdr_t)) {
    sr_icmp_hdr_t* orig_icmp =
        (sr_icmp_hdr_t*)((uint8_t*)orig_ip + orig_ip->ip_hl * 4);
    if (orig_icmp->icmp_type != icmp_type_echo_request &&
        orig_icmp->icmp_type != icmp_type_echo_reply) {
      return;
    }
  }

  route = sr_longest_prefix_match(sr, orig_ip->ip_src);
  if (!route || !(out_iface = sr_get_interface(sr, route->interface))) {
    return;
  }

  buf = calloc(1, len);
  ip_hdr = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
  icmp_hdr = (sr_icmp_t3_hdr_t*)((uint8_t*)ip_hdr + sizeof(sr_ip_hdr_t));

  icmp_hdr->icmp_type = type;
  icmp_hdr->icmp_code = code;
  quote_len = orig_len - sizeof(sr_ethernet_hdr_t);
  if (quote_len > ICMP_DATA_SIZE) {
    quote_len = ICMP_DATA_SIZE;
  }
  memcpy(icmp_hdr->data, orig_ip, quote_len);
  icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

  ip_hdr->ip_v = 4;
  ip_hdr->ip_hl = sizeof(sr_ip_hdr_t) / 4;
  ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  ip_hdr->ip_ttl = 64;
  ip_hdr->ip_p = ip_protocol_icmp;
  ip_hdr->ip_src = src_ip ? src_ip : out_iface->ip;
  ip_hdr->ip_dst = orig_ip->ip_src;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  sr_send_to_next_hop(sr, buf, len, route);
  free(buf);
}

