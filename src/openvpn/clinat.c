/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#include "syshead.h"

#if defined(ENABLE_CLIENT_NAT)

#include "clinat.h"
#include "proto.h"
#include "socket.h"
#include "memdbg.h"
#include <stdio.h>
#include <ctype.h>
#include <string.h>

/* Delta Table Types */

typedef struct delta_table_key {
  uint32_t src_addr;
  uint32_t dest_addr;
  uint16_t src_port;
  uint16_t dest_port;
} delta_table_key_t;

typedef struct delta_table_entry {
  delta_table_key_t key;
  uint16_t delta_out;
  uint16_t delta_in;
  uint8_t marked_to_remove;
  uint8_t reserved[3];
  uint32_t timestamp;
  struct delta_table_entry *_next;
} delta_table_entry_t;

typedef struct delta_table {
    struct delta_table_entry *head;
} delta_table_t;


// Global delta table
//#define DEBUG_DELTA 1

delta_table_t *table = NULL;

#define TIME_TO_RESPOND 60 * 5 // 5 Minutes
#define TIME_TO_LIVE 24 * 60 * 60

/* Delta Table Functions */

// In seconds, since epoch
static uint32_t 
get_timestamp() {
  return (uint32_t)time(NULL);
}

static void 
print_delta_table_entries(delta_table_t *table) {
    delta_table_entry_t *current = table->head;

  if (current == NULL) {
    return;
  }

  while (current != NULL) {
    printf("from %d -> to %d: removed: %s, timestamp: %d, delta_out: %d, delta_in: %d\n", 
      current->key.src_addr, current->key.dest_addr, current->marked_to_remove ? "true" : "false", 
      current->timestamp, current->delta_out, current->delta_in);
    current = current->_next;
  }
}

static struct delta_table *
init_delta_table() {
  delta_table_t *table = malloc(sizeof(delta_table_t));
  table->head = NULL;
  return table;
}

static struct delta_table_entry *
add_delta_entry(delta_table_t *table, delta_table_entry_t *new_delta_entry) {
  if (table->head == NULL) {
    table->head = new_delta_entry;
    table->head->_next = NULL;
  } else {
    // Add element to HEAD, for performance gain
    new_delta_entry->_next = table->head;
    table->head = new_delta_entry; 
  }
  return new_delta_entry;
}

static int 
remove_delta_entry(delta_table_t *table, delta_table_entry_t *delta_entry) {
  delta_table_entry_t *current = table->head;
  delta_table_entry_t *before = NULL;
  uint8_t found = 0;

  //msg (M_INFO, "On remove_delta_entry - entry: %p", &delta_entry);

  while (current != NULL) {
    if(current == delta_entry) {
      found = 1;
      break;
    }
    before = current;
    current = current->_next;
  }

  //Element not found
  if (!found) {
    return 0;
  }

  if(before==NULL){
    table->head = table->head->_next;
  } else {
    before->_next = delta_entry->_next;
  }

  //msg (M_INFO, "On remove_delta_entry - entry: %p - freed", &delta_entry);
  
  free(delta_entry);
  return 1;
}

static struct delta_table_entry *
get_delta_entry(delta_table_t *table, delta_table_key_t key) {
  delta_table_entry_t *current = table->head;
  delta_table_entry_t *aux = NULL;
  delta_table_entry_t *el = NULL;

  while (current != NULL) {
    // Check TTL and Timeout
    if ((current->marked_to_remove && get_timestamp() - current->timestamp >= TIME_TO_RESPOND) /* ||  get_timestamp() - current->timestamp >= TIME_TO_LIVE */){
      aux = current;
      //If the CURRENT is to be removed, then dont return it
      if (aux == el) { 
        el = NULL;
      }
      current = current->_next;
      remove_delta_entry(table, aux);
    } else {
      if ((
        // Regular connection
        (current->key.src_addr == key.src_addr &&
         current->key.src_port == key.src_port && 
         current->key.dest_addr == key.dest_addr && 
         current->key.dest_port == key.dest_port) ||
        //Check if it is a returned connection
        (current->key.dest_addr == key.src_addr &&
         current->key.dest_port == key.src_port && 
         current->key.src_addr == key.dest_addr && 
         current->key.src_port == key.dest_port))) {
        el = current;
      } 
      current = current->_next;
    }
  }

  return el;
}

/* Delta Table Functions End */


static bool
add_entry(struct client_nat_option_list *dest,
	  const struct client_nat_entry *e)
{
  if (dest->n >= MAX_CLIENT_NAT)
    {
      msg (M_WARN, "WARNING: client-nat table overflow (max %d entries)", MAX_CLIENT_NAT);
      return false;
    }
  else
    {
      dest->entries[dest->n++] = *e;
      return true;
    }
}

void
print_client_nat_list(const struct client_nat_option_list *list, int msglevel)
{
  struct gc_arena gc = gc_new ();
  int i;

  msg (msglevel, "*** CNAT list");
  if (list)
    {
      for (i = 0; i < list->n; ++i)
	{
	  const struct client_nat_entry *e = &list->entries[i];
	  msg (msglevel, "  CNAT[%d] t=%d %s/%s/%s",
	       i,
	       e->type,
	       print_in_addr_t (e->network, IA_NET_ORDER, &gc),
	       print_in_addr_t (e->netmask, IA_NET_ORDER, &gc),
	       print_in_addr_t (e->foreign_network, IA_NET_ORDER, &gc));
	}
    }
  gc_free (&gc);
}

struct client_nat_option_list *
new_client_nat_list (struct gc_arena *gc)
{
  struct client_nat_option_list *ret;
  ALLOC_OBJ_CLEAR_GC (ret, struct client_nat_option_list, gc);
  return ret;
}

struct client_nat_option_list *
clone_client_nat_option_list (const struct client_nat_option_list *src, struct gc_arena *gc)
{
  struct client_nat_option_list *ret;
  ALLOC_OBJ_GC (ret, struct client_nat_option_list, gc);
  *ret = *src;
  return ret;
}

void
copy_client_nat_option_list (struct client_nat_option_list *dest,
			     const struct client_nat_option_list *src)
{
  int i;
  for (i = 0; i < src->n; ++i)
    {
      if (!add_entry(dest, &src->entries[i]))
	break;
    }
}

void
add_client_nat_to_option_list (struct client_nat_option_list *dest,
            const char *type,
            const char *network,
            const char *netmask,
            const char *foreign_network,
            int msglevel)
{
  struct client_nat_entry e;
  bool ok;

  if (!strcmp(type, "snat"))
    e.type = CN_SNAT;
  else if (!strcmp(type, "dnat"))
    e.type = CN_DNAT;
  else
    {
      msg(msglevel, "client-nat: type must be 'snat' or 'dnat'");
      return;
    }

  if (network && !strcmp(network, "localhost"))
    {
      msg (M_INFO, "*** client-nat localhost detected...");
      e.network = 0xFFFFFFFF;
    } else {
      e.network = getaddr(0, network, 0, &ok, NULL);
      if (!ok)
      {
        msg(msglevel, "client-nat: bad network: %s", network);
        return;
      }
    }
    
  e.netmask = getaddr(0, netmask, 0, &ok, NULL);
  if (!ok)
    {
      msg(msglevel, "client-nat: bad netmask: %s", netmask);
      return;
    }
  e.foreign_network = getaddr(0, foreign_network, 0, &ok, NULL);
  if (!ok)
    {
      msg(msglevel, "client-nat: bad foreign network: %s", foreign_network);
      return;
    }

  add_entry(dest, &e);
}


#if 0
static void
print_checksum (struct openvpn_iphdr *iph, const char *prefix)
{
  uint16_t *sptr;
  unsigned int sum = 0;
  int i = 0;
  for (sptr = (uint16_t *)iph; (uint8_t *)sptr < (uint8_t *)iph + sizeof(struct openvpn_iphdr); sptr++)
    {
      i += 1;
      sum += *sptr;
    }
  msg (M_INFO, "** CKSUM[%d] %s %08x", i, prefix, sum);
}
#endif

static void
print_pkt (struct openvpn_iphdr *iph, const char *prefix, const int direction, const int msglevel)
{
  struct gc_arena gc = gc_new ();

  char *dirstr = "???";
  if (direction == CN_OUTGOING)
    dirstr = "OUT";
  else if (direction == CN_INCOMING)
    dirstr = "IN";

  msg(msglevel, "** CNAT %s %s %s -> %s",
      dirstr,
      prefix,
      print_in_addr_t (iph->saddr, IA_NET_ORDER, &gc),
      print_in_addr_t (iph->daddr, IA_NET_ORDER, &gc));
  
  gc_free (&gc);
}

#if DEBUG_DELTA

#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 8
#endif

static void hexdump(void *mem, unsigned int len)
{
  unsigned int i, j;
        
  for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
  {
    /* print offset */
    if(i % HEXDUMP_COLS == 0)
    {
      printf("0x%06x: ", i);
    }
 
    /* print hex data */
    if(i < len)
    {
      printf("%02x ", 0xFF & ((char*)mem)[i]);
    }
    else /* end of block, just aligning for ASCII dump */
    {
      printf("   ");
    }
                
    /* print ASCII dump */
    if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
    {
      for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
      {
        unsigned char ch = 0xFF & ((char*)mem)[j];

        if(j >= len) /* end of block, not really printing */
        {
          putchar(' ');
        } 
        else if (ch >= 0x80) 
        {
          putchar('.');
        }
        else if(isprint(((char*)mem)[j])) /* printable char */
        {
          putchar(0xFF & ((char*)mem)[j]);        
        }
        else /* other char */
        {
          putchar('.');
        }
      }
      putchar('\n');
    }
  }
}
#endif

static int try_number(const char *data, size_t dlen, uint32_t array[],
          int array_size, char sep, char term)
{
  uint32_t i, len;

  memset(array, 0, sizeof(array[0])*array_size);

  /* Keep data pointing at next char. */
  for (i = 0, len = 0; len < dlen && i < array_size; len++, data++) {
    if (*data >= '0' && *data <= '9') {
      array[i] = array[i]*10 + *data - '0';
    }
    else if (*data == sep)
      i++;
    else {
      /* Unexpected character; true if it's the
         terminator and we're finished. */
      if (*data == term && i == array_size - 1)
        return len;

      msg (M_ERRNO, "CNAT - try_number - Char %u (got %u nums) `%u' unexpected\n", len, i, *data);
      return 0;
    }
  }

  msg (M_ERRNO, "CNAT - ERROR: Failed to fill %u numbers separated by %c\n", array_size, sep);

  return 0;
}

static int try_rfc959(const char *, size_t, u_int32_t [], char);

static struct ftp_search {
  int direction;
  const char *pattern;
  size_t plen;
  char skip;
  char term;
  int (*getnum)(const char *, size_t, u_int32_t[], char);
} search[] = {
  {
    CN_OUTGOING,
    "PORT",  sizeof("PORT") - 1, ' ', '\r',
    try_rfc959,
  },
  {
    CN_INCOMING,
    "227 ",  sizeof("227 ") - 1, '(', ')',
    try_rfc959,
  },
};


/* Returns 0, or length of numbers: 192,168,1,1,5,6 */
static int 
try_rfc959(const char *data, size_t dlen, u_int32_t array[6],
           char term)
{
  return try_number(data, dlen, array, 6, ',', term);
}

/* Grab port: number up to delimiter */
static int 
get_port(const char *data, int start, size_t dlen, char delim,
        u_int32_t array[2])
{
  u_int16_t port = 0;
  int i;

  for (i = start; i < dlen; i++) {
    /* Finished? */
    if (data[i] == delim) {
      if (port == 0)
        break;
      array[0] = port >> 8;
      array[1] = port;
      return i + 1;
    }
    else if (data[i] >= '0' && data[i] <= '9')
      port = port*10 + data[i] - '0';
    else /* Some other crap */
      break;
  }
  return 0;
}

/* Return 1 for match, 0 for accept, -1 for partial. */
static int 
find_pattern(const char *data, size_t dlen,
      const char *pattern, size_t plen,
      char skip, char term,
      unsigned int *numoff,
      unsigned int *numlen,
      u_int32_t array[6],
      int (*getnum)(const char *, size_t, u_int32_t[], char))
{
  size_t i;

  if (check_debug_level (D_CLIENT_NAT))
    msg (M_INFO, "CNAT - find_pattern %s: dlen = %u\n", pattern, dlen);

  if (dlen == 0)
    return 0;

  if (dlen <= plen) {
    /* Short packet: try for partial? */
    if (strncasecmp(data, pattern, dlen) == 0)
      return -1;
    else return 0;
  }

  if (strncasecmp(data, pattern, plen) != 0) {
    return 0;
  }

  if (check_debug_level (D_CLIENT_NAT))
    msg (M_INFO, "CNAT - Pattern matches!\n");

  /* Now we've found the constant string, try to skip
     to the 'skip' character */
  for (i = plen; data[i] != skip; i++)
    if (i == dlen - 1) return -1;

  /* Skip over the last character */
  i++;

  if (check_debug_level (D_CLIENT_NAT))
    msg (M_INFO, "CNAT - Skipped up to `%c'!\n", skip);

  *numoff = i;
  *numlen = getnum(data + i, dlen - i, array, term);
  if (!*numlen)
    return -1;

  if (check_debug_level (D_CLIENT_NAT))
    msg (M_INFO, "CNAT - Match succeeded!\n");
  
  return 1;
}

static uint16_t
tcp_checksum (const uint8_t *buf,
        const int len_tcp,
        const uint32_t src_addr,
        const uint32_t dest_addr)
{
  uint16_t word16;
  uint32_t sum = 0;
  int i;
  uint8_t * psrc_addr = (uint8_t *) &src_addr;
  uint8_t * pdest_addr = (uint8_t *) &dest_addr;
  
  /* make 16 bit words out of every two adjacent 8 bit words and  */
  /* calculate the sum of all 16 bit words */
  for (i = 0; i < len_tcp; i += 2){
    word16 = ((buf[i] << 8) & 0xFF00) + ((i + 1 < len_tcp) ? (buf[i+1] & 0xFF) : 0);
    sum += word16;
  }

  /* add the TCP pseudo header which contains the IP source and destination addresses */
  for (i = 0; i < 4; i += 2){
    word16 =((psrc_addr[i] << 8) & 0xFF00) + (psrc_addr[i+1] & 0xFF);
    sum += word16;
  }
  for (i = 0; i < 4; i += 2){
    word16 =((pdest_addr[i] << 8) & 0xFF00) + (pdest_addr[i+1] & 0xFF);
    sum += word16;   
  }

  /* the protocol number and the length of the TCP packet */
  sum += (uint16_t) OPENVPN_IPPROTO_TCP + (uint16_t) len_tcp;

  /* keep only the last 16 bits of the 32 bit calculated sum and add the carries */
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
    
  /* Take the one's complement of sum */
  return ((uint16_t) ~sum);
}

static uint16_t 
ip_checksum(const void *buf, uint16_t hdr_len) {
  unsigned long sum = 0;
  const uint16_t *ip1;

  ip1 = buf;
  while (hdr_len > 1) {
    sum += *ip1++;
    if (sum & 0x80000000)
      sum = (sum & 0xFFFF) + (sum >> 16);
    hdr_len -= 2;
  }

  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);

  return(~sum);
}

static int 
client_nat_ftp_transform(struct buffer *ipbuf,
          const int direction, const uint32_t from_address, uint32_t replace_address) {

  uint32_t array[6] = {0};
  int ret = 0;
  int data_len = 0;

  struct ip_tcp_udp_hdr *hdr = (struct ip_tcp_udp_hdr *) BPTR (ipbuf);

  if (hdr->ip.protocol != OPENVPN_IPPROTO_TCP)
    return ret;

  if (table == NULL) 
      table = init_delta_table();
  
  delta_table_entry_t *entry = NULL;
  delta_table_key_t delta_key;

  // Because the address already was NATed, probably on OpenVPN Server
  if (direction == CN_OUTGOING)
    delta_key.src_addr = from_address;
  else if (direction == CN_INCOMING)
    delta_key.src_addr = hdr->ip.saddr;

  delta_key.src_port = hdr->u.tcp.source;
  delta_key.dest_addr = hdr->ip.daddr;
  delta_key.dest_port = hdr->u.tcp.dest;

#if DEBUG_DELTA
  msg (M_INFO, "delta_key - saddr: %d, sport: %d, daddr: %d, dport: %d", 
  delta_key.src_addr, delta_key.src_port, delta_key.dest_addr, delta_key.dest_port);

  msg (M_INFO, "seq: %x, ack: %x", 
  hdr->u.tcp.seq, hdr->u.tcp.ack_seq);
#endif

  int tcp_data_offset = OPENVPN_TCPH_GET_DOFF (hdr->u.tcp.doff_res);

  struct buffer tcpbuf = *ipbuf;
  if (!buf_advance (&tcpbuf, sizeof(struct openvpn_iphdr) + tcp_data_offset))
    return ret;

  uint8_t * tcp_data = (uint8_t *) BPTR (&tcpbuf);

#if DEBUG_DELTA
  msg (M_INFO, "TCP DATA BEFORE NAT:");
  hexdump(tcp_data, BLEN(&tcpbuf));    
#endif

  u_int32_t matchlen, matchoff;
  int found_pattern = -1;
  int i = 0;

  for (i = 0; i < sizeof(search) / sizeof(search[0]); i++) {
    if (search[i].direction != direction) continue;

    found_pattern = find_pattern(tcp_data, BLEN(&tcpbuf),
             search[i].pattern,
             search[i].plen,
             search[i].skip,
             search[i].term,
             &matchoff, &matchlen,
             array,
             search[i].getnum);
    if (found_pattern) break;
  }

  if (found_pattern > 0) 
    {

      if (check_debug_level (D_CLIENT_NAT)) 
        {
          msg (M_INFO, "client-nat FTP match: %.*s - data: %.*s\n",
            matchoff, tcp_data, matchlen, &tcp_data[matchoff]);
        }

      data_len = BLEN(&tcpbuf) - matchoff;

      uint32_t ip = htonl((array[0] << 24) | (array[1] << 16)
        | (array[2] << 8) | array[3]);
      uint16_t port = htons(array[4] << 8 | array[5]);
      uint8_t * addr_tmp = (uint8_t *) &replace_address;

      uint8_t new_tcp_data[32];
      memset(&new_tcp_data[0], 0, sizeof(new_tcp_data));

      int new_len = sprintf((char *) &new_tcp_data[0], "%d,%d,%d,%d,%d,%d%.*s",
        addr_tmp[0], addr_tmp[1], addr_tmp[2], addr_tmp[3], array[4], array[5], 
        data_len - matchlen, (char *)&tcp_data[matchoff + matchlen]);

      if (check_debug_level (D_CLIENT_NAT)) 
        {
          msg (M_INFO, "client-nat replaced address from: %.*s to: %.*s\n",
            data_len, &tcp_data[matchoff], new_len, &new_tcp_data[0]);
        }

      //If the new len is greater than the old, there will be there an adjustment
      if (new_len > data_len) 
        {
          //If the entry already exists
          if (entry = get_delta_entry(table, delta_key)) 
            {
              if (direction == CN_OUTGOING) 
                {
                  hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + (entry->delta_out));       // Need to update seq and ack
                  hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_in);
                  entry->delta_out += new_len - data_len;
                }
              else
                {
                  hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + (entry->delta_in));        // Need to update seq and ack
                  hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_out);
                  entry->delta_in += new_len - data_len;
                }
              //Update timestamp entry on delta entry, to keep this delta alive
              entry->timestamp = get_timestamp();
            }
          else 
            {
              // No entry found. Add a new one.
              entry = malloc(sizeof(delta_table_entry_t));
              entry->key = delta_key;

              if (direction == CN_OUTGOING) 
                {
                  entry->delta_out = new_len - data_len;
                  entry->delta_in = 0;
                }
              else
                {
                  entry->delta_in = new_len - data_len;
                  entry->delta_out = 0;
                }
              entry->marked_to_remove = 0;
              entry->timestamp = get_timestamp();
        
              //Add it to delta table
              add_delta_entry(table, entry);
            }

#if DEBUG_DELTA
          print_delta_table_entries(table);
#endif

          //Increase the tcpbuf and ipbuf reflecting the delta chars added to the segment.
          ASSERT(buf_inc_len(&tcpbuf, new_len - data_len));
          ASSERT(buf_inc_len(ipbuf, new_len - data_len));

          //Update tot_len
          hdr->ip.tot_len = htons(ntohs(hdr->ip.tot_len) + (new_len - data_len));

          // Readjust IP Checksum
          uint16_t head_len = OPENVPN_IPH_GET_LEN(hdr->ip.version_len);
          hdr->ip.check = 0;
          uint16_t check = ip_checksum( BPTR (ipbuf), head_len);
          hdr->ip.check = check;

          //Use new_len here!
          memcpy(&tcp_data[matchoff], new_tcp_data, new_len); 
        }
      else
        {
          // The replace size is the lesser or iqual the original? Pad with 0 if necessary.
          memcpy(&tcp_data[matchoff], new_tcp_data, data_len); 

          //If the entry already exists
          if (entry = get_delta_entry(table, delta_key)) 
            {
              if (direction == CN_OUTGOING) 
                {
                  hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + (entry->delta_out));       // Need to update seq and ack
                  hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_in);
                }
              else
                {
                  hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + (entry->delta_in));        // Need to update seq and ack
                  hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_out);
                }
              //Update timestamp entry on delta entry, to keep this delta alive
              entry->timestamp = get_timestamp();
            }

        }

      //Update TCP checksum
      hdr->u.tcp.check = 0;

      uint16_t tot_len = ntohs(hdr->ip.tot_len);
      uint16_t head_len = OPENVPN_IPH_GET_LEN(hdr->ip.version_len);

      uint16_t check = tcp_checksum(BPTR (ipbuf) + head_len, 
      tot_len - head_len, hdr->ip.saddr, hdr->ip.daddr); 

      hdr->u.tcp.check = htons(check);
      ret = 1;
    }
  else 
    {
      //No pattern found. Check if there is a delta entry for this connection
      if(entry = get_delta_entry(table, delta_key)) 
        {
          if (direction == CN_OUTGOING) 
            {
              hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + entry->delta_out);
              hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_in);
            } 
          else 
            {
              hdr->u.tcp.seq = htonl(ntohl(hdr->u.tcp.seq) + entry->delta_in);
              hdr->u.tcp.ack_seq = htonl(ntohl(hdr->u.tcp.ack_seq) - entry->delta_out);
            }

          //Update TCP checksum
          hdr->u.tcp.check = 0;

          uint16_t tot_len = ntohs(hdr->ip.tot_len);
          uint16_t head_len = OPENVPN_IPH_GET_LEN(hdr->ip.version_len);

          uint16_t check = tcp_checksum(BPTR (ipbuf) + head_len, 
          tot_len - head_len, hdr->ip.saddr, hdr->ip.daddr); 

          hdr->u.tcp.check = htons(check);

          //Update timestamp entry on delta entry
          entry->timestamp = get_timestamp();

          // If it is a FIN package, then remove entry from delta table
          if (OPENVPN_TCPH_FIN_MASK & hdr->u.tcp.flags) 
            {
              entry->marked_to_remove = 1;
              msg (M_INFO, "Delta marked to be removed!");
            }
  
          ret = 1; 
        }
      else 
        {
#if DEBUG_DELTA
          // Regular package!
          msg (M_INFO, "Regular package!: tot_len %d, seq %x, ack %x\n", ntohs(hdr->ip.tot_len), ntohl(hdr->u.tcp.seq), ntohl(hdr->u.tcp.ack_seq));
#endif
        }
    }

#if DEBUG_DELTA
  msg (M_INFO, "TCP DATA AFTER NAT:");
  hexdump(tcp_data, BLEN(&tcpbuf));
#endif

  return ret;
}

void
client_nat_transform (const struct client_nat_option_list *list,
          struct buffer *ipbuf,
          const int direction, 
          const bool enable_nat_ftp_support)
{
  struct ip_tcp_udp_hdr *h = (struct ip_tcp_udp_hdr *) BPTR (ipbuf);
  int i;
  uint32_t addr, *addr_ptr, from_addr;
  const uint32_t *from, *to;
  int accumulate = 0;
  unsigned int amask;
  unsigned int alog = 0;

  uint32_t orig_saddr = h->ip.saddr;
  uint32_t orig_daddr = h->ip.daddr;

  if (check_debug_level (D_CLIENT_NAT))
    print_pkt (&h->ip, "BEFORE", direction, D_CLIENT_NAT);

  for (i = 0; i < list->n; ++i)
    {
      const struct client_nat_entry *e = &list->entries[i]; /* current NAT rule */
      if (e->type ^ direction)
        {
          addr = *(addr_ptr = &h->ip.daddr);
          amask = 2;
        }
      else
        {
          addr = *(addr_ptr = &h->ip.saddr);
          amask = 1;
        }
      if (direction)
        {
          from = &e->foreign_network;
          to = &e->network;
        }
      else
        {
          from = &e->network;
          to = &e->foreign_network;
        }

      if (((addr & e->netmask) == *from) && !(amask & alog))
        {
          from_addr = *from;
    
          /* pre-adjust IP checksum */
          ADD_CHECKSUM_32(accumulate, addr);

          /* do NAT transform */
          addr = (addr & ~e->netmask) | *to;

          /* post-adjust IP checksum */
          SUB_CHECKSUM_32(accumulate, addr);

          /* write the modified address to packet */
          *addr_ptr = addr;

          /* mark as modified */
          alog |= amask;
        }
    }
  if (alog)
    {
      if (check_debug_level (D_CLIENT_NAT))
        print_pkt (&h->ip, "AFTER", direction, D_CLIENT_NAT);

      ADJUST_CHECKSUM(accumulate, h->ip.check);

      if (h->ip.protocol == OPENVPN_IPPROTO_TCP)
        {
          if (BLEN(ipbuf) >= sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_tcphdr))
            {
              ADJUST_CHECKSUM(accumulate, h->u.tcp.check);
            }

          uint32_t repl_addr = addr;
      
          if (amask == 2) 
            {
              if (direction)
                repl_addr = orig_saddr;
              else
                repl_addr = orig_daddr;
            }
      
          if (enable_nat_ftp_support)
            client_nat_ftp_transform(ipbuf, direction, from_addr, repl_addr);
    
        }
      else if (h->ip.protocol == OPENVPN_IPPROTO_UDP)
        {
          if (BLEN(ipbuf) >= sizeof(struct openvpn_iphdr) + sizeof(struct openvpn_udphdr))
           {
              ADJUST_CHECKSUM(accumulate, h->u.udp.check);
            }
        }
    }
}

/*
* Replaces the localhost token with the IP received from OpenVPN
*/
bool 
update_localhost_nat(struct client_nat_option_list *dest, in_addr_t local_ip)
{
  int i;
  bool ret = false;

  if (!dest)
    return ret;

  for (i=0; i <= dest->n; i++) 
    {
      struct client_nat_entry *nat_entry = &dest->entries[i];
      if (nat_entry && nat_entry->network == 0xFFFFFFFF) 
        {
          struct in_addr addr;
          
          nat_entry->network = ntohl(local_ip);
          addr.s_addr = nat_entry->network;
          char *dot_ip = inet_ntoa(addr);

          msg (M_INFO, "CNAT - Updating NAT table from localhost to: %s", dot_ip); 
          ret = true;
        }
    }

  return ret;
}

#endif
