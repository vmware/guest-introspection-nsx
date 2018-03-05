/*
 *
 * Copyright (C) 2018 VMware, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2.

 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
 *
 */

/*
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * This file (a part of vmw_conn_notify) contains logic to interact with
 * netfilter libraries and the connected clients.
 *
 * It forks two threads :
 * 1. vmw_netfilter_event_handler : It uses libnetfilter_queue and
 * libnetfilter_conntrack to receive network connection events from
 * netfilter kernel modules.
 *
 * 2. vmw_client_msg_recv : It receives client's response and redirects back
 * to appropriate netfilter library (which requires verdict).
 *
 * Please note that events are deliverd to the connected client through unix
 * domain socket in netfilter library callbacks.
 */

#include "vmw_conn.h"

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

/* Maximum queue length to handle connection burst */
#define VNET_NFQLENGTH 65536

/* Packet size to be retrieved from netfilter queue */
#define VNET_BUFSIZE 1024

/* Mark on packets to be put by our daemon after processing. */
#define VMW_NFQ_PKT_MARK  0x1

/* Loop back or local address and mask */
#define VMW_LOOPBACK_ADDRESS "127.0.0.1"
#define VMW_LOOPBACK_MASK 0xffffffff

/*
 * A wrapper structure to keep netfilter queue handle and FD for getting
 * packets from queue library/kernel module.
 */
struct _vmw_net_queue {
   struct nfq_handle *handle;          /* Netfilter queue connection handle */
   struct nfq_q_handle *qhandle;       /* Netfilter queue handle */
   int qfd;                            /* Netfilter queue fd */
};

/*
 * A wrapper structure to keep netfilter conntrack handle and FD for getting
 * connection states from conntrack library/kernel module.
 */
struct _vmw_net_conntrack {
   struct nfct_handle *cthandle;       /* Netfilter conntrack handle */
   int ctfd;                           /* Netfilter conntrack FD */
};

/*
 * Global data structure that contains netfilter related structures, listen
 * start/stop hash cache and thread pool structure  for delivering events.
 */
struct vmw_net_session {
  struct _vmw_net_queue  queue_ctx;           /* NFQ handle & FD */
  struct _vmw_net_conntrack conntrack_ctx;    /* Conntack FD and handle */
  pthread_mutex_t queue_lock;                 /* Lock to sync nfq send/recv */
};

/* Global structure to maintain netfilter Queue and conntrack handle */
struct vmw_net_session *vmw_net_sess_handle;

/*
 * Global lock to protect concurrent updates and lookups of the global
 * hashtable
 */
pthread_mutex_t global_pkthash_lock  = PTHREAD_MUTEX_INITIALIZER;

/*
 * Global variable indicates completion of all necessary
 * initialization
 */
volatile int g_vmw_init_done = 0;

extern struct vmw_client_scope g_client_ctx[MAX_CLIENTS];
extern GHashTable *global_queued_pkthash;
extern volatile int g_need_to_quit;

extern int
vmw_wait_for_event(int, fd_set *, uint8_t);
extern void
vmw_notify_exit();

/*
 * Destructor for the value entry of global hash table
 */
void
cleanup_global_hash_entry(gpointer data)
{
   global_packet_info *packet = NULL;
   if (data) {
      packet = (global_packet_info *)data;
      pthread_mutex_destroy(&packet->lock);
      DEBUG("Cleaning packet data with eventid %d from global hash table",
            packet->event_id);
      free(data);
      data = NULL;
   }
}

/*
 * Preserve the existing mark of packet and append it with
 * vmw_notifier mark
 */
uint32_t
update_packet_mark(struct nfq_data *nfad)
{
   return nfq_get_nfmark(nfad) | VMW_NFQ_PKT_MARK;
}

/* Log ipv4 address */
void
vmw_log_ipv4_address(struct sockaddr_in *addr)
{
   char dst[INET_ADDRSTRLEN] = {0};

   if (!addr) {
      goto exit;
   }

   inet_ntop(AF_INET,
             (const void *)&addr->sin_addr,
             dst,
             INET_ADDRSTRLEN);

   DEBUG("addr: %s, port: %u\n", dst, addr->sin_port);

exit:
   return;
}

/* Log ipv6 address */
void
vmw_log_ipv6_address(struct sockaddr_in6 *addr)
{
   char dst[INET6_ADDRSTRLEN] = {0};

   if (!addr) {
      goto exit;
   }

   inet_ntop(AF_INET6,
             (const void *)&addr->sin6_addr,
             dst,
             INET6_ADDRSTRLEN);
   DEBUG("addr: %s, port: %u\n", dst, addr->sin6_port);

exit:
   return;
}

/*
 * Deduce inbound/outbound event type based on network hook embedded in packet
 * header
 */
enum vmw_conn_event_type
get_event_type(struct nfq_data *nfa)
{
   struct nfqnl_msg_packet_hdr *ph;
   uint32_t index;
   enum nf_inet_hooks hook;
   enum vmw_conn_event_type ret = MAX_EVENT;

   if (!nfa) {
      goto exit;
   }

   /* Get the nfq message packet header */
   ph = nfq_get_msg_packet_hdr(nfa);
   if (NULL == ph) {
      goto exit;
   }
   hook = ph->hook;

   /*
    * The index of the device the queued packet was received via.
    * If the returned index is 0, the packet was locally generated or the input
    * interface is not known (i.e. POSTROUTING)
    */
   index = nfq_get_indev(nfa);
   if (index && (NF_INET_LOCAL_IN == hook)) {
      ret = INBOUND_PRECONNECT;
      goto exit;
   }

   /*
    * The index of the device the queued packet will be sent out.  If the
    * returned index is 0, the packet is destined for localhost or the output
    * interface is not yet known (ie. PREROUTING?).
    */
   index = nfq_get_outdev(nfa);
   if (index && (NF_INET_LOCAL_OUT == hook)) {
      ret = OUTBOUND_PRECONNECT;
      goto exit;
   }

   DEBUG("Packet received for invalid hook %d", (int)hook);

exit:
   return ret;
}

void
vmw_process_global_packet(uint32_t event_id,
                          int verdict,
                          struct vmw_net_session *sess)
{
   global_packet_info *global_packet = NULL;
   gpointer gkey = NULL;
   gpointer gvalue = NULL;
   uint32_t mark;

   pthread_mutex_lock(&global_pkthash_lock);
   g_hash_table_lookup_extended(global_queued_pkthash,
                                GUINT_TO_POINTER(event_id),
                                &gkey,
                                &gvalue);
   pthread_mutex_unlock(&global_pkthash_lock);

   if (gvalue == NULL) {
      return;
   }
   global_packet = (global_packet_info*) gvalue;
   /*
    * To prevent races with conn_data_send, take the packet
    * lock. This ensures the first recv for a packet is not
    * processed till all clients have been sent the packet.
    */
   pthread_mutex_lock(&global_packet->lock);

   /*
    * Verdict is sent either when the packet reference count is one
    * or when verdict of any client is NF_DROP
    */
   if ((1 == global_packet->ref_count) ||
       (verdict == NF_DROP)) {
      mark = global_packet->mark;
      pthread_mutex_unlock(&global_packet->lock);

      pthread_mutex_lock(&global_pkthash_lock);
      g_hash_table_remove(global_queued_pkthash,
                          GUINT_TO_POINTER(event_id));
      pthread_mutex_unlock(&global_pkthash_lock);

      pthread_mutex_lock(&sess->queue_lock);
      nfq_set_verdict2(sess->queue_ctx.qhandle,
                       event_id,
                       verdict,
                       mark,
                       0,
                       NULL);
      pthread_mutex_unlock(&sess->queue_lock);
   } else {
      /*
       * Don't send verdict as this packet is being processed by other
       * client, just reduce reference count in the global packet hash
       * table
       */
      global_packet->ref_count--;
      pthread_mutex_unlock(&global_packet->lock);
   }
   return;
}

/*
 * Release packet queued in netfilter NFQUEUE. This is called during client
 * disconnect.
 * Per client queued_pkthash contains packets that are delivered to the client
 * but response for them has not been come yet from the client so during
 * client disconnect, verdict for these packets are send to netfilter
 * library. On getting the verdict, netfilter library clears in-kernel data
 * structure for the packets.
 */
void
vmw_queued_pkthash_cleanup(struct vmw_net_session *sess,
                           struct vmw_client_scope *client_ptr)
{
   GHashTableIter iter;
   gpointer key = NULL;
   gpointer value = NULL;
   uint32_t event_id;

   g_hash_table_iter_init(&iter, client_ptr->queued_pkthash);
   while (g_hash_table_iter_next(&iter, &key,  &value)) {
      event_id = GPOINTER_TO_UINT(key);
      if (!value) {
         continue;
      }
      vmw_process_global_packet(event_id, NF_REPEAT, sess);

      g_hash_table_iter_remove(&iter);
   }

   return;
}

/* A client has disconnected, cleanup all related data structures */
void
vmw_client_cleanup(struct vmw_net_session *sess, int idx)
{
   int sd = 0;

   pthread_mutex_lock(&g_client_ctx[idx].client_sock_lock);
   sd = g_client_ctx[idx].client_sockfd;
   close(g_client_ctx[idx].client_sockfd);
   /*
    * Invalidate fd so send() adds no more packets to the
    * client hashtable
    */
   g_client_ctx[idx].client_sockfd = -1;
   g_client_ctx[idx].pkthash_cleanup_wait = 1;
   pthread_mutex_unlock(&g_client_ctx[idx].client_sock_lock);

   /*
    * Cleanup the client hashtable and references to this client
    * in the global hashtable.
    */
   vmw_queued_pkthash_cleanup(sess, &g_client_ctx[idx]);

   /* Cleanup completed, this index can be reused now */
   pthread_mutex_lock(&g_client_ctx[idx].client_sock_lock);
   g_client_ctx[idx].pkthash_cleanup_wait = 0;
   pthread_mutex_unlock(&g_client_ctx[idx].client_sock_lock);

   WARN("Client %d disconnected", sd);
   return;
}

/* Receive message from client and forward verdict back to netfilter NFQUEUE */
void *
vmw_client_msg_recv(void *arg)
{
   struct vmw_net_session *sess = (struct vmw_net_session *)arg;
   global_packet_info *global_packet = NULL;
   gpointer key;
   gpointer value = NULL;
   vmw_verdict client_verdict = { 0 };
   fd_set client_fds;
   int sd, max_sd, i, activity, ret;

   while (1) {
      if (ATOMIC_OR(&g_need_to_quit, 0)) {
         break;
      }
      /*
       * Only this thread frees client related
       * data structures so no need to hold a client_sock_lock
       */
      max_sd = 0;
      FD_ZERO(&client_fds);
      for (i = 0 ; i < MAX_CLIENTS; i++) {
         sd = g_client_ctx[i].client_sockfd;
         if (sd > 0) {
            FD_SET(sd, &client_fds);
            if (sd > max_sd) {
               max_sd = sd;
            }
         }
      }
      /*
       * vmw_wait_for_event() returns when
       * 1. graceful shutdown is initiated;
       * 2. client response is received for the packet delivered earlier;
       * 3. new client connection is formed or an established client connection
       * is disconnected.
       */
      activity = vmw_wait_for_event(max_sd, &client_fds, 1);
      if (activity <= 0)  {
           continue;
      }
      for (i = 0; i < MAX_CLIENTS; i++)  {
         sd = g_client_ctx[i].client_sockfd;
         if (sd < 0) {
            continue;
         }
         /* Data received or socket has been closed */
         if (FD_ISSET(sd , &client_fds)) {
            ret = recv(sd, (void *)&client_verdict, sizeof(client_verdict), 0);
            if (!ret) {
               /*
                * Client got disconneted, so release packets queued in netfilter
                * NFQUEUE.
                */
               vmw_client_cleanup(sess, i);
               continue;
            }
            if (!client_verdict.packetId) {
               continue;
            }
            if (client_verdict.verdict != NF_DROP) {
               client_verdict.verdict = NF_REPEAT;
            }
            vmw_process_global_packet(client_verdict.packetId,
                                      client_verdict.verdict,
                                      sess);

            pthread_mutex_lock(&g_client_ctx[i].client_sock_lock);
            g_hash_table_remove(g_client_ctx[i].queued_pkthash,
                                GUINT_TO_POINTER(client_verdict.packetId));
            pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);

         }
      }
   }

exit:
   return NULL;
}

/* Deliver network event to the connected clients */
int
vmw_conn_data_send(struct vmw_conn_identity_data *conn_data,
                   uint32_t packet_mark)
{
   global_packet_info *global_packet = NULL;
   gpointer key;
   gpointer value = NULL;
   int i, sd;
   int ret = 0, refcnt = 0;
   uint32_t mark = 0;

   /*
    * The event id of each contrack event is zero. The conntrack event
    * is just a notification; there is no response required for the
    * conntrack event.
    */
   if (conn_data->event_id) {
      /*
       * Init and add a global packet for this conn_data
       * to the hashtable
       */
      global_packet = (global_packet_info *)
               malloc(sizeof(global_packet_info));
      if (NULL == global_packet) {
         ret = -1;
         ERROR("Failed to allocate global packet info");
         goto exit;
      }
      global_packet->event_id = conn_data->event_id;
      global_packet->ref_count = 0;
      global_packet->mark = packet_mark;
      pthread_mutex_init(&global_packet->lock, NULL);
      pthread_mutex_lock(&global_pkthash_lock);
      g_hash_table_replace(global_queued_pkthash,
                           GUINT_TO_POINTER(conn_data->event_id),
                           (gpointer)global_packet);
      pthread_mutex_unlock(&global_pkthash_lock);
      /*
       * Need to hold the packet lock till we finish
       * sending this packets to all clients. We don't want
       * process the recv from a client till we have finished sending
       * it to all clients as the race will make the refcounts
       * go wrong.
       */
      pthread_mutex_lock(&global_packet->lock);
   }

   for (i = 0; i < MAX_CLIENTS; i++)  {
      pthread_mutex_lock(&g_client_ctx[i].client_sock_lock);
      if (g_client_ctx[i].client_sockfd < 0) {
         pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);
         continue;
      }
      sd = g_client_ctx[i].client_sockfd;

      if (conn_data->event_id) {
         g_hash_table_replace(g_client_ctx[i].queued_pkthash,
                              GUINT_TO_POINTER(conn_data->event_id),
                              NULL);
      }
      pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);

      ret = send(sd, conn_data, sizeof(*conn_data), 0);
      if (ret <= 0) {
         ERROR("Could not send event %u to client %d (error %s)",
               conn_data->event_id, sd, strerror(errno));
         /* Cleanup will be done by recv */
         continue;
      }

      /*
       * Send message successfully to client, update the global
       * packet, only if this is not a conntrack event.
       */
      if (conn_data->event_id) {
         global_packet->ref_count++;
      }
   }

exit:
   if (global_packet) {
      refcnt = global_packet->ref_count;
      pthread_mutex_unlock(&global_packet->lock);
      /*
       * No clients were sent this packet, remove it from the hash
       */
      if (refcnt == 0) {
         pthread_mutex_lock(&global_pkthash_lock);
         g_hash_table_remove(global_queued_pkthash,
                             GUINT_TO_POINTER(conn_data->event_id));
         pthread_mutex_unlock(&global_pkthash_lock);
      }
   }
   return ret;
}

/* Log connection related data and sends the data to client */
int
vmw_client_notify(struct vmw_conn_identity_data *conn_data,
                  struct vmw_net_session *sess,
                  uint32_t packet_mark)
{
   int ret = -1;

   if (!conn_data || !sess) {
      goto exit;
   }

   if ((AF_INET == conn_data->src.ss_family) &&
       (AF_INET == conn_data->dst.ss_family)) {
      vmw_log_ipv4_address((struct sockaddr_in *)&conn_data->src);
      vmw_log_ipv4_address((struct sockaddr_in *)&conn_data->dst);
   } else if ((AF_INET6 == conn_data->src.ss_family) &&
              (AF_INET6 == conn_data->dst.ss_family)) {
      vmw_log_ipv6_address((struct sockaddr_in6 *)&conn_data->src);
      vmw_log_ipv6_address( (struct sockaddr_in6 *)&conn_data->dst);
   } else {
      goto exit;
   }

   ret = vmw_conn_data_send(conn_data, packet_mark);

exit:
   return ret;
}

/*
 * Receive the network event notification from conntrack and NFQUEUE and
 * process it.
 */
void *
vmw_netfilter_event_handler(void *arg)
{
   char buf[VNET_BUFSIZE] __attribute__ ((aligned));
   struct vmw_net_session *sess = (struct vmw_net_session *)arg;
   ssize_t bread = 0;
   int maxfd, status = 0;
   fd_set session_fds, master;

   if (!sess) {
      status = 1;
      goto exit;
   }

   /* Clear the file descriptor set that to be monitored by select */
   FD_ZERO(&session_fds);
   /* Add queue FD to FD set to be monitored by select for notificaton */
   FD_SET(sess->queue_ctx.qfd, &session_fds);
   /* Add conntrack FD to FD set to be monitored by select for notificaton */
   FD_SET(sess->conntrack_ctx.ctfd, &session_fds);

   master = session_fds;
   maxfd = sess->conntrack_ctx.ctfd;
   /* Keep track of the biggest file descriptor */
   if (maxfd < sess->queue_ctx.qfd) {
      maxfd  = sess->queue_ctx.qfd;
   }

   while (1) {
      if (ATOMIC_OR(&g_need_to_quit, 0)) {
         break;
      }

      /*
       * Copy the master set back to readfds set so that both descriptors can be
       * monitored again for any notification
       */
      session_fds = master;
      status = vmw_wait_for_event(maxfd, &session_fds, 0);
      /* select() is used to receive events from conntrack and nfqueue */
      if (-1 == status) {
         if (EINTR == errno) {
            continue;
         }
         ERROR("Failed to read from netfilter channel, select failure error %s",
               strerror(errno));
         goto exit;
      } else if (0 == status) {
         continue;
      }

      if (FD_ISSET(sess->queue_ctx.qfd, &session_fds)) {
         /* Read the packet from the netlink socket which is in NFQUEUE */
         bread = recv(sess->queue_ctx.qfd, buf, sizeof(buf), 0);
         if (bread > 0) {
            pthread_mutex_lock(&sess->queue_lock);
            nfq_handle_packet(sess->queue_ctx.handle, buf, bread);
            pthread_mutex_unlock(&sess->queue_lock);
         }

        /*
         * To avoid ENOBUFS error , queue max length is increased with
         * nfq_set_queue_maxlen as per the netfilter documentation
         */
         if ((bread < 0) && (ENOBUFS == errno)) {
            ERROR("Dropping packets due to insufficient memory!\n");
            continue;
         }
      }

      if (FD_ISSET(sess->conntrack_ctx.ctfd, &session_fds)) {
         /* Read connection state from kernel connection table */
         status = nfct_catch(sess->conntrack_ctx.cthandle);
      }
   }

exit:
   return NULL;
}

/*
 * Callback to handle the received conntrack events in nfct_catch thread
 * context.
 */
static int
vmw_net_conntrack_callback(enum nf_conntrack_msg_type type,
                           struct nf_conntrack *ct,
                           void *data)
{
   struct vmw_conn_identity_data *conn_data = NULL;
   struct vmw_net_session *sess = (struct vmw_net_session *)data;
   uint8_t family;
   char state;

   /* Ignore all TCP states other than ESTABLISH, Close, Last Ack, Time Wait */
   state = nfct_get_attr_u8(ct, ATTR_TCP_STATE);
   if ((state != TCP_CONNTRACK_CLOSE) &&
       (state != TCP_CONNTRACK_TIME_WAIT) &&
       (state != TCP_CONNTRACK_LAST_ACK) &&
       (state != TCP_CONNTRACK_ESTABLISHED)) {
      goto exit;
   }

   conn_data = (struct vmw_conn_identity_data *)
           malloc(sizeof(struct vmw_conn_identity_data));
   if (!conn_data) {
      ERROR("Memory allocation failed for msg data");
      goto exit;
   }

   /* Retrieve L3 protocol address and L4 protocol port number */
   family = nfct_get_attr_u8(ct, ATTR_L3PROTO);
   switch(family) {
   case AF_INET:
      conn_data->src.ss_family = AF_INET;
      conn_data->dst.ss_family = AF_INET;
      struct sockaddr_in *src = (struct sockaddr_in *)&conn_data->src;
      struct sockaddr_in *dst = (struct sockaddr_in *)&conn_data->dst;
      src->sin_addr.s_addr = nfct_get_attr_u32(ct, ATTR_IPV4_SRC);
      dst->sin_addr.s_addr = nfct_get_attr_u32(ct, ATTR_IPV4_DST);
      src->sin_port = htons(nfct_get_attr_u32(ct, ATTR_PORT_SRC));
      dst->sin_port = htons(nfct_get_attr_u32(ct, ATTR_PORT_DST));
      break;

   case AF_INET6:
      conn_data->src.ss_family = AF_INET6;
      conn_data->dst.ss_family = AF_INET6;
      struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)&conn_data->src;
      struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&conn_data->dst;
      memcpy(&src6->sin6_addr.s6_addr,
             nfct_get_attr(ct, ATTR_IPV6_SRC),
             sizeof(uint32_t) * 4);
      memcpy(&dst6->sin6_addr.s6_addr,
             nfct_get_attr(ct, ATTR_IPV6_DST),
             sizeof(uint32_t) * 4);
      src6->sin6_port = htons(nfct_get_attr_u32(ct, ATTR_PORT_SRC));
      dst6->sin6_port = htons(nfct_get_attr_u32(ct, ATTR_PORT_DST));
      break;

   default:
      DEBUG("Invalid protocol family %uhh", family);
      goto exit;
   }

   if (TCP_CONNTRACK_ESTABLISHED == state) {
      conn_data->event_type = POSTCONNECT;
   } else {
      conn_data->event_type = DISCONNECT;
   }
   conn_data->event_id = 0;

   /* Send the packet to client */
   (void)vmw_client_notify(conn_data, sess, 0);

exit:
   if (conn_data) {
      free(conn_data);
      conn_data = NULL;
   }
   /* Break nfct_catch loop as process is being stopped */
   if (ATOMIC_OR(&g_need_to_quit, 0)) {
      return NFCT_CB_STOP;
   }
   return NFCT_CB_CONTINUE;
}

/* Register callback with conntrack to receive network events */
int
vmw_net_conntrack_init(void *arg)
{
   struct nfct_handle *h;
   struct nfct_filter *filter;
   struct vmw_net_session *sess = (struct vmw_net_session *)arg;
   int flags, ret = 0;

   if (!sess) {
      ret = -1;
      goto exit;
   }

   h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_UPDATE);
   if (!h) {
      ERROR("Error %s during nfct_open()", strerror(errno));
      ret = -1;
      goto exit;
   }

   filter = nfct_filter_create();
   if (!filter) {
      ERROR("Error %s during nfct_create_filter", strerror(errno));
      ret = -1;
      goto exit;
   }

   nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_TCP);
   nfct_filter_add_attr_u32(filter, NFCT_FILTER_L4PROTO, IPPROTO_UDP);

   /* Instruct conntrack to deliver IPv4 events in host-byte order */
   struct nfct_filter_ipv4 filter_ipv4 = {
      .addr = ntohl(inet_addr(VMW_LOOPBACK_ADDRESS)),
      .mask = VMW_LOOPBACK_MASK,
   };

   /* Ignore whatever that comes from 127.0.0.1 */
   nfct_filter_set_logic(filter,
                         NFCT_FILTER_SRC_IPV4,
                         NFCT_FILTER_LOGIC_NEGATIVE);
   nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV4, &filter_ipv4);

   /* Instruct conntrack to deliver IPv6 events in host-byte order */
   struct nfct_filter_ipv6 filter_ipv6 = {
      .addr = { 0x0, 0x0, 0x0, 0x1 },
      .mask = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff },
   };

   /* Ignore whatever that comes from ::1 (loopback) */
   nfct_filter_set_logic(filter,
                         NFCT_FILTER_SRC_IPV6,
                         NFCT_FILTER_LOGIC_NEGATIVE);
   nfct_filter_add_attr(filter, NFCT_FILTER_SRC_IPV6, &filter_ipv6);

   ret = nfct_filter_attach(nfct_fd(h), filter);
   if (-1 == ret) {
      ERROR("Error %s during nfct_filter_attach", strerror(errno));
      goto exit;
   }

   /* Register a callback with netfilter conntrack library */
   ret = nfct_callback_register(h,
                                NFCT_T_ALL,
                                vmw_net_conntrack_callback,
                                (void *)sess);
   if (-1 == ret) {
      ERROR("Error %s during nfct_callback_register", strerror(errno));
      goto exit;
   }
   sess->conntrack_ctx.cthandle = h;
   sess->conntrack_ctx.ctfd = nfct_fd(h);

   /* Make conntack fd as non-blocking fd so that it can be passed to select */
   flags = fcntl(sess->conntrack_ctx.ctfd, F_GETFL, 0);
   if (-1 == ret) {
      ERROR("Error %s during fctnl while accessing flag", strerror(errno));
      goto exit;
   }

   ret = fcntl(sess->conntrack_ctx.ctfd, F_SETFL, flags | O_NONBLOCK);
   if (-1 == ret) {
      ERROR("Error %s during fctnl while setting flag", strerror(errno));
      goto exit;
   }

exit:
   if (filter) {
      nfct_filter_destroy(filter);
      filter = NULL;
   }
   return ret;
}

/*
 * A callback which gets invoked in the context of receiver thread from
 * nfq_handle_packet function
 */
static int
vmw_net_queue_callback(struct nfq_q_handle *qh,
                       struct nfgenmsg *nfmsg,
                       struct nfq_data *nfa,
                       void *arg)
{
   struct nfqnl_msg_packet_hdr *ph;
   struct iphdr *ipinfo = NULL;
   struct ip6_hdr *ip6info = NULL;
   struct tcphdr *tcp_info = NULL;
   struct udphdr *udp_info = NULL;
   struct vmw_conn_identity_data *conn_data = NULL;
   struct vmw_net_session *sess = (struct vmw_net_session*)arg;
   int ret = -1;
   int status = 0;
   enum vmw_conn_event_type event_type = 0;
   unsigned char *data = NULL;
   uint32_t event_id;
   uint32_t packet_mark;

   sess = vmw_net_sess_handle;
   if (!nfa|| !sess) {
      ret = -1;
      goto exit;
   }

   conn_data = (struct vmw_conn_identity_data *)
           malloc(sizeof(struct vmw_conn_identity_data));
   if (!conn_data) {
      ERROR("Memory allocation failed for msg data");
      status = ENOMEM;
      ret = -1;
      goto exit;
   }

   ph = nfq_get_msg_packet_hdr(nfa);
   if (ph) {

      /* event_id is identified with packet_id */
      event_id = ntohl(ph->packet_id);
      DEBUG("hw_protocol=0x%04x, hook=%u, id=%u", ntohs(ph->hw_protocol),
           ph->hook, event_id);
      conn_data->event_id = event_id;
   }

   ret = nfq_get_payload(nfa, &data);
   if (-1 == ret || ret > VNET_BUFSIZE) {
      ERROR("Invalid packet length: %d, packet id: %u", ret, event_id);
      ret = -1;
      goto exit;
   }

   /* Get the iphdr from the payload */
   ipinfo = (struct iphdr *)data;

   if (IPVERSION == ipinfo->version) {
      conn_data->src.ss_family = AF_INET;
      conn_data->dst.ss_family = AF_INET;
      struct sockaddr_in *src = (struct sockaddr_in *)&conn_data->src;
      struct sockaddr_in *dst = (struct sockaddr_in *)&conn_data->dst;
      src->sin_addr.s_addr = ipinfo->saddr;
      dst->sin_addr.s_addr = ipinfo->daddr;

      if (IPPROTO_TCP == ipinfo->protocol) {
         /* Get the tcphdr from the payload */
         tcp_info = (struct tcphdr *)(data + sizeof(*ipinfo));
         src->sin_port = ntohs(tcp_info->source);
         dst->sin_port = ntohs(tcp_info->dest);
      } else if (IPPROTO_UDP == ipinfo->protocol) {
         /* Get the tcphdr from the payload */
         udp_info = (struct udphdr *)(data + sizeof(*ipinfo));
         src->sin_port = ntohs(udp_info->source);
         dst->sin_port = ntohs(udp_info->dest);
      } else {
         INFO("Non tcp/ip traffic: %d, id=%u", ipinfo->protocol, event_id);
         ret = -1;
         goto exit;
      }
      conn_data->protocol = ipinfo->protocol;
      vmw_log_ipv4_address((struct sockaddr_in *)src);
      vmw_log_ipv4_address((struct sockaddr_in *)dst);
   } else {
      ip6info = (struct ip6_hdr *)data;
      conn_data->src.ss_family = AF_INET6;
      conn_data->dst.ss_family = AF_INET6;
      struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)&(conn_data->src);
      struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)&(conn_data->dst);

      if (IPPROTO_TCP == ip6info->ip6_nxt) {
         tcp_info = (struct tcphdr *)(data + sizeof(*ip6info));
         src6->sin6_port = ntohs(tcp_info->source);
         dst6->sin6_port = ntohs(tcp_info->dest);

      } else if (IPPROTO_UDP == ip6info->ip6_nxt) {
         udp_info = (struct udphdr *)(data + sizeof(*ip6info));
         src6->sin6_port = ntohs(udp_info->source);
         dst6->sin6_port = ntohs(udp_info->dest);
      } else {
         INFO("Non tcp/ipv6 traffic: %d, id=%u", ip6info->ip6_nxt, event_id);
         ret = -1;
         goto exit;
      }
      memcpy(src6->sin6_addr.s6_addr,
             ip6info->ip6_src.s6_addr,
             16);
      memcpy(dst6->sin6_addr.s6_addr,
             ip6info->ip6_dst.s6_addr,
             16);

      conn_data->protocol = ip6info->ip6_nxt;
   }

   event_type = get_event_type(nfa);

   /* Don't add packet depicting invalid tcp state  to the thread pool queue */
   if (tcp_info) {
      if ((!tcp_info->syn) || (tcp_info->ack)) {
         DEBUG("Invalid tcp packet, ignoring packet: id=%u", event_id);
         ret = -1;
         goto exit;
      }
   }

   /* Don't add packet received on invalid hook to the thread pool queue */
   if (0 == event_type) {
      INFO("Invalid event type, ignoring packet: id=%u", event_id);
      ret = -1;
      goto exit;
   }

   /* Mark the packet with our mark */
   packet_mark = update_packet_mark(nfa);

   conn_data->event_type = event_type;
   conn_data->event_id = event_id;

   /* Deliver packet to client */
   ret = vmw_client_notify(conn_data, sess, packet_mark);
   if (ret <= 0) {
      goto exit;
   }

   DEBUG("Event %u is queued for delivery, packet id=%u",
          event_type, event_id);

exit:
   /* If there are no clients connected ret = 0 */
   if (ret <= 0 && sess) {
      /*
       * Re-inject the packet by providing NF_REPEAT verdict with mask bit set
       * so that the packet can be iterated through rest of the rules in the
       * ip chain.
       */
      nfq_set_verdict2(sess->queue_ctx.qhandle,
                      event_id,
                      NF_REPEAT,
                      packet_mark,
                      0,
                      NULL);
   }

   if (conn_data) {
      free(conn_data);
   }
   return ret;
}

/* Register callback with netfilter Queue library */
int
vmw_net_queue_init(struct vmw_net_session *sess)
{
   int ret = 0;
   struct nfq_q_handle *qh;

   if (!sess) {
      ret = -1;
      goto exit;
   }
   sess->queue_ctx.handle = nfq_open();
   if (!sess->queue_ctx.handle) {
      ERROR("Error %s during nfq_open()", strerror(errno));
      ret = -1;
      goto exit;
   }

   ret = nfq_unbind_pf(sess->queue_ctx.handle, AF_INET);
   if (ret < 0) {
      ERROR("Error %s during nfq_unbind_pf() with AF_INET", strerror(errno));
      goto exit;
   }
   ret = nfq_bind_pf(sess->queue_ctx.handle, AF_INET);
   if (ret < 0) {
      ERROR("Error %s  during nfq_bind_pf() with AF_INET", strerror(errno));
      goto exit;
   }

   ret = nfq_unbind_pf(sess->queue_ctx.handle, AF_INET6);
   if (ret < 0) {
      ERROR("Error %s during nfq_unbind_pf() with AF_INET6", strerror(errno));
      exit(1);
   }
   ret = nfq_bind_pf(sess->queue_ctx.handle, AF_INET6);
   if (ret < 0) {
      ERROR("Error %s during nfq_bind_pf() with AF_INET6", strerror(errno));
      goto exit;
   }

   qh = nfq_create_queue(sess->queue_ctx.handle,
                         0,
                         &vmw_net_queue_callback,
                         NULL);
   if (!qh) {
      ERROR("Error %s during nfq_create_queue()", strerror(errno));
      ret = -1;
      goto exit;
   }

   pthread_mutex_init(&sess->queue_lock, NULL);
   ret = nfq_set_mode(qh, NFQNL_COPY_PACKET, VNET_BUFSIZE);
   if (ret < 0) {
      ERROR("Error %s during nfq_set_mode", strerror(errno));
      goto exit;
   }

   /* Set kernel queue maximum length to handle connection burst */
   ret = nfq_set_queue_maxlen(qh, VNET_NFQLENGTH);
   if (ret < 0) {
      ERROR("Error %s during nfq_set_queue_maxlen()", strerror(errno));
      ret = 0;
      /* don't fail, continue */
   }

   sess->queue_ctx.qhandle = qh;
   sess->queue_ctx.qfd = nfq_fd(sess->queue_ctx.handle);

exit:

  /*
    * Clean-up is done by vmw_net_cleaup() which is executed in the main thread
    * context after the completion of vsetNetUserInit thread.
    */
   return ret;
}

/*
 * Unregister with netfilter conntrack library; close conntrack library and
 * netfilter queue library handle and lock.
 */
void
vmw_net_cleanup(struct vmw_net_session *sess)
{
   if (!sess) {
      goto exit;
   }

   /* Unregister conntrack callback and close handle */
   if (sess->conntrack_ctx.cthandle) {
      nfct_callback_unregister(sess->conntrack_ctx.cthandle);
      nfct_close(sess->conntrack_ctx.cthandle);
   }

   /* Close netfilter queue library handle */
   if (sess->queue_ctx.handle) {
      nfq_close(sess->queue_ctx.handle);
   }
   if (sess->queue_ctx.qhandle) {
      nfq_destroy_queue(sess->queue_ctx.qhandle);
      pthread_mutex_destroy(&sess->queue_lock);
   }

exit:
   return;
}

/*
 * Register with notification framework and wait for network event notification
 * and process them on reception. This is invoked during thread creation and
 * executed in a thread contex`.
 */
void *
vmw_init(void *arg)
{
   pthread_t client_msg_recv_thread;
   pthread_t netfilter_event_handler_thread;
   int ret;

   vmw_net_sess_handle = (struct vmw_net_session *)
           malloc( sizeof(struct vmw_net_session));
   if (!vmw_net_sess_handle) {
      ERROR("Failed to allocate memory for vnet session");
      goto exit;
   }

   /* Register a callback with netfilter queue library */
   if (vmw_net_queue_init(vmw_net_sess_handle) < 0) {
      ERROR("Error in intialising netfilter queue library handle");
      goto exit;
   }

   /* Register a callback with netfilter conntrack library */
   if (vmw_net_conntrack_init(vmw_net_sess_handle) < 0) {
      ERROR("Error in intialising netfilter conntrack library handle");
      goto exit;
   }

   ATOMIC_OR(&g_vmw_init_done, 1);
   INFO("%s is running", PROG_NAME);

   ret = pthread_create(&client_msg_recv_thread,
                        NULL,
                        vmw_client_msg_recv,
                        (void *)vmw_net_sess_handle);
   if (0 != ret) {
      ERROR("Could not create vmw_client_msg_recv thread");
      goto exit;
   }

   /* Process notfilcation received from netfilter libraries */
   ret = pthread_create(&netfilter_event_handler_thread,
                        NULL,
                        vmw_netfilter_event_handler,
                        (void *)vmw_net_sess_handle);
   if (0 != ret) {
      ERROR("Could not create vmw_netfilter_event_handler thread");
      vmw_notify_exit();
      pthread_join(client_msg_recv_thread, NULL);
      goto exit;
   }

   pthread_join(client_msg_recv_thread, NULL);
   pthread_join(netfilter_event_handler_thread, NULL);

exit:
   vmw_net_cleanup(vmw_net_sess_handle);

   /* Free struct vmw_net_session */
   if (vmw_net_sess_handle) {
      free(vmw_net_sess_handle);
      vmw_net_sess_handle = NULL;
   }
   return NULL;
}

