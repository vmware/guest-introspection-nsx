#ifndef VMW_CONN_H
#define VMW_CONN_H
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
 * vmw_conn.h contains data structures/definitions for interaction with clients
 * (consumer of network events).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/types.h>
#ifdef _x86_64
#include <asm-x86_64/types.h>
#endif

#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <glib.h>
#include <pthread.h>

#define ATOMIC_OR(var, value)   __sync_or_and_fetch((var), (value))

#define LOG_MSG(level, str, fmt, ...)  \
        syslog(level, "%s: %s: " fmt, str, __FUNCTION__, ##__VA_ARGS__)

#define INFO(fmt, ...) LOG_MSG(LOG_INFO, "INFO", fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG_MSG(LOG_WARNING, "WARN", fmt, ##__VA_ARGS__)
#define ERROR(fmt, ...) LOG_MSG(LOG_ERR, "ERROR", fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...) LOG_MSG(LOG_DEBUG, "DEBUG", fmt, ##__VA_ARGS__)
#define NOTICE(fmt, ...) LOG_MSG(LOG_NOTICE, "NOTICE", fmt, ##__VA_ARGS__)

#define PROG_NAME "vmw_conn_notfiy"

/* Maximum number of supported client */
#define MAX_CLIENTS 1

/* Network event Type */
enum vmw_conn_event_type {
   OUTBOUND_PRECONNECT = 1,            /* Outgoing connection initiation*/
   POSTCONNECT,                        /* Established connection */
   DISCONNECT,                         /* Disconnected connetion */
   INBOUND_PRECONNECT,                 /* Incoming connection inititation */
   MAX_EVENT,
};

/* Network connection identification related data */
struct vmw_conn_identity_data {
   struct sockaddr_storage src;           /* Source ip */
   struct sockaddr_storage dst;           /* Destination ip */
   enum vmw_conn_event_type event_type;   /* Network connection type */
   uint32_t event_id;                     /* Event id */
   uint8_t protocol;                      /* L3 protocol */
};

struct vmw_client_scope {
   int client_sockfd;
   pthread_mutex_t client_sock_lock;   /* Lock to sync nfq send/recv packets */
   int client_version;                 /* Client version */
   GHashTable *queued_pkthash;         /* Hash table to store packets queued for
                                        verdict */
   uint8_t pkthash_cleanup_wait;       /* Wait for completion of on-going
                                          pkthash clean */
   int  client_mark;                   /* client specified mark to be set in
                                          verdict*/
};

/* Packet info from client */
typedef struct _vmw_verdict {
   int packetId;
   int verdict;
} vmw_verdict;

/* version and mark info per client */
typedef struct clientInfo {
   int version;
   int mark;
}clientInfo;
#endif
