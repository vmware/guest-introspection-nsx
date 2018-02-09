
# Copyright (C) 2018 VMware, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published
# by the Free Software Foundation; version 2. 
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA.
#

#
# SPDX-License-Identifier: GPL-2.0-only
#
default: vmw_conn_oss

all: vmw_conn_oss install

INCLUDES=-I./include/ -I/usr/include

ifndef LIB_NETFILTER_INCLUDE
LIB_NETFILTER_INCLUDE=-I/usr/src/debug/libnetfilter_conntrack-1.0.6/include/
endif

GLIB_INCLUDES=-I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include/ $(LIB_NETFILTER_INCLUDE) 
CFLAGS=$(INCLUDES) $(GLIB_INCLUDES)
VMW_OPEN_LIBNETFLT_OBJS=-L/usr/lib64/,/usr/lib/x86_64-linux-gnu/lib, \
								 -lmnl -lnfnetlink -lpthread\
								 -lnetfilter_queue -lnetfilter_conntrack -lglib-2.0

###############################
# vmw_conn_notify open source
###############################
NET_OPEN_SOURCE =\
		   ./vmw_conn_main.c \
		   ./vmw_conn_netfilter.c


VMW_OPEN_SOURCE_OBJS=\
		      ./vmw_conn_main.o \
		      ./vmw_conn_netfilter.o

vmw_conn_oss:   $(VMW_OPEN_SOURCE_OBJS)
	$(CC) $(CC_DEBUG_OPTS) $(CC_WARNINGS) $(CC_OPTS) $(INCLUDES) \
	$(GLIB_INCLUDES) -o \
	./vmw_conn_notify \
	$(VMW_OPEN_SOURCE_OBJS) \
	$(LDFLAGS) \
	$(VMW_OPEN_LIBNETFLT_OBJS) \
	$(CC_LIB_PATHS) \

install:
	mkdir -p /etc/vmw_conn_notify
	cp ./vmw_conn_notify.conf /etc/vmw_conn_notify/
	cp ./vmw_conn_notifyd /etc/init.d/
	chmod 755 /etc/init.d/vmw_conn_notifyd
	cp ./vmw_conn_notify /usr/sbin/
	chmod 755 /usr/sbin/vmw_conn_notify

clean:
	rm *.o
	rm vmw_conn_notify 
