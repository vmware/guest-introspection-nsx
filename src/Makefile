
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

MKFILE := $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))
SRCDIR := $(dir $(abspath $(MKFILE)))
SRCROOT := $(SRCDIR:%/=%)

default: vmw_conn_oss

all: vmw_conn_oss install

ifndef LIB_NETFILTER_INCLUDE
LIB_NETFILTER_INCLUDE := -I/usr/src/debug/libnetfilter_conntrack-1.0.6/include
endif

CC := gcc

GLIB_INCLUDES := -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

INCLUDES := \
	-I./include/ \
	-I/usr/include \
	-I/usr/lib/x86_64-linux-gnu/glib-2.0/include \
	$(GLIB_INCLUDES) \
	$(LIB_NETFILTER_INCLUDE)

CFLAGS := -Wall -Wextra -Werror -Wno-unused-parameter -g $(INCLUDES)

LDFLAGS := \
	-L/usr/lib64/ \
	-L/usr/lib/x86_64-linux-gnu/lib \
	-lpthread \
	-lglib-2.0 \
	-lmnl \
	-lnfnetlink \
	-lnetfilter_queue \
	-lnetfilter_conntrack

VMW_OPEN_SOURCE_BIN := $(SRCROOT)/vmw_conn_notify

VMW_INSTALL_CONFDIR := /etc/vmw_conn_notify
VMW_INSTALL_INITDIR := /etc/init.d

###############################
# vmw_conn_notify open source
###############################
VMW_OPEN_SOURCE_SRCS := \
	$(SRCROOT)/vmw_conn_main.c \
	$(SRCROOT)/vmw_conn_netfilter.c

VMW_OPEN_SOURCE_OBJS := \
	$(SRCROOT)/vmw_conn_main.o \
	$(SRCROOT)/vmw_conn_netfilter.o

$(VMW_OPEN_SOURCE_OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

vmw_conn_oss: $(VMW_OPEN_SOURCE_OBJS)
	$(CC) -o $(VMW_OPEN_SOURCE_BIN) $(VMW_OPEN_SOURCE_OBJS) $(LDFLAGS)

install:
	mkdir -p $(VMW_INSTALL_CONFDIR)
	cp $(SRCROOT)/vmw_conn_notify.conf $(VMW_INSTALL_CONFDIR)
	cp $(SRCROOT)/vmw_conn_notifyd $(VMW_INSTALL_INITDIR)
	chmod 755 $(VMW_INSTALL_INITDIR)/vmw_conn_notifyd
	cp $(VMW_OPEN_SOURCE_BIN) /usr/sbin/
	chmod 755 /usr/sbin/vmw_conn_notify

clean:
	rm -f $(VMW_OPEN_SOURCE_OBJS)
	rm -f $(VMW_OPEN_SOURCE_BIN)
