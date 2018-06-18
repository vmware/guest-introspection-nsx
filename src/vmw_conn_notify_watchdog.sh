#!/bin/bash
#
# Copyright (C) 2018 VMware, Inc. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2.
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
#
# This is the connection notifier watchdog script that monitors vmw_conn_notify

# Sleep for 60 seconds by default
IMMORTAL=60


VMW_CONN_NOTIFY_NAME=vmw_conn_notify
VMW_CONN_NOTIFY_BIN=/usr/sbin/$VMW_CONN_NOTIFY_NAME
VMW_CONN_NOTIFY_CONFIG=/etc/vmw_conn_notify/vmw_conn_notify.cfg
LOCK_FILE=/var/lock/subsys/vmw_conn_notifyd
VMW_CONN_NOTIFY_WATCHDOG_NAME=vmw_conn_notifyd_watchdog
VMW_CONN_NOTIFY_WATCHDOG=/usr/sbin/$VMW_CONN_NOTIFY_WATCHDOG_NAME

# Logging related variables
LOGPREFIX=$VMW_CONN_NOTIFY_WATCHDOG_NAME
PID_LOGPREFIX=$$
VERBOSE=1
SILENT=0
LOG_LEVEL=$VERBOSE
GM_SUCCESS=0
GM_FAIL=1

MAX_RETRIES_VMW_CONN_NOTIFY=8


# Logging related variables
GM_SUCCESS=0
GM_FAIL=1

# Time taken for vmw_conn_notify to stop its all services
VMW_CONN_NOTIFY_STOP_TIME=4

# Check for missing binaries
if [ ! -f $VMW_CONN_NOTIFY_BIN ] ; then
   vmw_logger "$VMW_CONN_NOTIFY_BIN not installed" $SILENT $ERROR
   if [ "$1" = "stop" ] ; then
      exit 0
   else
      exit 5
   fi
fi

#####################################################################
# Definition:
# Function to log messages
#
# Arguments:
# Argument 1: String to print
# Argument 2: LOG_LEVEL(SILENT(0) / VERBOSE(1))
# Argument 3: Log Status (success|info, warning, failure|err)
#####################################################################
vmw_logger() {
   local VERBOSE=1
   local SILENT=0
   local STR=$1
   local LOG_LEVEL=${2:-$VERBOSE}
   local LOG_STATUS=${3:-"info"}

   if [ "${LOG_LEVEL}" -eq $VERBOSE ]; then
     echo "${STR}"
   fi

   case "$LOG_STATUS" in
   "err"|"failure") # failure
       LOG_STATUS="err"
       ;;
   "warn") # warning
       LOG_STATUS="warning"
       ;;
   "info"|"success") # success
       LOG_STATUS="info"
       ;;
   *)
       LOG_STATUS="info"
       ;;
   esac

   logger -p daemon.$LOG_STATUS -t "$VMW_CONN_NOTIFY_WATCHDOG_NAME[$$]" "$STR"
}

#
# Enable this when we have a config file
# Check for missing config file
[ -e $VMW_CONN_NOTIFY_CONFIG ] && . $VMW_CONN_NOTIFY_CONFIG

status() {
   local retval="$GM_SUCCESS"

   #
   # Check if there's already running instance of vmw_conn_notify, using lock_file
   # and using pidof command.. so at any time we will run only one instance
   #
   if [ -f $LOCK_FILE -a -n "`pidof $VMW_CONN_NOTIFY_BIN`" ] ; then
      retval="$GM_SUCCESS"
   else
      retval="$GM_FAIL"
   fi

   return "$retval"
}


start() {
   local retval="$GM_SUCCESS"
   local IMMORTAL=${IMMORTAL:-60}
   local VERBOSE=1
   local SILENT=0
   local LOG_LEVEL=$SILENT
   local iter_vmw_conn_notify=0

   while :
      do
      # Sleep so we don't continuously spawn the process(s)
      sleep $IMMORTAL
      # Status returns the combined status and can pinpoint which service is stopped
      status
      retval=$?
      if [ $retval -eq $GM_SUCCESS ] ; then
         :
      else
         vmw_logger "vmw_conn_notify not running" $SILENT $ERROR
         vmw_logger "Attempting fix" $SILENT $INFO
         mkdir -p /var/lock/subsys
         touch $LOCK_FILE
         iter_vmw_conn_notify=$((iter_vmw_conn_notify+1))
         $VMW_CONN_NOTIFY_BIN &
      fi

      # We reach here which means we have exhausted the number of retries
      # Check one more time if our last start was successful, if not then exit
      if [ $iter_vmw_conn_notify -ge $MAX_RETRIES_VMW_CONN_NOTIFY ]; then
         status
         retval=$?
         if [ $retval -ne $GM_SUCCESS ]; then
            vmw_logger "Max retries exceeded! Closing $VMW_CONN_NOTIFY_NAME service" $SILENT $ERROR
            stop
            exit $GM_FAIL
         else
            # Our last start was successful, reset counters again
            iter_vmw_conn_notify=0
         fi
      fi
   done

}

if [ "`id -u`" -ne 0 ] ; then
   vmw_logger "User has insufficient privilege." $SILENT $ERROR
   exit 4
fi

# Stop the vmw_conn_notify watchdog
stop() {
   local retval=$GM_SUCCESS
   local VERBOSE=1
   local SILENT=0
   local LOG_LEVEL=$SILENT

   vmw_logger "Stopping $VMW_CONN_NOTIFY_NAME service" $SILENT $INFO

   kill -SIGTERM `pidof $VMW_CONN_NOTIFY_BIN`
   retval=$?
   if [ $retval -eq $GM_SUCCESS ] ; then
      ### Now, delete the lock file ###
      rm -f $LOCK_FILE
      sleep $VMW_CONN_NOTIFY_STOP_TIME
   else
      vmw_logger "$VMW_CONN_NOTIFY_NAME service stop error" $SILENT $ERROR
   fi
}

start
# We already handle TERM signals, should never come here...
exit 1
