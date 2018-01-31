/*
 * Copyright (C) 2018 VMware, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation (or any later at your option)

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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Linux userland component for enabling network connection event notification.
 *
 * vmw_conn_main.c (connection notifier) can be run as a daemon or a server
 * process with the name vmw_conn_notify. It listens on  a unix domain socket.
 * It can be gracefully terminated using SIGINT or SIGTERM signal.
 *
 * It supports connections from MAX_CLIENT number of client through unix domain
 * socket. At a time only one instance of this process/daemon can run.
 *
 * It is a multithreaded program. The main thread waits for connection from the
 * clients and other threads defined in vmw_conn_netfilter.c interacts with the
 * registerd clients and netfilter libraries.
 */

#include "vmw_conn.h"

/* Unix domain socket path */
#define SOCK_PATH "/var/run/.vmw_conn_notify_socket"

/* PID file to don't allow running of duplicate instance */
#define VMW_PID_FILE "/var/run/vmw_conn_notify.pid"

#define PROC_PATH_SIZE 256
#define VMW_CONN_NOTIFY_VERSION "1.0.0"
#define VMW_CONFIG_FILE "/etc/vmw_conn_notify/vmw_conn_notify.conf"
#define VMW_CONFIG_GROUP_NAME "VMW_CONN_NOTIFY_CONFIG"

extern volatile int g_vmw_init_done;
extern void *vmw_init(void *);
extern bool vmw_is_mark_unused(int mark);

/* Global client context array */
struct vmw_client_scope g_client_ctx[MAX_CLIENTS];

/* Global variable to indicate process termintation/shutdown event */
volatile int g_need_to_quit  = 0;

/*
 * Array of FDs  to break select() in case of shutdown event or new client
 * connection event.
 */
static int process_exit_fds[2];

/* Command line get_opt flags */
#define GETOPT_OPTIONS "vpl:"
int process_flag = 0;
int version_flag = 0;
int log_flag = 0;

/*
 * Do dummy write on pipe write fd to  break select() blocking in case of
 * process termination event or new connection event
 */
void
vmw_notify_exit()
{
   int dummy_value = 0;

   ATOMIC_OR(&g_need_to_quit, 1);
   write(process_exit_fds[1], &dummy_value, sizeof(dummy_value));

   return;
}

/*
 * Process SIGINT/SIFTERM signal to notify all running threads blocked on
 * select() to inititate shutdown.
 */
static void
vmw_handle_process_exit_signal(int sig_num)
{

   NOTICE("%s recieved signal %d", PROG_NAME, sig_num);
   if (SIGINT == sig_num || SIGTERM == sig_num) {
      NOTICE("%s is being shutdown", PROG_NAME);
      vmw_notify_exit();
   } else {
      ERROR("Invalid signal is received %d", sig_num);
   }
   return;
}

/*
 * This function opens and loads the GKeyFile object for a given file.
 * Caller has to free the GKeyFile object in case of success.
*/
GKeyFile *
vmw_get_loaded_gkey_file(char *fileName)
{
   GKeyFile *configFile = NULL;

   configFile = g_key_file_new();
   if (NULL == configFile) {
      ERROR("Failed to create new GKeyFile object");
      goto exit;
   }

   if (!g_key_file_load_from_file(configFile, fileName, 0, NULL)) {
      ERROR("Failed to load config file");
      g_key_file_free(configFile);
      configFile = NULL;
      goto exit;
   }

exit:
   return configFile;
}

/*
 * This function opens and loads the vmw_conn_notify config file, reads
 * the config params and sets the log level accordingly.
 */
static void
vmw_handle_config_change_signal() {
   int value = 0;
   GError *error = NULL;
   GKeyFile *configFile = NULL;

   if (ATOMIC_OR(&g_need_to_quit, 0)) {
      goto exit;
   }

   configFile = vmw_get_loaded_gkey_file(VMW_CONFIG_FILE);
   if (NULL == configFile) {
      ERROR("Failed to load the config file.");
      goto exit;
   }

   /* Getting the debug level */
   value = g_key_file_get_integer(configFile,
                                  VMW_CONFIG_GROUP_NAME,
                                  "DEBUG_LEVEL",
                                  &error);

   if (!error) {
      if ((LOG_EMERG <= value) && (LOG_DEBUG >= value)) {
         setlogmask(LOG_UPTO(value));
         NOTICE("Successfully setting the Log level to %d", value);
      } else {
         WARN("Wrong debug level provided in "
              "/etc/vmw_conn_notify/vmw_conn_notify.conf %d",
               value);
      }
   } else {
      WARN("Failed to read /etc/vmw_conn_notify/vmw_conn_notify.conf error: %s",
            error->message);
   }

exit:
   if (error) {
      g_error_free(error);
   }
   if (configFile) {
      g_key_file_free(configFile);
   }
   return;
}

/* Install signal handler for SIGINT and SIGTERM signals */
int
vmw_set_sighandler()
{
   struct sigaction sig_action;
   int ret = 0;

   /* Set the handler for SIGTERM to do graceful exit of the threads */
   memset(&sig_action, 0, sizeof(sig_action));
   sig_action.sa_handler = vmw_handle_process_exit_signal;
   ret = sigaction(SIGTERM, &sig_action, NULL);
   if (0 != ret) {
      ERROR("Failed to set the SIGTERM signal handler, error: %s",
            strerror(errno));
      goto exit;
   }

   /* Set the handler for SIGINT to do graceful exit of thread threads. */
   memset(&sig_action, 0, sizeof(sig_action));
   sig_action.sa_handler = vmw_handle_process_exit_signal;
   ret = sigaction(SIGINT, &sig_action, NULL);
   if (0 != ret) {
      ERROR("Failed to set the SIGINT signal handler, error: %s",
            strerror(errno));
      goto exit;
   }

   /*
    * Set the handler for SIGHUP to change the log level as
    * per the config file.
    */
   memset(&sig_action, 0, sizeof(sig_action));
   sig_action.sa_handler = vmw_handle_config_change_signal;
   ret = sigaction(SIGHUP, &sig_action, NULL);
   if (0 != ret) {
      ERROR("Failed to set the SIGHUP signal handler, error: %s",
             strerror(errno));
      goto exit;
   }

   /* Dummy pipe to notify process exit blocked on select */
   ret = pipe(process_exit_fds);
   if (0 != ret) {
      ERROR("Could not create dummy eventfd, error: %s", strerror(errno));
      goto exit;
   }

exit:
   return ret;
}

/* Record pid in a file to detect duplicate process */
static int
vmw_record_pid()
{
   FILE *fpid = NULL;
   int status = 0;

   if ((fpid = fopen(VMW_PID_FILE, "w"))) {
      fprintf(fpid, "%d", getpid());
      fclose(fpid);
   } else {
      status = -1;
      ERROR("Failed to create pid file %s: %s", VMW_PID_FILE, strerror(errno));
   }
   return status;
}

/*
 * Check whether a process with given pid is running or not; return true
 * if a process is running otherwise return false
 */
static bool
vmw_check_process_running(pid_t pid)
{
   bool status = false;
   FILE *fproc = NULL;
   char proc_file[PROC_PATH_SIZE] = {0};

   sprintf(proc_file, "/proc/%d/stat", pid);
   if ((fproc = fopen(proc_file, "r"))) {
      fprintf(stdout, "Found %s already running with pid %d, exiting\n",
              PROG_NAME, pid);
      ERROR("Found %s already running with pid %d, exiting\n",
            PROG_NAME, pid);
      fclose(fproc);
      status = true;
   }

   return status;
}

/* Check if a process with given pid is already running */
static bool
vmw_check_duplicate_process()
{
   FILE *fpid = NULL;
   pid_t pid;
   int ret;
   bool status = false;

   /* Check if VMW_PID_FILE exists */
   if ((fpid = fopen(VMW_PID_FILE, "r+"))) {

      /* Read the pid from the pid file */
      ret = fscanf(fpid, "%d", &pid);
      if (1 == ret) {
         /*
          * We found a pid, now check if there is an instnace of this process
          * already running with this pid
          */
         status = vmw_check_process_running(pid);
      }
      fclose(fpid);
   }

   return status;
}

/*
 * In addition to given fds, call select() to monitor event on read fd of pipe.
 * This is to break blocking on select() in the event of process termincation by
 * just dummy write on the the write fd of the pipe.
 */
int
vmw_wait_for_event(int maxfd, fd_set *readfds, uint8_t new_client_connreq)
{
   int ret;
   int dummy_value = 1;

   if (ATOMIC_OR(&g_need_to_quit, 0)) {
      ret = 0;
      goto exit;
   }

   /*
    * Use read fd of pipe to get process termination/new client connection
    * event
    */
   FD_SET(process_exit_fds[0], readfds);
   if (process_exit_fds[0] > maxfd) {
         maxfd = process_exit_fds[0];
   }

   ret = select(maxfd + 1, readfds, NULL, NULL, NULL);
   if (ret < 0) {
      ERROR("select() failed with error %s", strerror(errno));
      goto exit;
   }
   if (FD_ISSET(process_exit_fds[0], readfds)) {
      if (new_client_connreq && !ATOMIC_OR(&g_need_to_quit, 0)) {
         /* Consume new client connection event */
         ret = read(process_exit_fds[0], (void *)&dummy_value,
                    sizeof(dummy_value));
      }
      ret = 0;
      goto exit;
   }

exit:
   return ret;
}

/* Print command line help */
static void
usage(void)
{
   fprintf(stderr, "usage: %s <options>\n", PROG_NAME);
   fprintf(stderr, "       -v: Display %s version and exit\n", PROG_NAME);
   fprintf(stderr, "       -p: Run as process \n");
   fprintf(stderr, "       -l <level>: Log level in 1..7 range\n");

   exit(1);
}
/* Parse command line options */
static void
get_opt(int argc, char **argv)
{
   int opt;
   int option_index;

   static struct option options[] = {
      {"version", no_argument, 0, 'v'},
      {"process",     no_argument, 0, 'p'},
      {0, 0, 0, 0}
   };

   while (1) {
      opt = getopt_long(argc, argv, GETOPT_OPTIONS, options, &option_index);
      if (-1 == opt) {
         break;
      }
      switch (opt) {
         case 'v':
            version_flag = 1;
            break;
         case 'p':
            process_flag = 1;
            break;
         case 'l':
            log_flag = atoi(optarg);
            if (log_flag > LOG_DEBUG) {
               fprintf(stderr, "Invalid log level %d", log_flag);
               ERROR("Invalid log level %d", log_flag);
               usage();
            }
            break;
         default:
            usage();
      }
   }
}

/*
 * Process command line options. Set appropriate log level based on command line
 * input; also record pid after starting this program in daemon or process mode
 * based on command line input.
 */
static int
vmw_process_option(int argc, char **argv)
{
   int ret = 0;

   get_opt(argc, argv);

   if (version_flag) {
      fprintf(stdout, "%s version :\t%s\n", PROG_NAME, VMW_CONN_NOTIFY_VERSION);
      goto exit;
   }

   /* Use PID during logging */
   openlog(PROG_NAME, LOG_CONS | LOG_PID, LOG_USER);

   if (true == vmw_check_duplicate_process()) {
      ERROR("%s is already running\n", PROG_NAME);
      ret = 1;
      closelog();
      goto exit;
   }

   if (!process_flag) {
      daemon(0, 0);
   }

   if (log_flag > 0) {
      /* Set log prority for this process/daemon for syslog logging*/
      setlogmask(LOG_UPTO(log_flag));
   } else {
      setlogmask(LOG_UPTO(LOG_INFO));
   }

   if (!process_flag) {
      INFO("%s has started as daemon\n", PROG_NAME);
   } else {
      INFO("%s has started\n", PROG_NAME);
   }

   /* Record PID into pid file */
   ret = vmw_record_pid();

exit:
   return ret;
}

int
main(int argc, char **argv) {
   struct sockaddr_un local, remote;
   fd_set readfds, master;
   pthread_t init_thread;
   pthread_t *init_thread_ptr = NULL;
   socklen_t len;
   int i, maxfd;
   int dummy_value = 0, ret = 0;
   int sock = -1, new_socket = -1;
   uint32_t version = 1;
   uint8_t new_client_connreq = 0;
   bool mark_unused = FALSE;
   clientInfo cInfo = { 0 };

   /* Process command line options */
   if (vmw_process_option(argc, argv)) {
      ret = 1;
      goto exit;
   }

   /* Setting the log level */
   vmw_handle_config_change_signal();

   /*
    * Setup signal handler to catch SIGINT and SIGTERM for provided graceful
    * shutdown
    */
   if (vmw_set_sighandler()) {
     ret = 1;
     goto exit;
   }

   /* Create unix domain socket */
   if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
      ERROR("Socket creation failed with error %s", strerror(errno));
      ret = sock;
      goto exit;
   }

   local.sun_family = AF_UNIX;
   strcpy(local.sun_path, SOCK_PATH);
   unlink(local.sun_path);
   len = strlen(local.sun_path) + sizeof(local.sun_family);

   ret = bind(sock, (struct sockaddr *)&local, len);
   if (-1 == ret) {
      ERROR("bind() failed with error %s", strerror(errno));
      goto exit;
   }

   ret = listen(sock, MAX_CLIENTS);
   if (-1 == ret) {
      ERROR("bind() failed with error %s", strerror(errno));
      goto exit;
   }

   /* Clear the file descriptor set that to be monitored by select */
   FD_ZERO(&readfds);

   /* Add sock fd  to FD set to be monitored by select for new connection */
   FD_SET(sock, &readfds);
   master = readfds;
   maxfd = sock;

   for (i = 0; i < MAX_CLIENTS; i++) {
      /*
       * Create per client  hash table for keeping record of packets which are
       * delivered to the client and verdict yet to be receivied for them.
       */
      g_client_ctx[i].queued_pkthash = g_hash_table_new(g_direct_hash,
                                                        g_direct_equal);
      pthread_mutex_init(&g_client_ctx[i].client_sock_lock, NULL);
   }

   while (1) {

      /* Is process/daemon being shutdown? */
      if (ATOMIC_OR(&g_need_to_quit, 0)) {
         break;
      }

      /*
       * Copy the master set back to readfds set so that sock fd can be
       * monitored again for any new connection
       */
      readfds = master;
      ret = vmw_wait_for_event(maxfd, &readfds, new_client_connreq);
      if (-1 == ret) {
         if (EINTR == errno) {
            continue;
         }
         ERROR("Failed to accept new connection, select failure error %s",
               strerror(errno));
         break;
      } else if (0 == ret) {
         /* Looks like signal is received for graceful shutdown */
         continue;
      }

      len = sizeof(remote);
      new_socket = accept(sock, (struct sockaddr *)&remote, &len);
      if (-1 == new_socket) {
         ERROR("bind() failed with error %s", strerror(errno));
         ret = new_socket;
         goto exit;
      }

      INFO("Connection from client socket %d is recevied", new_socket);
      for (i = 0; i < MAX_CLIENTS; i++) {
         pthread_mutex_lock(&g_client_ctx[i].client_sock_lock);
         if (g_client_ctx[i].client_sockfd <= 0 &&
             !g_client_ctx[i].pkthash_cleanup_wait) {
            pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);
            ret = recv(new_socket, (void *)&cInfo, sizeof(clientInfo), 0);
            if (ret <= 0) {
               ERROR("Failed to complete connection with client socket %d, "
                     "error %s", new_socket, strerror(errno));
               close(new_socket);
               new_socket = -1;
               break;
            }
            mark_unused = vmw_is_mark_unused(cInfo.mark);
            if (FALSE == mark_unused) {
               ERROR("Failed to complete connection with client socket %d, "
                     "error %s", new_socket, strerror(errno));
               close(new_socket);
               break;
            }
            /*
             * The version can be used to identify client verdict but currenty
             * it is not used.
             */
            send(new_socket, &version, sizeof(version), 0);

            pthread_mutex_lock(&g_client_ctx[i].client_sock_lock);
            g_client_ctx[i].client_version = cInfo.version;
            g_client_ctx[i].client_mark = cInfo.mark;
            g_client_ctx[i].client_sockfd = new_socket;
            pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);
            INFO("Adding client to the list of connected client as "
                 "socket %d at index %d version %x mark %x", new_socket, i,
                cInfo.version, cInfo.mark);

            /*
             * Send new client connection notification to vmw_client_msg_recv
             * thread for updating client_cnt array
             */
            write(process_exit_fds[1], &dummy_value, sizeof(dummy_value));
            break;
         } else {
            pthread_mutex_unlock(&g_client_ctx[i].client_sock_lock);
         }
      }

      if (i == MAX_CLIENTS) {
         ERROR("Closing the connection with new client socket %d as maximum "
               "number of client %d is already registered",
               new_socket, MAX_CLIENTS);
         close(new_socket);
         new_socket = -1;
      }

      if (!ATOMIC_OR(&g_vmw_init_done, 0)) {
            pthread_create(&init_thread, NULL, vmw_init, NULL);
            init_thread_ptr = &init_thread;
      }
   }

   if (init_thread_ptr) {
      pthread_join(init_thread, NULL);
   }

   for (i = 0; i < MAX_CLIENTS; i++) {
      if (g_client_ctx[i].client_sockfd > 0) {
         close(g_client_ctx[i].client_sockfd);
      }
      pthread_mutex_destroy(&g_client_ctx[i].client_sock_lock);
      g_hash_table_remove_all(g_client_ctx[i].queued_pkthash);
      g_hash_table_destroy(g_client_ctx[i].queued_pkthash);
   }

   if (sock > 0) {
      close(sock);
   }
   closelog();
   unlink(VMW_PID_FILE);
   ret = 0;

exit:
   return ret;
}
