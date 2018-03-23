#ifndef WIN32
  	signal(SIGPIPE, SIG_IGN);
	if (use_syslog) {
		if (log_file != stdout) {
			pt_log(kLog_error, "Logging using syslog overrides the use of a specified logfile (using -f).\n");
			fclose(log_file);
			log_file	= stdout;
		}		
		openlog("ptunnel", LOG_PID, LOG_USER);
	}
	if (NULL != root_dir) {
		pt_log(kLog_info, "Restricting file access to %s\n", root_dir);
		if (-1 == chdir(root_dir) || -1 == chroot(root_dir)) {
			pt_log(kLog_error, "%s: %s\n", root_dir, strerror(errno));
			exit(1);
		}
	}
	if (daemonize) {
		pt_log(kLog_info, "Going to the background.\n");
		if (0 < (pid = fork()))
			exit(0);
		if (0 > pid)
			pt_log(kLog_error, "fork: %s\n", strerror(errno));
		else
			if (-1 == setsid())
				pt_log(kLog_error, "setsid: %s\n", strerror(errno));
			else {
				if (0 < (pid = fork()))
					exit(0);
				if (0 > pid)
					pt_log(kLog_error, "fork: %s\n", strerror(errno));
				else {
					if (NULL != pid_file) {
						fprintf(pid_file, "%d\n", getpid());
						fclose(pid_file);
					}
					freopen("/dev/null", "r", stdin);
					freopen("/dev/null", "w", stdout);
					freopen("/dev/null", "w", stderr);
				}
			}
	}
#endif /* !WIN32 */



/*	pt_forwarder:
	Sets up a listening TCP socket, and forwards incoming connections
	over ping packets.
*/
void		pt_forwarder(void) {
	int					server_sock, new_sock, sock, yes = 1;
	fd_set				set;
	struct timeval		time;
	struct sockaddr_in	addr, dest_addr;
	socklen_t			addr_len;
	pthread_t			pid;
	uint16_t			rand_id;
	
	pt_log(kLog_debug, "Starting forwarder..\n");
	//	Open our listening socket
	sock					= socket(AF_INET, SOCK_STREAM, 0);
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &yes, sizeof(int)) == -1) {
		pt_log(kLog_error, "Failed to set SO_REUSEADDR option on listening socket: %s\n", strerror(errno));
		close(sock);
		return;
	}
	addr.sin_family			= AF_INET;
	addr.sin_port			= htons(tcp_listen_port);
	addr.sin_addr.s_addr	= INADDR_ANY;
	memset(&(addr.sin_zero), 0, 8);
	if (bind(sock, (struct sockaddr*)&addr, sizeof(struct sockaddr)) == -1) {
		pt_log(kLog_error, "Failed to bind listening socket: %s\n", strerror(errno));
		close(sock);
		return;
	}
	server_sock		= sock;
	//	Fill out address structure
	memset(&dest_addr, 0, sizeof(struct sockaddr_in));
	dest_addr.sin_family			= AF_INET;
	if (use_udp)
		dest_addr.sin_port			= htons(kDNS_port /* dns port.. */);
	else
		dest_addr.sin_port			= 0;
	dest_addr.sin_addr.s_addr		= given_proxy_ip;
	pt_log(kLog_verbose, "Proxy IP address: %s\n", inet_ntoa(*((struct in_addr*)&given_proxy_ip)));
	
	listen(server_sock, 10);
	while (1) {
		FD_ZERO(&set);
		FD_SET(server_sock, &set);
		time.tv_sec		= 1;
		time.tv_usec	= 0;
		if (select(server_sock+1, &set, 0, 0, &time) > 0) {
			pt_log(kLog_info, "Incoming connection.\n");
			addr_len	= sizeof(struct sockaddr_in);
			new_sock	= accept(server_sock, (struct sockaddr*)&addr, &addr_len);
			if (new_sock < 0) {
				pt_log(kLog_error, "Accepting incoming connection failed.\n");
				continue;
			}
			pthread_mutex_lock(&num_threads_lock);
			if (num_threads <= 0) {
				pt_log(kLog_event, "No running proxy thread - starting it.\n");
#ifndef WIN32
				if (pthread_create(&pid, 0, pt_proxy, 0) != 0)
#else
				if (0 == (pid = _beginthreadex(0, 0, (unsigned int (__stdcall *)(void *))pt_proxy, 0, 0, 0)))
#endif
				{
					pt_log(kLog_error, "Couldn't create thread! Dropping incoming connection.\n");
					close(new_sock);
					pthread_mutex_unlock(&num_threads_lock);
					continue;
				}
			}
			addr	= dest_addr;
			rand_id	= (uint16_t)rand();
			create_and_insert_proxy_desc(rand_id, rand_id, new_sock, &addr, given_dst_ip, tcp_port, kProxy_start, kUser_flag);
			pthread_mutex_unlock(&num_threads_lock);
		}
	}
}
