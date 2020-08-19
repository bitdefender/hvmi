/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hvmidaemon.h"
#include "hvmisettings.h"
#include "argparse.h"
#include <cstring>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <fcntl.h>

#include <bdvmi/backendfactory.h>
#include <bdvmi/domainhandler.h>
#include <bdvmi/domainwatcher.h>
#include <bdvmi/logger.h>

#include "hvmidomainhandler.h"
#include "hvmieventhandler.h"
#include "introcoremanager.h"

#include "config.h"

sig_atomic_t g_stop = 0;

static int g_pidfile_fd = -1;

namespace {

void stop_daemon( void )
{
	g_stop = SIGINT;
}

void sig_stop_daemon( int /* signo */ )
{
	stop_daemon();
}

/*
 * This function should be called in two ways:
 * 1. acquire_pidfile( 0 ) will only try to lock the pidfile and check if the daemon is already running.
 * 2. acquire_pidfile( getpid() ) will also perform the previous operations and will additionally write the pid
 * in the pidfile and will keep the file descriptor open.
 *
 * ret < 0 : Some unknown error.
 * ret = 0 : Pidfile acquired. If pid != 0, the process now has the ownership over the file.
 * ret > 0 : Pidfile is already locked. The return value is the pid of the process owning the pidfile.
 */
int acquire_pidfile( int pid )
{
	int fd;
	int ret = -1;

	if ( g_pidfile_fd > 0 ) {
		return 0;
	}

	fd = open( HVMID_PIDFILE, O_CREAT | O_WRONLY | O_EXCL | O_CLOEXEC, 0644 );
	if ( fd == -1 ) {
		/*
		 * The file may or may not exist. Even if it exists, it is possible to be a leftover from a
		 * previous run that terminated abruptly. (crashed)
		 */
		fd = open( HVMID_PIDFILE, O_RDWR | O_CLOEXEC );
		if ( fd == -1 ) {
			std::cout << "Failed to open pidfile: " << strerror( errno ) << std::endl;
			return -1;
		}
	}

	if ( flock( fd, LOCK_EX | LOCK_NB ) == -1 ) {

		/* `man errno` tells us that these may be the same value. We do not care. */
		if ( EWOULDBLOCK == errno || EAGAIN == errno ) {
			/* The file is locked. Let's see by who? */
			char    pfcontent[16];
			ssize_t n = read( fd, pfcontent, sizeof( pfcontent ) - 1 );
			if ( n >= 0 ) {
				pfcontent[n] = '\0';
				sscanf( pfcontent, "%d", &ret );
			}
		} else {
			std::cerr << "flock() failed: " << strerror( errno );
		}

		/* The file is already owned, nothing to do further. */

		close( fd );

		return ret;
	}

	if ( pid == 0 ) {
		close( fd );
		return 0;
	}

	if ( ftruncate( fd, 0 ) == -1 || lseek( fd, 0, SEEK_SET ) == -1 || dprintf( fd, "%d\n", pid ) == -1 )
		/* Keep going, but log the error. */
		std::cerr << "Failed to write pid: " << strerror( errno ) << std::endl;

	g_pidfile_fd = fd;

	return 0;
}

void cleanup_pidfile()
{
	if ( g_pidfile_fd == -1 )
		return;

	unlink( HVMID_PIDFILE );

	close( g_pidfile_fd );

	g_pidfile_fd = -1;
}

void daemonize( void )
{
	pid_t pid;

	/* Standard daemon initialization code. (man 7 daemon) */

	pid = fork();

	if ( pid < 0 )
		exit( EXIT_FAILURE );

	if ( pid > 0 )
		exit( EXIT_SUCCESS );

	if ( setsid() < 0 )
		exit( EXIT_FAILURE );

	signal( SIGCHLD, SIG_IGN );
	signal( SIGHUP, SIG_IGN );

	pid = fork();

	if ( pid < 0 )
		exit( EXIT_FAILURE );

	if ( pid > 0 )
		exit( EXIT_SUCCESS );

	umask( 0 );

	chdir( "/" );

	if ( acquire_pidfile( getpid() ) > 0 ) {
		std::cout << HVMID_NAME << " is already running." << std::endl;
		exit( EXIT_FAILURE );
	}

	close( STDIN_FILENO );
	close( STDOUT_FILENO );
	close( STDERR_FILENO );
}

int do_work( void )
{
	bdvmi::logger << bdvmi::INFO << HVMID_NAME << " starting" << std::flush;

	try {
		HvmiSettings settings;
		settings.loadDaemonSettings();

		bdvmi::BackendFactory bf( settings.backend_ );
		auto                  pdw = bf.domainWatcher( g_stop );

		HvmiDomainHandler bdh( settings, pdw.get() );

		bool firstWarning = true;

		while ( g_stop == 0 && !pdw->accessGranted() ) {
			if ( firstWarning ) {
				bdvmi::logger << bdvmi::WARNING << "Waiting for introspection access to be granted..."
				              << std::flush;
				firstWarning = false;
			}
			sleep( 1 );
		}

		if ( g_stop == 0 ) {
			bdh.ignoreDomains( settings.ignoredDomains_ );

			bdvmi::logger << bdvmi::INFO << "Registering handlers" << std::flush;
			pdw->handler( &bdh );

			bdvmi::logger << bdvmi::INFO << "Waiting for domains to be started" << std::flush;
			pdw->waitForDomains();

			kill( 0, SIGINT ); // tell the children it's over
			bdh.startExitTimeoutThread( HVMID_EXIT_TIMEOUT );
			bdh.collectChildProcesses();
		}
	} catch ( const std::exception &e ) {
		bdvmi::logger << bdvmi::ERROR << HVMID_NAME " shutdown with error: " << e.what() << std::flush;
		return -1;
	} catch ( ... ) {
		bdvmi::logger << bdvmi::ERROR << HVMID_NAME " shutdown because of an unknown exception" << std::flush;
		return -1;
	}

	bdvmi::logger << bdvmi::INFO << HVMID_NAME << " shutdown complete" << std::flush;

	return 0;
}

int start( void )
{
	int result = 0;

	struct sigaction act = {};

	daemonize();

	openlog( HVMID_DAEMON_NAME, LOG_PID, 0 );

	// set signal handler
	act.sa_handler = sig_stop_daemon;
	sigemptyset( &act.sa_mask );
	sigaction( SIGINT, &act, nullptr );
	sigaction( SIGTERM, &act, nullptr );
	signal( SIGHUP, SIG_IGN );

	sigset_t mask;

	sigemptyset( &mask );
	sigaddset( &mask, SIGCHLD );
	pthread_sigmask( SIG_BLOCK, &mask, nullptr );

	bdvmi::logger.info( []( const std::string &s ) { syslog( LOG_INFO, "%s", s.c_str() ); } );
	bdvmi::logger.debug( []( const std::string &s ) { syslog( LOG_DEBUG, "%s", s.c_str() ); } );
	bdvmi::logger.warning( []( const std::string &s ) { syslog( LOG_WARNING, "%s", s.c_str() ); } );
	bdvmi::logger.error( []( const std::string &s ) { syslog( LOG_ERR, "%s", s.c_str() ); } );

	result = do_work();

	closelog();

	cleanup_pidfile();

	return result;
}

#if 0
int debug( void )
{
	int result = 0;

	openlog( HVMID_DAEMON_NAME, LOG_PID, 0 );

	do {

		bdvmi::logger.info( []( const std::string &s ) { syslog( LOG_INFO, "%s", s.c_str() ); } );
		bdvmi::logger.debug( []( const std::string &s ) { syslog( LOG_DEBUG, "%s", s.c_str() ); } );
		bdvmi::logger.warning( []( const std::string &s ) { syslog( LOG_WARNING, "%s", s.c_str() ); } );
		bdvmi::logger.error( []( const std::string &s ) { syslog( LOG_ERR, "%s", s.c_str() ); } );

		result = do_work();
	} while ( 0 );

	closelog();

	return result;
}
#endif

} // end of anonymous namespace

int main( int argc, const char **argv )
{
	auto parser = argparse::ArgumentParser( argv[0], HVMID_NAME );

	parser.add_argument( "-s", "--start", "Start " HVMID_NAME, false );
	parser.add_argument( "-k", "--kill", "Stop " HVMID_NAME, false );

	parser.enable_help();

	auto err = parser.parse( argc, argv );
	if ( err ) {
		std::cout << err << std::endl;
		return -1;
	}

	if ( parser.exists( "help" ) ) {
		parser.print_help();
		return 0;
	}

	if ( parser.exists( "start" ) ) {
		int pid = acquire_pidfile( 0 );

		if ( pid > 0 ) {
			std::cout << HVMID_NAME << " is already running." << std::endl;
			return 0;
		}

		/*
		 * No reason to cancel if we cannot access the pidfile because of some unknown error.
		 * Just tell the user about this and hope for the best.
		 */
		if ( pid < 0 )
			std::cerr << "Error: Cannot access the pidfile!" << std::endl;

		std::cout << "Starting " << HVMID_NAME << "..." << std::endl;
		return start();
	}

	if ( parser.exists( "kill" ) ) {
		int pid = acquire_pidfile( 0 );
		if ( pid <= 0 ) {
			std::cout << HVMID_NAME << " is not currently running." << std::endl;
			return 0;
		}

		if ( kill( pid, SIGTERM ) == -1 ) {
			std::cout << "Error: Failed to stop " << HVMID_NAME << std::endl;
			return -1;
		}

		std::cout << "Waiting for the daemon to shutdown gracefully..." << std::flush;

		for ( int t = 0; t < 60; t++ ) {

			if ( kill( pid, 0 ) == -1 ) {
				std::cout << " Done" << std::endl;
				return 0;
			}

			sleep( 1 );
		}

		std::cout << std::endl << "Force killing pid " << pid << "..." << std::endl;

		if ( kill( pid, SIGKILL ) == -1 ) {
			std::cout << "Failed to force kill the daemon" << std::endl;
			return -1;
		}

		return 0;
	}

	parser.print_help();

	return 0;
}
