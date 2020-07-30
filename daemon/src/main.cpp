/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hvmidaemon.h"
#include "hvmisettings.h"
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <syslog.h>

#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>

#include <sys/stat.h>

#include <bdvmi/backendfactory.h>
#include <bdvmi/domainhandler.h>
#include <bdvmi/domainwatcher.h>
#include <bdvmi/logger.h>

#include "hvmidomainhandler.h"
#include "hvmieventhandler.h"
#include "introcoremanager.h"

#include "config.h"

sig_atomic_t g_stop = 0;

namespace {

void stop_daemon( void )
{
	g_stop = SIGINT;
}

void sig_stop_daemon( int /* signo */ )
{
	stop_daemon();
}

void daemonize( void )
{
	pid_t pid;

	// Standard daemon initialization code. (man 7 daemon)

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

	// Close all file descriptors
	for ( int fd = sysconf( _SC_OPEN_MAX ); fd >= 0; fd-- ) {
		close( fd );
	}
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

int main( int /* argc */, char ** /* argv */ )
{
	return start();
}
