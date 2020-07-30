/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __THREADHELPER_H_INCLUDED__
#define __THREADHELPER_H_INCLUDED__

#include <string>
#include <thread>
#include <bdvmi/logger.h>

class ThreadHelper {

public:
	ThreadHelper() = default;

	~ThreadHelper()
	{
		if ( thread_.joinable() )
			thread_.join();
	}

	template <typename Callback, typename... Args> bool start( Callback &&callback, Args &&... args )
	{
		if ( thread_.joinable() )
			return false;

		thread_ = std::thread( std::forward<Callback>( callback ), std::forward<Args>( args )... );
		return true;
	}

	template <typename StopCallback> bool stop( StopCallback &&stopCallback )
	{
		try {
			stopCallback();

			if ( !thread_.joinable() )
				return false;

			thread_.join();
		} catch ( const std::exception &e ) {
			bdvmi::logger << bdvmi::ERROR << "Could not join thread: " << e.what() << std::flush;
			return false;
		}

		return true;
	}

	bool isRunning() const
	{
		return thread_.joinable();
	}

	ThreadHelper( const ThreadHelper & ) = delete;
	ThreadHelper &operator=( const ThreadHelper & ) = delete;

private:
	std::thread thread_;
};

#endif // __THREADHELPER_H_INCLUDED__
