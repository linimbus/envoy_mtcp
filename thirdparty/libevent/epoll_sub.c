/*
 * Copyright 2003-2009 Niels Provos <provos@citi.umich.edu>
 * Copyright 2009-2012 Niels Provos and Nick Mathewson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "evconfig-private.h"
#include <stdint.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <netinet/in.h>

#include <execinfo.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

int debugflag = 1;

void DebugLog(const char* format, ...)
{
    va_list arglist;
    if ( debugflag )
    {
        va_start(arglist, format);
        vprintf(format, arglist);
        va_end(arglist);
    }
}

int epoll_create1_event(int sock_flags)
{
    int epfd;

    epfd = epoll_create1(sock_flags);
    if ( epfd < 0 )
    {
        DebugLog("epoll_create1 ret %d failed!\n", epfd );
        return -1;
    }

    DebugLog( "epoll_create1  input  : flags %d \n", sock_flags );
    DebugLog( "epoll_create1  output : epfd %d \n", epfd + 10000 );

    epfd += 10000;

    return epfd;
}

int accept4_event(int sockfd, struct sockaddr *addr, socklen_t *paddrlen, int flags)
{
    int  client_sock;

    client_sock = accept4((sockfd > 10000 ? (sockfd - 10000) : sockfd), addr, paddrlen, flags);

    DebugLog( "accept4    input  : scfd %d, flags %d \n", sockfd, flags );
    DebugLog( "accept4    output : ret %d \n", client_sock + 10000 );

    if ( client_sock > 0 )
    {
        client_sock += 10000;
    }

    return client_sock;
}

int listen_event( int sockfd, int backlog )
{
    int  ret;

    ret = listen((sockfd > 10000 ? (sockfd - 10000) : sockfd), backlog);

    DebugLog( "listen     input  : fd %d, backlog %d \n", sockfd, backlog);
    DebugLog( "listen     output : ret %d \n", ret );

    return ret;
}

int epoll_ctl_event(int epfd, int op, int fd, struct epoll_event * pevent)
{
    int  ret;
    char buf[1024];
    int  cnt = 0;

    if ( epfd < 10000 )
    {
        DebugLog("epoll_ctl_stub input failed! epfd = %d\n", epfd );
        return -1;
    }

    ret = epoll_ctl(epfd - 10000, op, (fd > 10000 ? (fd - 10000) : fd), pevent);
    if ( ret != 0 )
    {
        DebugLog("epoll_ctl_stub ret %d failed!\n", ret );
        return -1;
    }

    DebugLog( "epoll_ctl  input  : epfd %d, op %d, fd %d, events %d, data %d \n", epfd, op, fd, pevent->events, pevent->data.fd );
    DebugLog( "epoll_ctl  output : ret %d \n", ret );

    return 0;
}


int epoll_wait_event(int epfd, struct epoll_event *pevents, int maxevents, int timeout)
{
    int  ret;
    char buf[1024];
    int  cnt = 0;
    int  i;
    
    if ( epfd < 10000 )
    {
        DebugLog("epoll_wait_stub input failed! epfd = %d\n", epfd );
        return -1;
    }

    ret = 0; 
    ret = epoll_wait(epfd - 10000, pevents, maxevents, timeout);
    if ( ret > 0 )
    {
        cnt += sprintf(buf + cnt, "epoll_wait  input  : epfd %d, event %p, num %d, timeout %d \n", epfd, pevents, maxevents, timeout );
        cnt += sprintf(buf + cnt, "epoll_wait  output : ret %d\n", ret );
        for ( i = 0 ; i < ret ; i++ )
        {
            cnt += sprintf(buf + cnt, "                   : fd %d, event %d \n", pevents[i].data.fd, pevents[i].events );
        }
        
        DebugLog("%s",buf);
    }

    return ret;
}




