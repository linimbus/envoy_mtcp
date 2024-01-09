#include "common/api/os_sys_calls_impl.h"

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#ifdef  __cplusplus
#if  __cplusplus
extern "C" {
#endif
#endif

void DebugLog(const char* format, ...);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif


namespace Envoy {
namespace Api {

int OsSysCallsImpl::bind(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    int rc = ::bind((sockfd > 10000 ? (sockfd - 10000) : sockfd), addr, addrlen);

    ::DebugLog("bind input  : fd  %d, addr  %p, len %d \n",sockfd, addr, addrlen );
    ::DebugLog("bind output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::connect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    int rc = ::connect((sockfd > 10000 ? (sockfd - 10000) : sockfd), addr, addrlen);

    ::DebugLog("connect input  : fd  %d, addr  %p, len %d \n",sockfd, addr, addrlen );
    ::DebugLog("connect output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::accept(int sockfd, sockaddr* addr, socklen_t *addrlen) {
    int rc = ::accept((sockfd > 10000 ? (sockfd - 10000) : sockfd), addr, addrlen);

    ::DebugLog("accept input  : fd  %d, addr  %p, len %u \n", sockfd, addr, *addrlen );
    ::DebugLog("accept output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::ioctl(int sockfd, unsigned long int request, void* argp) {
    int rc = ::ioctl((sockfd > 10000 ? (sockfd - 10000) : sockfd), request, argp);

    ::DebugLog("ioctl input  : fd  %d, request %lu, argp %p \n", sockfd, request, argp );
    ::DebugLog("ioctl output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::open(const std::string& full_path, int flags, int mode) {
    int rc = ::open(full_path.c_str(), flags, mode);

    ::DebugLog("open input  : path %s, flag %d, mode %d \n", full_path.c_str(), flags, mode );
    ::DebugLog("open output : fd   %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::close(int sockfd) {
    int rc = ::close((sockfd > 10000 ? (sockfd - 10000) : sockfd));

    ::DebugLog("close input  : fd %d \n", sockfd );
    ::DebugLog("close output : ret %d, errno %d \n", rc, errno );

    return rc;
}

ssize_t OsSysCallsImpl::write(int sockfd, const void* buffer, size_t num_bytes) {
    ssize_t rc = ::write((sockfd > 10000 ? (sockfd - 10000) : sockfd), buffer, num_bytes);

    ::DebugLog("write input  : fd  %d, buffer %p, len %lu \n", sockfd, buffer, num_bytes );
    ::DebugLog("write output : ret %lu, errno %d \n", rc, errno );

    return rc;
}

ssize_t OsSysCallsImpl::writev(int sockfd, const iovec* iovec, int num_iovec) {
    ssize_t rc = ::writev((sockfd > 10000 ? (sockfd - 10000) : sockfd), iovec, num_iovec);

    ::DebugLog("writev input  : fd  %d, iovec %p, num %d \n", sockfd, iovec, num_iovec );
    ::DebugLog("writev output : ret %lu, errno %d \n", rc, errno );

    return rc;
}

ssize_t OsSysCallsImpl::readv(int sockfd, const iovec* iovec, int num_iovec) {
    ssize_t rc = ::readv((sockfd > 10000 ? (sockfd - 10000) : sockfd), iovec, num_iovec);

    ::DebugLog("readv input  : fd  %d, iovec %p, num %d \n", sockfd, iovec, num_iovec );
    ::DebugLog("readv output : ret %lu, errno %d \n", rc, errno );

    return rc;
}

ssize_t OsSysCallsImpl::recv(int sockfd, void* buffer, size_t length, int flags) {
    ssize_t rc = ::recv((sockfd > 10000 ? (sockfd - 10000) : sockfd), buffer, length, flags);
    
    ::DebugLog("recv input  : fd  %d, buffer %p, len %lu, flag %d \n", sockfd, buffer, length, flags );
    ::DebugLog("recv output : ret %lu, errno %d \n", rc, errno );
    
    return rc;
}

int OsSysCallsImpl::shmOpen(const char* name, int oflag, mode_t mode) {
    return ::shm_open(name, oflag, mode);
}

int OsSysCallsImpl::shmUnlink(const char* name) { 
    return ::shm_unlink(name); 
}

int OsSysCallsImpl::ftruncate(int fd, off_t length) { 
    return ::ftruncate(fd, length); 
}

void* OsSysCallsImpl::mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
    return ::mmap(addr, length, prot, flags, fd, offset);
}

int OsSysCallsImpl::stat(const char* pathname, struct stat* buf) { 
    return ::stat(pathname, buf); 
}

int OsSysCallsImpl::setsockopt(int sockfd, int level, int optname, const void* optval, socklen_t optlen) {

    int rc = ::setsockopt((sockfd > 10000 ? (sockfd - 10000) : sockfd), level, optname, optval, optlen);

    ::DebugLog("setsockopt input  : fd  %d, level %d, optname %d \n", sockfd, level, optname );
    ::DebugLog("setsockopt output : ret %d, errno %d \n", rc, errno );

    return rc;
}


int OsSysCallsImpl::getsockopt(int sockfd, int level, int optname, void* optval, socklen_t* optlen) {

    int rc = ::getsockopt( (sockfd > 10000 ? (sockfd - 10000) : sockfd) , level, optname, optval, optlen);

    ::DebugLog("getsockopt input  : fd  %d, level %d, optname %d optlen %d!\n", sockfd, level, optname, *optlen );
    ::DebugLog("getsockopt output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::getsockname(int sockfd, struct sockaddr *paddr, socklen_t *paddrlen){

    int rc = ::getsockname((sockfd > 10000 ? (sockfd - 10000) : sockfd), paddr, paddrlen);

    ::DebugLog("getsockname input  : fd  %d, paddr %p, addrlen %d \n", sockfd, paddr, *paddrlen );
    ::DebugLog("getsockname output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::getpeername(int sockfd, struct sockaddr *paddr, socklen_t *paddrlen){

    int rc = ::getpeername((sockfd > 10000 ? (sockfd - 10000) : sockfd), paddr, paddrlen);

    ::DebugLog("getpeername input  : fd  %d, paddr %p, addrlen %d \n", sockfd, paddr, *paddrlen );
    ::DebugLog("getpeername output : ret %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::socket(int domain, int type, int protocol) {
    
    int rc = ::socket(domain, type, protocol);
    
    ::DebugLog("socket knl stack input  : domain %d, type %d, protocal %d \n", domain, type, protocol );
    ::DebugLog("socket knl stack output : fd %d, errno %d \n", rc, errno );

    return rc;
}

int OsSysCallsImpl::socket2(int domain, int type, int protocol) {
    
    int rc = ::socket(domain, type, protocol);
    if ( rc > 0 )
    {
        rc += 10000;
    }
    
    ::DebugLog("socket user stack input  : domain %d, type %d, protocal %d \n", domain, type, protocol );
    ::DebugLog("socket user stack output : fd %d, errno %d \n", rc , errno );

    return rc;
}

} // namespace Api
} // namespace Envoy
