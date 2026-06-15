#ifndef UV_STUB_H
#define UV_STUB_H
#include <stddef.h>
#define UV_VERSION_HEX 0x011200
typedef struct uv_fs_s { const char* path; void* ptr; long result; } uv_fs_t;
typedef void uv_loop_t;
enum {
  UV_E2BIG = -1,
  UV_EACCES = -2,
  UV_EADDRINUSE = -3,
  UV_EADDRNOTAVAIL = -4,
  UV_EAFNOSUPPORT = -5,
  UV_EAGAIN = -6,
  UV_EBADF = -7,
  UV_EBUSY = -8,
  UV_ECONNABORTED = -9,
  UV_ECONNREFUSED = -10,
  UV_ECONNRESET = -11,
  UV_EDESTADDRREQ = -12,
  UV_EEXIST = -13,
  UV_EFAULT = -14,
  UV_EFBIG = -15,
  UV_EHOSTUNREACH = -16,
  UV_EILSEQ = -17,
  UV_EINTR = -18,
  UV_EINVAL = -19,
  UV_EIO = -20,
  UV_EISCONN = -21,
  UV_EISDIR = -22,
  UV_ELOOP = -23,
  UV_EMFILE = -24,
  UV_EMLINK = -25,
  UV_EMSGSIZE = -26,
  UV_ENAMETOOLONG = -27,
  UV_ENETDOWN = -28,
  UV_ENETUNREACH = -29,
  UV_ENFILE = -30,
  UV_ENOBUFS = -31,
  UV_ENODATA = -32,
  UV_ENODEV = -33,
  UV_ENOENT = -34,
  UV_ENOMEM = -35,
  UV_ENOPROTOOPT = -36,
  UV_ENOSPC = -37,
  UV_ENOSYS = -38,
  UV_ENOTCONN = -39,
  UV_ENOTDIR = -40,
  UV_ENOTEMPTY = -41,
  UV_ENOTSOCK = -42,
  UV_ENOTSUP = -43,
  UV_ENOTTY = -44,
  UV_ENXIO = -45,
  UV_EPERM = -46,
  UV_EPIPE = -47,
  UV_EPROTO = -48,
  UV_EPROTONOSUPPORT = -49,
  UV_EPROTOTYPE = -50,
  UV_ERANGE = -51,
  UV_EROFS = -52,
  UV_ESPIPE = -53,
  UV_ESRCH = -54,
  UV_ETIMEDOUT = -55,
  UV_ETXTBSY = -56,
  UV_EXDEV = -57,
};
#ifdef __cplusplus
extern "C" {
#endif
const char* uv_strerror(int err);
const char* uv_err_name(int err);
int  uv_os_tmpdir(char* buffer, size_t* size);
int  uv_fs_link(uv_loop_t*, uv_fs_t*, const char* path, const char* new_path, void* cb);
int  uv_fs_mkstemp(uv_loop_t*, uv_fs_t*, const char* tpl, void* cb);
int  uv_fs_mkdtemp(uv_loop_t*, uv_fs_t*, const char* tpl, void* cb);
void uv_fs_req_cleanup(uv_fs_t*);
#ifdef __cplusplus
}
#endif
#endif
