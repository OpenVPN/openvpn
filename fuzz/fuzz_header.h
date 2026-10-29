/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef FUZZ_H
#define FUZZ_H

#include <sys/types.h>
#include <sys/socket.h>

// Forward declared because we want to use FuzzedDataProvider,
// which requires CPP.
extern ssize_t fuzz_get_random_data(void *buf, size_t len);

ssize_t fuzz_recv(int sockfd, void *buf, size_t len, int flags){
	return fuzz_get_random_data(buf, len);
}

ssize_t fuzz_read(int sockfd, void *buf, size_t len){
	return fuzz_get_random_data(buf, len);
}

ssize_t fuzz_write(int fd, const void *buf, size_t count) {
  return count;
}

int fuzz_isatty(int fd) {
  return 1;
}

char *fuzz_fgets(char *s, int size, FILE *stream) {
  ssize_t v = fuzz_get_random_data(s, size-1);
  // We use fgets to get trusted input. As such, assume we have
  // an ascii printable char at the beginning.
  printf("Calling into fgets\n");
  if (s[0] <= 0x21 || s[0] >= 0x7f) {
    s[0] = 'A';
  }
  s[size-1] = '\0';
  return s;
}

int fuzz_select(int nfds, fd_set *readfds, fd_set *writefds,fd_set *exceptfds, struct timeval *timeout) {
  char val;
  ssize_t c = fuzz_get_random_data(&val, 1);
  return c;
}

ssize_t fuzz_send(int sockfd, const void *buf, size_t len, int flags) {
  return len;
}

FILE *fp_p = NULL;
FILE *fuzz_fopen(const char *pathname, const char *mode) {
   if (mode == NULL) return fp_p;
   return fp_p;
}

int fuzz_fclose(FILE *stream) {
   if (stream == NULL) return 1;
   return 2;
}

size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen) {
  if (buf == NULL) {
    return len;
  }
  return len;
}

#endif
