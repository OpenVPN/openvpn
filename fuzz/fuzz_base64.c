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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base64.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > 500) {
    return 0;
  }

  char *new_str = (char *)malloc(size + 1);
  if (new_str == NULL) {
    return 0;
  }
  memcpy(new_str, data, size);
  new_str[size] = '\0';

  char *str = NULL;
  openvpn_base64_encode(data, size, &str);
  if(str != NULL) {
    free(str);
  }

  uint16_t outsize = 10000;
  char *output_buf = (char *)malloc(outsize);
  openvpn_base64_decode(new_str, output_buf, outsize);
  free(output_buf);

  free(new_str);
  return 0;
}
