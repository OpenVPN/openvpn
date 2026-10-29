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

#include <fuzzer/FuzzedDataProvider.h>

// Returns a NULL-terminated C string that should be freed by the caller.
char *get_modifiable_string(FuzzedDataProvider &provider) {
  std::string s1 = provider.ConsumeRandomLengthString();
  char *tmp = (char *)malloc(s1.size() + 1);
  memcpy(tmp, s1.c_str(), s1.size());
  tmp[s1.size()] = '\0';
  return tmp;
}

FuzzedDataProvider *prov = NULL;


extern "C" ssize_t fuzz_get_random_data(void *buf, size_t len) {
  size_t ret_val;
  char *cbuf = (char*)buf;

  if (prov->remaining_bytes() == 0) {
    return -1;
  }

  double prob = prov->ConsumeProbability<double>();
  if (prob < 0.05) {
    return 0;
  }

  if (len == 1) {
    ret_val = prov->ConsumeData(buf, 1);
    return ret_val;
  }
  ret_val = prov->ConsumeData(buf, len);
  return ret_val;
}

