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
#include <assert.h>

FuzzedDataProvider *prov = NULL;

extern "C" void fuzz_random_init(const uint8_t *data, size_t size) {
   assert(prov == NULL);
   prov = new FuzzedDataProvider(data, size);
}

extern "C" void fuzz_random_destroy() {
   assert(prov != NULL);
  delete prov;
  prov = NULL;
}

extern "C" char *get_random_string() {
   assert(prov != NULL);

   std::string s1 = prov->ConsumeRandomLengthString();
   char *tmp = (char *)malloc(s1.size() + 1);
   memcpy(tmp, s1.c_str(), s1.size());
   tmp[s1.size()] = '\0';
   return tmp;
}

extern "C" int fuzz_randomizer_get_int(int min, int max) {
   assert(prov != NULL);
   return prov->ConsumeIntegralInRange<int>(min, max);
} 

extern "C" char *fuzz_random_get_string_max_length(int max_len) {
  assert(prov != NULL);

  std::string s1 = prov->ConsumeBytesAsString(
                           prov->ConsumeIntegralInRange<uint32_t>(1, max_len));
  char *tmp123 = (char*)malloc(s1.size()+1);
  memcpy(tmp123, s1.c_str(), s1.size());
  tmp123[s1.size()] = '\0';

  return tmp123;
}

extern "C" size_t fuzz_get_random_data(void *buf, size_t len) {
  assert(prov != NULL);
  size_t ret_val;
  char *cbuf = (char*)buf;

  if (prov->remaining_bytes() == 0) {
    return -1;
  }

  double prob = prov->ConsumeProbability<double>();
  if (prob < 0.05) {
    return 0;
  }

  //if (len == 1) {
  //  ret_val = prov->ConsumeData(buf, 1);
  //  return ret_val;
  //}
  ret_val = prov->ConsumeData(buf, len);
  return ret_val;
}
 

// Simple garbage collector
#define GB_SIZE 100
void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

// If the garbage collector is used then this must be called as first thing
// during a fuzz run.
extern "C" void gb_init() {
  pointer_idx = 0;

   for (int i = 0; i < GB_SIZE; i++) {
     pointer_arr[i] = NULL;
   }
}

extern "C" void gb_cleanup() {
  for(int i = 0; i < GB_SIZE; i++) {
    if (pointer_arr[i] != NULL) {
      free(pointer_arr[i]);
    }
  }
}

extern "C" char *gb_get_random_string() {
  char *tmp = get_random_string();
  pointer_arr[pointer_idx++] = (void*)tmp;
  return tmp;
}

