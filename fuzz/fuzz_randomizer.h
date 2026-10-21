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

#include <stdio.h>
#include <stdint.h>

void fuzz_random_init(const uint8_t *data, size_t size);
void fuzz_random_destroy();
char *get_random_string();
int fuzz_randomizer_get_int(int min, int max);
size_t fuzz_get_random_data(void *buf, size_t len);
char *fuzz_random_get_string_max_length(int max_len);

void gb_init();
void gb_cleanup();
char *gb_get_random_string();

int fuzz_success;
