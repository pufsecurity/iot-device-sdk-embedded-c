/* Copyright 2018-2020 Google LLC
 *
 * This is part of the Google Cloud IoT Device SDK for Embedded C.
 * It is licensed under the BSD 3-Clause license; you may not use this file
 * except in compliance with the License.
 *
 * You may obtain a copy of the License at:
 *  https://opensource.org/licenses/BSD-3-Clause
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iotc_bsp_time.h>

#include <stddef.h>
#include <sys/time.h>
#include <time.h>
#ifdef PUF
#include <stdio.h>
#endif

void iotc_bsp_time_init() { /* empty */
}

iotc_time_t iotc_bsp_time_getcurrenttime_seconds() {
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  return (iotc_time_t)((current_time.tv_sec) +
                       (current_time.tv_usec + 500000) /
                           1000000); /* round the microseconds to seconds */
}

iotc_time_t iotc_bsp_time_getcurrenttime_milliseconds() {
  struct timeval current_time;
  gettimeofday(&current_time, NULL);
  #ifdef PUF
  iotc_bsp_time_print_currenttime_day_time();
  #endif
  return (iotc_time_t)((current_time.tv_sec * 1000) +
                       (current_time.tv_usec + 500) /
                           1000); /* round the microseconds to milliseconds */
}

iotc_time_t iotc_bsp_time_getmonotonictime_milliseconds() {
  struct timespec current_time;
  clock_gettime(CLOCK_MONOTONIC, &current_time);
  return (iotc_time_t)((current_time.tv_sec * 1000) +
                       (current_time.tv_nsec / 1000000));
}

#ifdef PUF
void iotc_bsp_time_print_currenttime_day_time() {

  time_t time_seconds = time(0);
  struct timeval current_time;
  struct tm lt;
  uint64_t us;
  gettimeofday(&current_time, NULL);
  localtime_r(&time_seconds, &lt);
  us = current_time.tv_usec %1000000;
 
  printf("[Time %02d/%02d/%04d %02d:%02d:%02d.%06d]", lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900,
            lt.tm_hour, lt.tm_min, lt.tm_sec, us);
      
}
#endif
