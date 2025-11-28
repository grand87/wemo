/*
 * Copyright 2021 (c) Volodymyr "N0dGrand87" Sharaienko <grandamx@gmail.com>
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "utils.h"

#include <mgos.h>
#include <mgos_config.h>
#include <stdio.h>

void getMacAddress(char* result) {
    uint8_t buffer[6];
    device_get_mac_address(buffer);
    sprintf(result, "%02x%02x%02x%02x%02x%02x", buffer[0], buffer[1], buffer[2],
            buffer[3], buffer[4], buffer[5]);
}
