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

#pragma once

#include <string>
#include <unordered_map>
#include "mgos_mongoose.h"
#include "mgos_wemo.h"

class UPNPServer {
   public:
    struct DeviceInfo {
        std::string name;
        void* userData;  // used within event handler
        on_device_control_event_handler pfnStateEventHandler;
    };

    UPNPServer();

    void init();

    // TODO: support new device including description
    bool addDevice(const DeviceInfo& deviceInfo);

   private:
    mg_connection* udpServer;
    mg_connection* httpServer;

    bool sendResponseRequest;
    enum ResponseRequestType { RRT_ROOTDEVICE, RRT_CLOSECOMPANION };

    ResponseRequestType sendResponseRequestType;

    std::unordered_map<std::string, DeviceInfo> devices;
    // TODO: define mapping between http server & deviceInfo

    void sendSearchResponse(struct mg_connection* nc);

    bool onHTTPMessage(mg_connection* nc, http_message* message);

    bool processHTTPMessage(mg_connection* nc, bool isGet, const mg_str& uri,
                            const mg_str& body);

    int calculateDeviceDescriptionSize() const;

    void populateDeviceDescription(char* buffer, int bufferSize) const;

    bool processDescriptionRequest(mg_connection* nc, const mg_str& body);

    int parseBinaryState(const mg_str& body) const;

    bool processControlRequest(mg_connection* nc, const mg_str& body);

    bool sendHTTPResponse(mg_connection* nc, int status_code,
                          const char* message);

    bool onUNPNMessage(mg_connection* nc, const std::string& msg);

    mg_connection* initHTTPServer();

    void initUDPServer();

    bool startUPNPService();

    void stopUPNPService();

    static void onHTTPEvent(mg_connection* nc, int ev, void* ev_data,
                            void* /*user_data*/);

    static void onUPNPEvent(mg_connection* nc, int ev, void* /*ev_data*/,
                            void* /*user_data*/);

    static void onNetworkEvent(int ev, void* /*evd*/, void* arg);

    bool isValidDeviceInfo(const DeviceInfo& deviceInfo) const;
};
