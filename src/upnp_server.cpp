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

#include "unpn_server.h"

#include <mgos_config.h>
#include "mgos.h"
#include "mgos_mongoose.h"
#include "mgos_net.h"

#include "utils.h"

#include "lwip/igmp.h"
#include "lwip/inet.h"

#include "lwip/ip_addr.h"

#include <string>
#include <unordered_map>

namespace {

constexpr int UNPN_UDP_PORT = 1900;
constexpr int UNPN_HTTP_PORT = 1901;

constexpr char UPNP_LISTENER_ADDRESS[] = "239.255.255.250";

constexpr char UPNP_LISTENER_SPEC[] = "udp://239.255.255.250:1900";
constexpr char UPNP_HTTP_SERVICE_SPEC[] = "tcp://%s:1901";

constexpr char UNPN_RESPONSE_ROOTDEVICE_TEMPLATE[] =
    "HTTP/1.1 200 OK ## copy\r\n"
    "CACHE-CONTROL: max-age=86400\r\n"
    "EXT:\r\n"
    "LOCATION: http://%s:%d/description.xml\r\n"
    "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n"
    "01-NLS: 905bfa3c-1dd2-11b2-8928-%s\r\n"
    "SERVER: Unspecified, UPnP/1.0, Unspecified\r\n"
    "X-User-Agent: redsonic\r\n"
    "ST: urn:rootdevice\r\n"
    "USN: uuid:Socket-1_0-%s::urn:rootdevice\r\n";

constexpr char UNPN_RESPONSE_CLOSECOMPANION_TEMPLATE[] =
    "HTTP/1.1 200 OK ## copy\r\n"
    "CACHE-CONTROL: max-age=86400\r\n"
    "EXT:\r\n"
    "LOCATION: http://%s:%d/description.xml\r\n"
    "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n"
    "01-NLS: 905bfa3c-1dd2-11b2-8928-%s\r\n"
    "SERVER: Unspecified, UPnP/1.0, Unspecified\r\n"
    "X-User-Agent: redsonic\r\n"
    "ST: urn:closecompanion:service:light:1\r\n"
    "USN: "
    "uuid:Socket-1_0-%s::urn:closecompanion:service:light:1\r\n";

constexpr int DEVICE_NAME_MAX_LENGTH = 16;
constexpr int DEVICE_UDN_MAX_LENGTH = 32;

constexpr char UNPN_DESCRIPTION_DEVICE_TEMPLATE[] =
    "<device>\r\n"
    "    <deviceType>urn:MakerMusings:device:controllee:1</deviceType>\r\n"
    "    <friendlyName>%s</friendlyName>\r\n"  // name
    "    <manufacturer>Belkin International Inc.</manufacturer>\r\n"
    "    <modelName>Emulated Socket</modelName>\r\n"
    "    <modelNumber>3.1415</modelNumber>\r\n"
    "    <UDN>uuid:Socket-1_0-%s</UDN>\r\n"  // unique-id
    "</device>\r\n";

constexpr char UNPN_DESCRIPTION_TEMPLATE[] =
    "<?xml version=\"1.0\"?>\r\n"
    "<root>\r\n"
    "%s\r\n"
    "</root>\r\n";

constexpr char UNPN_CONTROL_RESPONSE_TEMPLATE[] =
    "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
    "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\r\n"
    "<s:Body>\r\n"
    "   <u:%sStateResponse xmlns:u=\"urn:Belkin:service:basicevent:1\">\r\n"
    "   <BinaryState>%d</BinaryState>\r\n"
    "   </u:%sStateResponse>\r\n"
    "</s:Body>\r\n"
    "</s:Envelope>\r\n";

bool upnpHALJoinGroup(const char* group) {
    ip_addr_t group_addr;
    group_addr.addr = inet_addr(group);

#ifdef IP4_ADDR_ANY4
#define ADDR IP4_ADDR_ANY4
#else
#define ADDR IP_ADDR_ANY
#endif

    err_t err = igmp_joingroup(ADDR, &group_addr);
    if (err != ERR_OK) {
        LOG(LL_ERROR, ("udp_join_multigroup failed! (%d)", (int)err));
        return false;
    }

    return true;
}

static void upnpJoinGroup(const char* address) {
    LOG(LL_INFO, ("Joining %s", address));
    if (!upnpHALJoinGroup(address)) {
        LOG(LL_ERROR, ("Failed to join %s", address));
    }
}

const char* getLocalIPAddress() { return mgos_sys_config_get_wifi_sta_ip(); }

struct mg_connection* upnpGetListener(const char* address, int port,
                                      mg_event_handler_t handler,
                                      void* userData) {
    struct mg_connection* lc =
        mg_bind(mgos_get_mgr(), UPNP_LISTENER_SPEC, handler, userData);
    if (lc == NULL) {
        LOG(LL_ERROR, ("Failed to listen on %s", UPNP_LISTENER_SPEC));
        return NULL;
    }
    lc->user_data = userData;
    LOG(LL_INFO, ("Listening on %s", UPNP_LISTENER_SPEC));

    lc->sa.sin.sin_port = htons(port);
    inet_aton(address, &lc->sa.sin.sin_addr);

    upnpJoinGroup(address);

    return lc;
}

}  // namespace

void UPNPServer::sendSearchResponse(struct mg_connection* nc) {
    // TODO: setup timer for some value to avoid flooding - see spec 1.3.3
    // Search response

    // TODO: implement for each device

    if (sendResponseRequest) {
        const char* macAddr = mgos_sys_ro_vars_get_mac_address();

        const char* responseTemplate =
            sendResponseRequestType == RRT_ROOTDEVICE
                ? UNPN_RESPONSE_ROOTDEVICE_TEMPLATE
                : UNPN_RESPONSE_CLOSECOMPANION_TEMPLATE;

        LOG(LL_INFO, ("Response for %d", sendResponseRequestType));

        char response[strlen(responseTemplate) + 128];
        snprintf(response, sizeof(response), responseTemplate,
                 getLocalIPAddress(), UNPN_HTTP_PORT, macAddr, macAddr);
        LOG(LL_DEBUG, ("onUNPNMessage response \n%s", (response)));
        LOG(LL_DEBUG, ("onUNPNMessage response %d bytes", (strlen(response))));

        mg_send(nc, response, strlen(response));
        sendResponseRequest = false;
    }
}

bool UPNPServer::onHTTPMessage(mg_connection* nc, http_message* message) {
    mg_str uriNullTerminated = mg_strdup_nul(message->uri);
    LOG(LL_DEBUG, ("onHTTPMessage uri %s", uriNullTerminated.p));
    mg_strfree(&uriNullTerminated);
    const bool isGet = mg_vcasecmp(&message->method, "get") == 0;
    return processHTTPMessage(nc, isGet, message->uri, message->body);
}

bool UPNPServer::processHTTPMessage(mg_connection* nc, bool isGet,
                                    const mg_str& uri, const mg_str& body) {
    if (isGet) {
        if (mg_vcasecmp(&uri, "/description.xml") == 0) {
            return processDescriptionRequest(nc, body);
        }
    } else {
        if (mg_vcasecmp(&uri, "/upnp/control/basicevent1") == 0) {
            return processControlRequest(nc, body);
        }
    }

    return false;
}

int UPNPServer::calculateDeviceDescriptionSize() const {
    int size = strlen(UNPN_DESCRIPTION_TEMPLATE);
    // TODO: make it as a constexpr calculation
    const int singleDeviceStrLen = strlen(UNPN_CONTROL_RESPONSE_TEMPLATE) +
                                   DEVICE_NAME_MAX_LENGTH +
                                   DEVICE_UDN_MAX_LENGTH;
    size += singleDeviceStrLen * devices.size();
    return size;
}

void UPNPServer::populateDeviceDescription(char* buffer, int bufferSize) const {
    char macAddr[32];
    getMacAddress(macAddr);

    // population list of devices string representation
    // const int response_size = calculateDeviceDescriptionSize();
    char device_info_str[bufferSize];
    char* msg = device_info_str;
    int pos = 0;
    for (auto& d : devices) {
        snprintf(msg, bufferSize - pos, UNPN_DESCRIPTION_DEVICE_TEMPLATE,
                 d.first.c_str(), macAddr);
        pos += strlen(msg);
        msg += pos;
    }

    snprintf(buffer, bufferSize, UNPN_DESCRIPTION_TEMPLATE, device_info_str);
}

bool UPNPServer::processDescriptionRequest(mg_connection* nc,
                                           const mg_str& body) {
    LOG(LL_DEBUG, ("processDescriptionRequest()"));

    const int response_size = calculateDeviceDescriptionSize();
    char response[response_size];
    populateDeviceDescription(response, response_size);

    return sendHTTPResponse(nc, 200, response);
}

int UPNPServer::parseBinaryState(const mg_str& body) const {
    const char* ptr = mg_strstr(body, mg_mk_str("</BinaryState>"));
    ptr--;
    if (*ptr == '1')
        return 1;
    else
        return 0;
}

bool UPNPServer::processControlRequest(mg_connection* nc, const mg_str& body) {
    LOG(LL_INFO, ("processControlRequest() devices size = %d", devices.size()));
    if (devices.size() == 0) {
        LOG(LL_ERROR, ("processControlRequest() devices.size() == 0"));
        // TODO: send http response error - no devices
        return false;
    }

    char response_http_buffer[strlen(UNPN_CONTROL_RESPONSE_TEMPLATE) + 128];

    const DeviceInfo& devInfo = devices.begin()->second;

    // determine type of request SetBinaryState vs GetBinaryState
    if (mg_strstr(body, mg_mk_str("SetBinaryState")) != nullptr) {
        const int newState = parseBinaryState(body);
        devInfo.pfnStateEventHandler(true, newState, devInfo.userData);
        snprintf(response_http_buffer, sizeof(response_http_buffer),
                 UNPN_CONTROL_RESPONSE_TEMPLATE, "SetBinary", newState,
                 "SetBinary");
    } else if (mg_strstr(body, mg_mk_str("GetBinaryState")) != nullptr) {
        const int currentState =
            devInfo.pfnStateEventHandler(false, 0, devInfo.userData);
        snprintf(response_http_buffer, sizeof(response_http_buffer),
                 UNPN_CONTROL_RESPONSE_TEMPLATE, "GetBinary", currentState,
                 "GetBinary");
    } else {
        LOG(LL_ERROR, ("processControlRequest() invalid request"));
        // TODO: send http response error - invalid request
        return false;
    }

    return sendHTTPResponse(nc, 200, response_http_buffer);
}

bool UPNPServer::sendHTTPResponse(mg_connection* nc, int status_code,
                                  const char* message) {
    LOG(LL_DEBUG, ("sendHTTPResponse \n%s", (message)));

    // TODO: add argument to define content type (enum)
    mg_send_head(nc, status_code, strlen(message), "Content-Type: text/xml");
    mg_send(nc, message, strlen(message));

    return true;
}

bool UPNPServer::onUNPNMessage(mg_connection* nc, const std::string& msg) {
    std::size_t found = msg.find("M-SEARCH");
    if (found != std::string::npos) {
        LOG(LL_DEBUG, ("onUNPNMessage content \n%s", (msg.c_str())));
        if (msg.find("ssdp:discover", found + 1) != std::string::npos ||
            msg.find("upnp:rootdevice", found + 1) != std::string::npos) {
            sendResponseRequest = true;

            if (msg.find("urn:closecompanion:service:light:1", found + 1) !=
                std::string::npos) {
                sendResponseRequestType = RRT_CLOSECOMPANION;
            } else {
                sendResponseRequestType = RRT_ROOTDEVICE;
            }

            return true;
        }
    }
    return false;
}

mg_connection* UPNPServer::initHTTPServer() {
    LOG(LL_DEBUG, ("initHTTPServer for instance %p", (this)));

    char serverSpec[128];
    snprintf(serverSpec, 128, UPNP_HTTP_SERVICE_SPEC, getLocalIPAddress());

    struct mg_connection* lc =
        mg_bind(mgos_get_mgr(), serverSpec, onHTTPEvent, this);
    if (lc == NULL) {
        LOG(LL_ERROR, ("Failed to listen on %s", serverSpec));
        return NULL;
    }

    lc->user_data = this;
    LOG(LL_INFO, ("Listening on %s", serverSpec));

    mg_set_protocol_http_websocket(lc);

    return lc;
}

void UPNPServer::initUDPServer() {
    LOG(LL_INFO, ("initUDPServer for instance %p", (this)));
    udpServer = upnpGetListener(UPNP_LISTENER_ADDRESS, UNPN_UDP_PORT,
                                onUPNPEvent, this);
}

bool UPNPServer::startUPNPService() {
    // TODO: added error checking
    // TODO: add initialization per added device
    httpServer = initHTTPServer();
    initUDPServer();

    return true;
}

void UPNPServer::stopUPNPService() {
    // TODO: added error checking
    LOG(LL_ERROR, ("%s", "stopUPNPService() event not implemented"));
}

void UPNPServer::onHTTPEvent(mg_connection* nc, int ev, void* ev_data,
                             void* /*user_data*/) {
    if (ev == MG_EV_HTTP_REQUEST) {
        LOG(LL_DEBUG, ("onHTTPEvent MG_EV_HTTP_REQUEST event"));
        struct http_message* hm = static_cast<http_message*>(ev_data);
        UPNPServer* instance = static_cast<UPNPServer*>(nc->user_data);
        instance->onHTTPMessage(nc, hm);
    }
}

void UPNPServer::onUPNPEvent(mg_connection* nc, int ev, void* /*ev_data*/,
                             void* /*user_data*/) {
    UPNPServer* instance = static_cast<UPNPServer*>(nc->user_data);

    switch (ev) {
        case MG_EV_POLL: {
            // LOG(LL_DEBUG, ("onUPNPEvent MG_EV_POLL event"));
            if (instance->sendResponseRequest) {
                instance->sendSearchResponse(nc);
                nc->flags |= MG_F_SEND_AND_CLOSE;
            }
            break;
        }
        case MG_EV_ACCEPT: {
            LOG(LL_DEBUG, ("onUPNPEvent MG_EV_ACCEPT event"));
            instance->sendResponseRequest = false;
            break;
        }
        case MG_EV_RECV: {
            LOG(LL_DEBUG, ("onUPNPEvent MG_EV_RECV event"));

            struct mbuf* io = &nc->recv_mbuf;

            char* buffer = static_cast<char*>(io->buf);
            buffer[io->len] = 0;
            const std::string message(buffer);
            if (instance->onUNPNMessage(nc, message)) {
                nc->flags &= ~MG_F_SEND_AND_CLOSE;
            } else {
                mbuf_remove(io, io->len);
                nc->flags |= MG_F_CLOSE_IMMEDIATELY;
            }
            break;
        }
        case MG_EV_SEND: {
            LOG(LL_DEBUG, ("onUPNPEvent MG_EV_SEND event"));
            nc->flags |= MG_F_SEND_AND_CLOSE;
            break;
        }
        case MG_EV_CLOSE: {
            LOG(LL_DEBUG, ("onUPNPEvent MG_EV_CLOSE event"));
            break;
        }
        default: {
            LOG(LL_DEBUG, ("onUPNPEvent not implemented for event %d", (ev)));
            break;
        }
    }
}

void UPNPServer::onNetworkEvent(int ev, void* /*evd*/, void* arg) {
    switch (ev) {
        case MGOS_NET_EV_IP_ACQUIRED: {
            LOG(LL_DEBUG, ("Net got an IP address"));
            UPNPServer* instance = static_cast<UPNPServer*>(arg);
            instance->startUPNPService();
            break;
        }
        case MGOS_NET_EV_DISCONNECTED: {
            LOG(LL_DEBUG, ("Net lost connection"));
            UPNPServer* instance = static_cast<UPNPServer*>(arg);
            instance->stopUPNPService();
            break;
        }
        default:
            break;
    }
}

bool UPNPServer::isValidDeviceInfo(const DeviceInfo& deviceInfo) const {
    if (deviceInfo.name.size() >= DEVICE_NAME_MAX_LENGTH) return false;
    return true;
}

UPNPServer::UPNPServer()
    : udpServer(nullptr), httpServer(nullptr), sendResponseRequest(false) {}

void UPNPServer::init() {
    // register to wait on network ready
    mgos_event_add_group_handler(MGOS_EVENT_GRP_NET, onNetworkEvent, this);
}

// TODO: support new device including description
bool UPNPServer::addDevice(const DeviceInfo& deviceInfo) {
    if (!isValidDeviceInfo(deviceInfo)) return false;

    if (devices.find(deviceInfo.name) == devices.end()) {
        LOG(LL_INFO, ("addDevice() - new device registered %s",
                      deviceInfo.name.c_str()));
        devices[deviceInfo.name] = deviceInfo;
        return true;
    } else
        LOG(LL_ERROR,
            ("addDevice() - device exists %s", deviceInfo.name.c_str()));
    return false;
}
