# ESPHttpxClient

HTTP/HTTPS client for ESP32 with optional TLS support, asynchronous operation, and event-driven callbacks.

---

## Features

- Plain HTTP and HTTPS support.
- TLS with certificate validation.
- Event-driven interface:
    - Status, headers, body data, errors, connection events.
- Request body writing via callback.
- Handles chunked transfer encoding and content-length.
- Automatic HTTP redirection with configurable limit.
- URL-encoded paths and query parameters.
- Keep-alive or close connections after request.

---

### Why build this instead of using the available clients?

This client was created because I wasn’t able to use the Arduino or ESP-IDF HTTP clients effectively in my particular setup for long-lived connections. So, I built a client designed specifically for my use case.

It provides:

- A non-blocking, loop-driven design (`http.loop()`) suited for persistent connections.
- Support for chunked transfer encoding with incremental data handling via `onWriteData`.
- Complete event callbacks for status updates, headers, incoming data, and error handling.
- Automatic handling of redirects and HTTPS certificate validation.

## Requirements

- ESP32 platform

---

## Full Example

This example demonstrates how to use `ESPHttpxClient` on an ESP32 to make HTTP(S) requests with query parameters, chunked body data, and event handling.

```cpp
#include <Arduino.h>
#include <WiFi.h>
#include <ESPHTTPxClient.h>

using namespace ESP_HTTPX_CLIENT;

ESPHttpxClient http;

void setup() {
    Serial.begin(115200);

    // Connect to Wi-Fi
    WiFi.begin("SSID", "PASSWORD");
    while (WiFi.status() != WL_CONNECTED) {}
    WiFi.setSleep(false);

    Serial.printf("IP address: %s\n", WiFi.localIP().toString().c_str());

    // Example body data
    static const char toSend[] = "Sample request body data...";
    static size_t toSendLen = strlen(toSend);

    // Body write callback
    http.onWriteData([](uint8_t *buffer, size_t bufferSize, size_t index) -> ssize_t {
        if (index >= toSendLen) return -1; // no more data
        ssize_t chunk = min((size_t)16, toSendLen - index);
        memcpy(buffer, toSend + index, chunk);
        return chunk;
    });

    int requestCounter = 0;

    // Event callback
    http.onEvent([&](ESPHttpxClientEvent event, uint8_t *data, size_t len, bool headerTruncated) {
        switch(event) {
            case CONNECTION_SUCCESSFUL_EVENT:
                Serial.println("Connection successful");
                http.sendContentLength(-1); // enable chunked transfer
                http.startBody();
                break;

            case SEND_HOSTNAME_EVENT:
                http.sendHostname("example.com"); // placeholder
                break;
                
            case SEND_METHOD_EVENT:
                http.sendHttpMethod(Method::HTTP_GET);
                break;

            case SEND_PATH_AND_QUERY_EVENT:
                http.sendPath("/api/test");
                http.sendQueryParam("param", "value");
                http.sendQueryParam("i", requestCounter);
                break;

            case DATA_EVENT:
                Serial.print("Received data: ");
                Serial.write((char*)data, len);
                Serial.println();
                break;

            case STATUS_RECEIVED_EVENT:
                Serial.print("Status code: ");
                Serial.write((char*)data, len);
                Serial.println();
                break;

            case HEADER_RECEIVED_EVENT:
                Serial.print("Header: ");
                Serial.write((char*)data, len);
                Serial.println();
                break;

            case CONNECTION_CLOSED_EVENT:
                Serial.println("Connection closed");
                break;

            case REQUEST_FINISHED_EVENT:
                Serial.println("Request finished");
                requestCounter++;
                if (requestCounter < 3) {
                    delay(100);
                    http.sendRequest(); // repeat request
                }
                break;

            case CONNECTION_FAILED_EVENT:
                Serial.println("Connection failed");
                break;

            case ERROR_EVENT:
                Serial.printf("Error code: %d\n", data[0]);
                break;

            default:
                break;
        }
    });

    // Client configuration
    http.setMode(HTTPS_SECURE);  // Options: PLAIN_HTTP, HTTPS_INSECURE, HTTPS_SECURE
    http.setKeepAlive(true);

    // Start request
    http.start();
}

void loop() {
    // Process client events and read/write operations
    http.loop();
}
```

### Notes

- Replace `"SSID"` and `"PASSWORD"` with your Wi-Fi credentials.
- Replace `"example.com"` and `"/api/test"` with your target hostname and path.
- The `onWriteData` callback handles chunked body uploads automatically.
- The `onEvent` callback receives all client events: connection status, headers, data chunks, errors, and request completion.
- Use `http.loop()` frequently in `loop()` to allow the client to process reads, writes, and events.
- `setKeepAlive(true)` allows reusing the connection for multiple requests.
- `setMode(HTTPS_SECURE)` enables TLS with optional certificate verification; use `PLAIN_HTTP` or `HTTPS_INSECURE` as needed.
- Query parameters added via `sendQueryParam()` are automatically URL-encoded.
- The client handles HTTP redirections and chunked transfer encoding internally.