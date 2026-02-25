//
// Created by xav on 2/23/26.
//

#ifndef ESPHTTPSASYNCLIENT_H
#define ESPHTTPSASYNCLIENT_H

#include <esp_tls.h>
#include <esp_crt_bundle.h>

#define EHTTPSCA_CLIENT_TIMEOUT (-0x1)

#ifdef EHTTPSCA_ENABLE_LOGGING
#define EHTTPSCA_LOG(str) Serial.print(str)
#define EHTTPSCA_LOGW(str, len) Serial.write(str, len)
#define EHTTPSCA_LOGN(str) Serial.print("[EHTTPSCA] "); Serial.println(str)
#define EHTTPSCA_LOGF(str, p...) Serial.print("[EHTTPSCA] "); Serial.printf(str, p)
#else
#define HTTP_LOG(str)
#define HTTP_LOGW(str, len)
#define HTTP_LOGN(str)
#define HTTP_LOGF(str, p...)
#endif

#define EHTTPSCA_WRITE_CHECK(data, len, retval, counter)   \
        ssize_t _res##counter = 0;                     \
        do {                                           \
            _res##counter = writeWithTimeout(data, len); \
            EHTTPSCA_LOGW((const char*) data, len);     \
            if (_res##counter < 0) {                   \
                EHTTPSCA_LOGF("Write error: 0x%x\n", -(int)_res##counter); \
                return retval;                         \
            }                                          \
        } while(false)

#define EHTTPSCA_WRITE_CHECK_VOID(data, len, counter)      \
        do {                                           \
            ssize_t _res##counter = writeWithTimeout(data, len); \
            EHTTPSCA_LOGW((const char*) data, len);     \
            if (_res##counter < 0) {                   \
                EHTTPSCA_LOGF("Write error: 0x%x\n", -(int)_res##counter); \
                return;                                \
            }                                          \
        } while(false)

#define EHTTPSCA_WRITE_BOTH(str) EHTTPSCA_WRITE_CHECK_VOID((const uint8_t*) (str), strlen(str), 0)
#define EHTTPSCA_WRITE_LN_CHECK_VOID() EHTTPSCA_WRITE_CHECK_VOID((const uint8_t*) LINE_FEED, LINE_FEED_LEN, 0)

namespace EHTTPSCA
{
    typedef enum {
        STR2INT_SUCCESS,
        STR2INT_OVERFLOW,
        STR2INT_UNDERFLOW,
        STR2INT_INCONVERTIBLE
    } str2int_errno;

    inline str2int_errno str2ul(unsigned *out, char *s, int base) {
        char *end;
        if (s[0] == '\0' || isspace((unsigned char) s[0]))
            return STR2INT_INCONVERTIBLE;
        errno = 0;
        unsigned long l = strtoul(s, &end, base);
        if (errno == ERANGE && l == ULONG_MAX)
            return STR2INT_OVERFLOW;
        if (*end != '\0')
            return STR2INT_INCONVERTIBLE;
        *out = l;
        return STR2INT_SUCCESS;
    }

    enum Mode
    {
        PLAIN_HTTP,
        HTTPS_SECURE,
        HTTPS_INSECURE, // Only works with the esp-idf, because of pre-compiled code
    };

    enum Method
    {
        HTTP_GET = 0,
        HTTP_POST,
        HTTP_PUT,
        HTTP_DELETE,
    };

    inline const char* methodToString(const Method method)
    {
        switch (method)
        {
            case HTTP_GET: return "GET ";
            case HTTP_POST: return "POST ";
            case HTTP_PUT: return "PUT ";
            case HTTP_DELETE: return "DELETE ";
            default: return nullptr;
        }
    }

    inline bool getHeaderValue(const char *header, size_t len, const char **outStart, size_t *outLen)
    {
        if (header == nullptr || outStart == nullptr || outLen == nullptr || len == 0)
        {
            return false;
        }

        auto start = (const char*) memchr(header, ':', len);
        if (start == nullptr)
        {
            return false;
        }

        start++;
        while (start < (header + len) && isspace((unsigned char) *start))
        {
            start++;
        }

        size_t remaining = len - (start - header);
        if (remaining == 0)
        {
            *outStart = start;
            *outLen = 0;
            return true;
        }

        auto end = (const char*) memchr(start, '\n', remaining);
        if (end == nullptr)
        {
            end = header + len;
        }

        end--;
        while (end > start && isspace((unsigned char) *end))
        {
            end--;
        }

        *outStart = start;
        *outLen = (end - start) + 1;
        return true;
    }

    enum ESPHttpsClientAsyncState
    {
        STOPPED = 0,
        CONNECTING,
        SENDING_BODY,
        READING_STATUS,
        READING_HEADERS,
        READING_DATA,
        READING_CHUNK_SIZE,
        READING_CHUNK_SIZE_CRLF,
        READING_CHUNK_DATA,
        READING_CHUNK_DATA_CRLF,
    };

    enum ESPHttpsClientAsyncEvent
    {
        CONNECTION_SUCCESSFUL_EVENT,
        CONNECTION_FAILED_EVENT,
        WRITE_BODY_EVENT,
        STATUS_RECEIVED_EVENT,
        HEADER_RECEIVED_EVENT,
        DATA_EVENT,
        REQUEST_FINISHED_EVENT,
    };

    static const char* HTTP_VER PROGMEM = " HTTP/1.1";
    static const char *CONTENT_LENGTH_HEADER PROGMEM = "Content-Length";

    static const char *TRANSFER_ENCODING_HEADER PROGMEM = "Transfer-Encoding";
    static constexpr size_t TRANSFER_ENCODING_HEADER_LEN = 17;

    static const char *LOCATION_HEADER PROGMEM = "Location";
    static constexpr size_t LOCATION_HEADER_LEN = 8;

    static const char *CHUNKED_HEADER PROGMEM = "chunked";
    static const char *HOST_HEADER PROGMEM = "Host: ";
    static const char *USER_AGENT_HEADER PROGMEM = "User-Agent: ";
    static const char *CONNECTION_KEEP_HEADER PROGMEM = "Connection: keep-alive";
    static const char *CONNECTION_CLOSE_HEADER PROGMEM = "Connection: close";
    static const char *HEADER_SEPARATOR PROGMEM = ": ";
    static const char *REDIRECTION_STATUS PROGMEM = "301";

    static const char *END_CHUNK_MARKER PROGMEM = "0\r\n\r\n";
    static constexpr size_t END_CHUNK_MARKER_LEN = 5;

    static const char *TERMINATORS[] PROGMEM = {"\r\n\r\n", "\n\n"};
    static constexpr size_t TERMINATORS_COUNT = 2;

    static const char LINE_FEED[] PROGMEM = "\r\n";
    static constexpr size_t LINE_FEED_LEN = 2;

    using ESPHttpsClientAsyncEventHandler = std::function<void(ESPHttpsClientAsyncEvent event, uint8_t *data, size_t len, bool headerTruncated)>;

    template <size_t totalDataSize, size_t headerBufferSize, size_t maxHostnameLen = 128, size_t maxPathLen = 256>
    class ESPHttpsClientAsync
    {
    public:
        ESPHttpsClientAsync(const ESPHttpsClientAsync&) = delete;
        ESPHttpsClientAsync& operator=(const ESPHttpsClientAsync&) = delete;

        explicit ESPHttpsClientAsync(): path{}, hostname{}, dataBuffer{}, currentHeaderBuffer{}
        {
            currentMethod = HTTP_GET;
            keepAlive = false;
            sentPath = false;
            pathLen = 0;
            hostnameLen = 0;
            currentState = STOPPED;
            eventHandler = nullptr;
            handle = nullptr;
            cert = nullptr;
            certLen = 0;
            config = {};
            headerBufferOffset = 0;
            isReceivingChunked = false;
            currentChunkSize = 0;
            currentChunkOffset = 0;
            port = -1;
            mode = HTTPS_SECURE;
            contentLength = 0;
            contentSentLen = 0;
            hasRedirection = false;
            redirectionCount = 0;
            maxRedirections = 5;

            for (size_t i = 0; i < TERMINATORS_COUNT; i++)
            {
                terminatorsLengths[i] = strlen(TERMINATORS[i]);
            }
        }

        ~ESPHttpsClientAsync()
        {
            cleanup();
        }

        void setCertPem(const char *cert)
        {
            this->cert = cert;
            this->certLen = strlen(cert) + 1;
        }

        void setHostname(const char *host)
        {
            snprintf(this->hostname, maxHostnameLen, "%s", host);
            hostnameLen = strlen(hostname);
        }

        void setPath(const char *path, Method method, bool keepAlive = false)
        {
            setPath(path, strlen(path), method, keepAlive);
        }

        void setPath(const char *path, size_t len, Method method, bool keepAlive = false)
        {
            currentMethod = method;
            this->keepAlive = keepAlive;

            size_t finalLen = min(maxPathLen-1, len);
            memcpy(this->path, path, finalLen);
            this->path[finalLen] = 0;
            pathLen = finalLen;
        }

        void setPort(int port)
        {
            this->port = port;
        }

        void setMode(Mode mode)
        {
            this->mode = mode;
        }

        void start()
        {
            if (hostnameLen == 0)
            {
                return;
            }

            if (isTlsStarted())
            {
                EHTTPSCA_LOGN("Tried to connect but connection already started.");
                return;
            }

            handle = esp_tls_init();
            // memset(&config, 0, sizeof(config));

            config = {
                .cacert_buf = mode == PLAIN_HTTP || mode == HTTPS_INSECURE ? nullptr : (const unsigned char*)cert,
                .cacert_bytes = mode == PLAIN_HTTP || mode == HTTPS_INSECURE ? 0 : certLen,
                .non_block = true,
                .skip_common_name = mode == PLAIN_HTTP || mode == HTTPS_INSECURE,
                .is_plain_tcp = mode == PLAIN_HTTP,
            };

            if (mode == HTTPS_SECURE && (cert == nullptr || certLen == 0))
            {
                config.crt_bundle_attach = esp_crt_bundle_attach;
            }

            currentState = CONNECTING;
        }

        void sendHeader(const char *name, const char *value, bool endHeaders = false)
        {
            EHTTPSCA_WRITE_BOTH(name);
            EHTTPSCA_WRITE_BOTH(HEADER_SEPARATOR);
            EHTTPSCA_WRITE_BOTH(value);
            EHTTPSCA_WRITE_LN_CHECK_VOID();

            if (endHeaders)
            {
                EHTTPSCA_WRITE_LN_CHECK_VOID();
                callCb(WRITE_BODY_EVENT);
            }
        }

        void sendContentLength(ssize_t length, bool endHeaders = false)
        {
            contentLength = length;

            if (length >= 0)
            {
                char numBuf[32]{};
                snprintf(numBuf, sizeof(numBuf), "%zu", length);
                sendHeader(CONTENT_LENGTH_HEADER, numBuf, endHeaders);

                if (length == 0)
                {
                    currentState = READING_STATUS;
                }
            }
            else
            {
                sendHeader(TRANSFER_ENCODING_HEADER, CHUNKED_HEADER, endHeaders);
            }
        }

        bool isSendingChunked()
        {
            return contentLength < 0;
        }

        bool write(const char *data)
        {
            return write((uint8_t*) data, strlen(data));
        }

        bool write(const char *data, size_t len)
        {
            return write((const uint8_t*) data, len);
        }

        bool write(const uint8_t *data, size_t len)
        {
            if (currentState != SENDING_BODY)
            {
                return false;
            }

            bool isChunked = isSendingChunked();
            if (isChunked)
            {
                char numBuf[32]{};
                snprintf(numBuf, sizeof(numBuf), "%zx\r\n", len);
                EHTTPSCA_WRITE_CHECK(numBuf, strlen(numBuf), false, 0);
            }

            EHTTPSCA_WRITE_CHECK(data, len, false, 0);
            contentSentLen += len;
            if (isChunked)
            {
                EHTTPSCA_WRITE_CHECK(LINE_FEED, LINE_FEED_LEN, false, 0);
            }

            if (!isChunked && contentSentLen >= contentLength)
            {
                currentState = READING_STATUS;
            }
            return true;
        }

        void endChunkedBody()
        {
            if (isSendingChunked())
            {
                EHTTPSCA_WRITE_CHECK_VOID(END_CHUNK_MARKER, END_CHUNK_MARKER_LEN, 0);
                currentState = READING_STATUS;
            }
        }

        void close()
        {
            cleanup();
        }

        void loop()
        {
            if (handle != nullptr && currentState == CONNECTING)
            {
                int actualPort = port <= 0 ? (mode == PLAIN_HTTP ? 80 : 443) : port;
                int res = esp_tls_conn_new_async(hostname, hostnameLen, actualPort, &config, handle);

                if (res == 1)
                {
                    callCb(CONNECTION_SUCCESSFUL_EVENT);
                }
                else if (res == -1)
                {
                    callCb(CONNECTION_FAILED_EVENT);
                }
            }

            if (handle != nullptr && currentState > SENDING_BODY)
            {
                ssize_t read = esp_tls_conn_read(handle, dataBuffer, totalDataSize);
                if (read == -0x004C) // Reading information from the socket failed
                {
                    EHTTPSCA_LOGN("Connection has been closed forcefully.");
                    callCb(CONNECTION_FAILED_EVENT);
                    return;
                }

                if (read == -0x50)
                {
                    EHTTPSCA_LOGN("Connection reset by peer.");
                    callCb(CONNECTION_FAILED_EVENT);
                    return;
                }

                if (read < 0 && read != -0x6900 && (mode != PLAIN_HTTP || read != EHTTPSCA_CLIENT_TIMEOUT)) // No data of requested type currently available on underlying transport
                {
                    EHTTPSCA_LOGF("Error reading data from socket: 0x%x\n", -read);
                    return;
                }

                if (read <= 0)
                {
                    return;
                }

                size_t start = 0;
                while (start < read)
                {
                    size_t remaining = read - start;

                    switch (currentState)
                    {
                    case READING_STATUS:
                        {
                            EHTTPSCA_LOGN("Searching for status code and message.");
                            uint8_t *statusStart = (uint8_t*) memchr(dataBuffer+start, ' ', remaining);

                            if (statusStart == nullptr)
                            {
                                EHTTPSCA_LOGN("Status code for request not found.");
                                callCb(STATUS_RECEIVED_EVENT, (uint8_t*) "-1", 2);
                                return;
                            }

                            size_t newLen = (statusStart - dataBuffer);
                            if (newLen < 4)
                            {
                                EHTTPSCA_LOGN("Could not parse status code.");
                                callCb(STATUS_RECEIVED_EVENT, (uint8_t*) "-1", 2);
                                return;
                            }

                            statusStart += 1;
                            callCb(STATUS_RECEIVED_EVENT, statusStart, 3);
                            currentState = READING_HEADERS;

                            uint8_t *statusEnd = (uint8_t*) memchr(dataBuffer + start, '\n', remaining);
                            if (statusEnd != nullptr)
                            {
                                start = (statusEnd - dataBuffer) + 1;
                            }

                            continue;
                        }
                    case READING_HEADERS:
                        {
                            if (currentHeaderBuffer[0] == 0)
                            {
                                headerBufferOffset = 0;
                            }

                            bool cont = false;
                            for (size_t i = start; i < read; i++)
                            {
                                bool terminatorFound = false;
                                char c = dataBuffer[i];

                                for (size_t j = 0; j < TERMINATORS_COUNT; j++)
                                {
                                    if (TERMINATORS[j][terminatorMatchCounts[j]] == c)
                                    {
                                        terminatorMatchCounts[j]++;
                                    }
                                    else
                                    {
                                        terminatorMatchCounts[j] = (TERMINATORS[j][0] == c) ? 1 : 0;
                                    }

                                    if (terminatorMatchCounts[j] >= terminatorsLengths[j])
                                    {
                                        terminatorFound = true;
                                        break;
                                    }
                                }

                                if (terminatorFound)
                                {
                                    if (isReceivingChunked)
                                    {
                                        currentState = READING_CHUNK_SIZE;
                                    }
                                    else
                                    {
                                        currentState = READING_DATA;
                                    }

                                    start = i + 1;
                                    cont = true;
                                    break;
                                }

                                if (headerBufferOffset >= headerBufferSize - 1)
                                {
                                    currentHeaderBuffer[headerBufferSize - 1] = 0;
                                    callCb(HEADER_RECEIVED_EVENT, (uint8_t*)currentHeaderBuffer, headerBufferSize - 1, true);
                                    headerBufferOffset = 0;
                                }

                                currentHeaderBuffer[headerBufferOffset++] = c;

                                if (c == '\n')
                                {
                                    size_t lineLength = headerBufferOffset;

                                    if (lineLength >= 2 && currentHeaderBuffer[lineLength - 2] == '\r')
                                    {
                                        lineLength -= 2;
                                    }
                                    else
                                    {
                                        lineLength -= 1;
                                    }

                                    currentHeaderBuffer[lineLength] = 0;
                                    if (lineLength > 0)
                                    {
                                        callCb(HEADER_RECEIVED_EVENT, (uint8_t*) currentHeaderBuffer, lineLength);
                                    }

                                    headerBufferOffset = 0;
                                    currentHeaderBuffer[0] = 0;
                                }
                            }

                            if (cont)
                            {
                                continue;
                            }

                            start = read;
                            break;
                        }
                    case READING_DATA:
                        {
                            EHTTPSCA_LOGF("Read %zu bytes from the socket\n", remaining);
                            callCb(DATA_EVENT, (uint8_t*) dataBuffer + start, remaining);
                            start = read;
                            continue;
                        }
                    case READING_CHUNK_SIZE:
                        {
                            bool cont = false;
                            uint8_t *offsetBuffer = dataBuffer + start;
                            for (size_t i = 0; i < remaining; i++)
                            {
                                if (currentChunkOffset >= sizeof(chunkSizeBuf)-1)
                                {
                                    EHTTPSCA_LOGN("Could not parse chunk size.");
                                    callCb(CONNECTION_FAILED_EVENT);
                                    return;
                                }

                                if (offsetBuffer[i] == '\n')
                                {
                                    chunkSizeBuf[currentChunkOffset] = 0;
                                    currentState = READING_CHUNK_SIZE_CRLF;
                                    start += i;
                                    cont = true;
                                    break;
                                }

                                if (offsetBuffer[i] == '\r')
                                {
                                    chunkSizeBuf[currentChunkOffset] = 0;
                                    currentState = READING_CHUNK_SIZE_CRLF;
                                    start += i + 1;
                                    cont = true;
                                    break;
                                }

                                chunkSizeBuf[currentChunkOffset] = offsetBuffer[i];
                                currentChunkOffset++;
                            }

                            if (cont)
                            {
                                continue;
                            }
                            break;
                        }
                    case READING_CHUNK_SIZE_CRLF:
                        {
                            char c = (dataBuffer + start)[0];
                            if (c != '\n')
                            {
                                EHTTPSCA_LOGN("Error parsing chunk header, invalid line ending.");
                                callCb(CONNECTION_FAILED_EVENT);
                                return;
                            }

                            int res = str2ul(&currentChunkSize, chunkSizeBuf, 16);
                            if (res != STR2INT_SUCCESS)
                            {
                                EHTTPSCA_LOGF("Error parsing chunk size: %d\n", res);
                                callCb(CONNECTION_FAILED_EVENT);
                                return;
                            }

                            EHTTPSCA_LOGF("Current chunk size is %zu\n", currentChunkSize);
                            if (currentChunkSize == 0)
                            {
                                callCb(CONNECTION_FAILED_EVENT); // Will convert to REQUEST_FINISHED automatically
                                return;
                            }

                            currentState = READING_CHUNK_DATA;
                            start++;
                            currentChunkOffset = 0;
                            break;
                        }
                    case READING_CHUNK_DATA:
                        {
                            size_t available = remaining;
                            size_t remaining = currentChunkSize - currentChunkOffset;

                            size_t toConsume = (available < remaining) ? available : remaining;
                            callCb(DATA_EVENT, dataBuffer + start, toConsume);

                            currentChunkOffset += toConsume;
                            start += toConsume;

                            if (currentChunkOffset == currentChunkSize)
                            {
                                currentState = READING_CHUNK_DATA_CRLF;
                                currentChunkOffset = 0;
                            }
                            break;
                        }
                    case READING_CHUNK_DATA_CRLF:
                        {
                            size_t available = remaining;
                            if (available == 0)
                            {
                                continue;
                            }

                            char c = dataBuffer[start];
                            if (c == '\r')
                            {
                                start++;
                                if (start >= read)
                                {
                                    continue;
                                }

                                if (dataBuffer[start] != '\n')
                                {
                                    EHTTPSCA_LOGN("Invalid chunk terminator (CR not followed by LF).");
                                    callCb(CONNECTION_FAILED_EVENT);
                                    return;
                                }

                                start++;
                                currentState = READING_CHUNK_SIZE;
                                continue;
                            }

                            if (c == '\n')
                            {
                                start++;
                                currentState = READING_CHUNK_SIZE;
                                continue;
                            }

                            EHTTPSCA_LOGN("Invalid chunk terminator (expected CRLF or LF).");
                            callCb(CONNECTION_FAILED_EVENT);
                            return;
                        }
                    default: ;
                    }
                }
            }
        }

        void onEvent(ESPHttpsClientAsyncEventHandler cb)
        {
            eventHandler = cb;
        }
    private:

        void sendPath(const char *userAgent = "ESP32-ESP-IDF-CLIENT")
        {
            const char *methodStr = methodToString(currentMethod);
            if (methodStr == nullptr || sentPath)
            {
                return;
            }

            EHTTPSCA_WRITE_BOTH(methodStr);
            EHTTPSCA_WRITE_BOTH(pathLen == 0 ? "/" : path);
            EHTTPSCA_WRITE_BOTH(HTTP_VER);
            EHTTPSCA_WRITE_LN_CHECK_VOID();

            EHTTPSCA_WRITE_BOTH(HOST_HEADER);
            EHTTPSCA_WRITE_BOTH(hostname);
            EHTTPSCA_WRITE_LN_CHECK_VOID();

            EHTTPSCA_WRITE_BOTH(USER_AGENT_HEADER);
            EHTTPSCA_WRITE_BOTH(userAgent);
            EHTTPSCA_WRITE_LN_CHECK_VOID();

            EHTTPSCA_WRITE_BOTH(keepAlive ? CONNECTION_KEEP_HEADER : CONNECTION_CLOSE_HEADER);
            EHTTPSCA_WRITE_LN_CHECK_VOID();
            sentPath = true;
        }

        ssize_t writeWithTimeout(const char *data, size_t len, unsigned long timeout = 2500)
        {
            return writeWithTimeout((const uint8_t*) data, len, timeout);
        }

        ssize_t writeWithTimeout(const uint8_t *data, size_t len, unsigned long timeout = 2500)
        {
            unsigned long timer = millis();
            ssize_t remaining = len;

            while (remaining > 0)
            {
                if (millis() - timer > timeout)
                {
                    break;
                }

                ssize_t sent = esp_tls_conn_write(handle, data + len - remaining, remaining);
                if (sent > 0)
                {
                    remaining -= sent;
                    timer = millis();
                }
                else if (sent < 0 &&
                    sent != ESP_TLS_ERR_SSL_WANT_READ &&
                    sent != ESP_TLS_ERR_SSL_WANT_WRITE &&
                    (mode != PLAIN_HTTP || sent != EHTTPSCA_CLIENT_TIMEOUT))
                {
                    EHTTPSCA_LOGF("Error writing to socket: 0x%x\n", -sent);
                    return sent;
                }

                vTaskDelay(1);
            }

            if (remaining > 0)
            {
                callCb(CONNECTION_FAILED_EVENT);
                return EHTTPSCA_CLIENT_TIMEOUT;
            }

            return len;
        }

        void handleRedirection(const char *locationHeader, size_t headerLen)
        {
            if (redirectionCount >= maxRedirections)
            {
                EHTTPSCA_LOGN("HTTP redirections exceeded the limit.");
                callCb(CONNECTION_FAILED_EVENT);
                return;
            }

            const char *valueStart = nullptr;
            size_t valueLen = 0;
            bool found = getHeaderValue(locationHeader, headerLen, &valueStart, &valueLen);
            if (!found)
            {
                callCb(CONNECTION_FAILED_EVENT);
                return;
            }

            if (mode == PLAIN_HTTP && valueLen >= 5 && strncasecmp(valueStart, "https", 5) == 0)
            {
                EHTTPSCA_LOGN("Unsupported HTTPS redirect, aborting.");
                callCb(CONNECTION_FAILED_EVENT);
                return;
            }

            redirectionCount++;
            setPath(valueStart, valueLen, currentMethod, keepAlive);

            cleanup();
            start();
        }

        void callCb(const ESPHttpsClientAsyncEvent event, uint8_t *data = nullptr, size_t len = 0, bool truncated = false)
        {
            bool wasConnected = (currentState == READING_DATA);

            if (event == CONNECTION_SUCCESSFUL_EVENT)
            {
                sendPath();
                currentState = SENDING_BODY;
            }
            else if (event == CONNECTION_FAILED_EVENT)
            {
                cleanup();
            }
            else if (event == WRITE_BODY_EVENT)
            {
                currentState = SENDING_BODY;
            }
            else if (event == STATUS_RECEIVED_EVENT && data != nullptr && len >= 3 && memcmp(data, REDIRECTION_STATUS, 3) == 0)
            {
                EHTTPSCA_LOGN("Redirection detected.");
                hasRedirection = true;
            }
            else if (event == HEADER_RECEIVED_EVENT && data != nullptr && len > 0)
            {
                if (len >= TRANSFER_ENCODING_HEADER_LEN && strncasecmp((char*) data, TRANSFER_ENCODING_HEADER, TRANSFER_ENCODING_HEADER_LEN) == 0)
                {
                    isReceivingChunked = true;
                }

                if (len >= LOCATION_HEADER_LEN && strncasecmp((char*) data, LOCATION_HEADER, LOCATION_HEADER_LEN) == 0)
                {
                    handleRedirection((const char*) data, len);
                    return;
                }
            }

            if (eventHandler)
            {
                if (event == CONNECTION_FAILED_EVENT && wasConnected)
                {
                    eventHandler(REQUEST_FINISHED_EVENT, data, len, truncated);
                }
                else
                {
                    eventHandler(event, data, len, truncated);
                }
            }
        }

        void cleanup()
        {
            if (handle != nullptr)
            {
                esp_tls_conn_destroy(handle);
                handle = nullptr;
            }

            sentPath = false;
            currentState = STOPPED;
            headerBufferOffset = 0;
            currentChunkSize = 0;
            currentChunkOffset = 0;
            contentSentLen = 0;
            contentLength = 0;
            isReceivingChunked = false;
            hasRedirection = false;
            redirectionCount = 0;
        }

        esp_tls_conn_state_t getTlsState()
        {
            if (handle == nullptr)
            {
                return ESP_TLS_INIT;
            }

            esp_tls_conn_state_t state{};
            int res = esp_tls_get_conn_state(handle, &state);
            if (res != ESP_OK)
            {
                return ESP_TLS_INIT;
            }

            return state;
        }

        bool isTlsStarted()
        {
            esp_tls_conn_state_t state = getTlsState();
            return state == ESP_TLS_DONE || state == ESP_TLS_HANDSHAKE || state == ESP_TLS_CONNECTING;
        }

        Method currentMethod;
        bool keepAlive;
        bool sentPath;

        char path[maxPathLen];
        size_t pathLen;
        char hostname[maxHostnameLen];
        size_t hostnameLen;

        int port;
        Mode mode;
        ESPHttpsClientAsyncState currentState;
        ESPHttpsClientAsyncEventHandler eventHandler;
        esp_tls_t *handle;

        const char *cert;
        size_t certLen;
        esp_tls_cfg_t config;

        uint8_t dataBuffer[totalDataSize];

        size_t headerBufferOffset;
        char currentHeaderBuffer[headerBufferSize];
        size_t terminatorMatchCounts[TERMINATORS_COUNT]{};
        size_t terminatorsLengths[TERMINATORS_COUNT]{};

        ssize_t contentLength;
        ssize_t contentSentLen;

        bool isReceivingChunked;
        size_t currentChunkSize;
        size_t currentChunkOffset;
        char chunkSizeBuf[32]{};

        bool hasRedirection;
        size_t redirectionCount;
        size_t maxRedirections;
    };
}

#endif
