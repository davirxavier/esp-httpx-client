import socket
import re

HOST = "0.0.0.0"
PORT = 8080
BUFFER_SIZE = 4096


def format_raw_request(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    text = text.replace("\r", "\\r").replace("\n", "\\n\n")
    return text


def parse_headers(header_bytes: bytes):
    headers = {}
    lines = header_bytes.decode("iso-8859-1").split("\r\n")
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    return headers


def is_valid_request_line(line: str) -> bool:
    return bool(re.match(r"^[A-Z]+ .+ HTTP/\d\.\d$", line))


def read_exact(conn, n):
    data = b""
    while len(data) < n:
        chunk = conn.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def read_chunked_body(conn, initial_data):
    body = b""
    buffer = initial_data
    valid = True

    while True:
        # Read chunk size line
        while b"\r\n" not in buffer:
            more = conn.recv(BUFFER_SIZE)
            if not more:
                return body, False
            buffer += more

        line, buffer = buffer.split(b"\r\n", 1)

        try:
            chunk_size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return body, False

        if chunk_size == 0:
            # Read final CRLF
            while len(buffer) < 2:
                more = conn.recv(BUFFER_SIZE)
                if not more:
                    return body, False
                buffer += more

            if buffer[:2] != b"\r\n":
                return body, False

            buffer = buffer[2:]
            break

        # Read chunk data + CRLF
        while len(buffer) < chunk_size + 2:
            more = conn.recv(BUFFER_SIZE)
            if not more:
                return body, False
            buffer += more

        chunk = buffer[:chunk_size]
        body += chunk

        if buffer[chunk_size:chunk_size + 2] != b"\r\n":
            return body, False

        buffer = buffer[chunk_size + 2:]

    return body, valid


def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)

        print(f"Listening on {HOST}:{PORT}...")

        while True:
            conn, addr = server.accept()
            with conn:
                print(f"\nConnection from {addr}")

                data = b""

                # Read headers
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    data += chunk

                if b"\r\n\r\n" not in data:
                    print("Invalid request: incomplete headers")
                    continue

                header_part, remaining = data.split(b"\r\n\r\n", 1)
                header_lines = header_part.decode("iso-8859-1").split("\r\n")

                if not header_lines:
                    print("Invalid request: empty")
                    continue

                request_line = header_lines[0]
                valid_request_line = is_valid_request_line(request_line)

                headers = parse_headers(header_part)

                body = b""
                body_valid = True
                is_chunked = False
                has_content_length = False
                is_multipart = False
                conflicting_length = False

                # Detect conflicting headers
                if "transfer-encoding" in headers and "content-length" in headers:
                    conflicting_length = True
                    body_valid = False

                # Handle chunked
                if "transfer-encoding" in headers and "chunked" in headers["transfer-encoding"].lower():
                    is_chunked = True
                    body, body_valid = read_chunked_body(conn, remaining)

                # Handle Content-Length
                elif "content-length" in headers:
                    has_content_length = True
                    try:
                        declared_length = int(headers["content-length"])
                    except ValueError:
                        body_valid = False
                        declared_length = 0

                    if body_valid:
                        if len(remaining) < declared_length:
                            body = remaining + read_exact(conn, declared_length - len(remaining))
                        else:
                            body = remaining[:declared_length]

                        if len(body) != declared_length:
                            body_valid = False

                else:
                    body = remaining

                # Detect multipart
                if "content-type" in headers and "multipart/form-data" in headers["content-type"].lower():
                    is_multipart = True

                full_request = header_part + b"\r\n\r\n" + body

                print("----- RAW REQUEST START -----")
                print(format_raw_request(full_request))
                print("------ RAW REQUEST END ------")

                overall_valid = valid_request_line and body_valid and not conflicting_length

                print("Detection:")
                print(f"  Valid request line: {valid_request_line}")
                print(f"  Uses Content-Length: {has_content_length}")
                print(f"  Uses Chunked Encoding: {is_chunked}")
                print(f"  Multipart Form Data: {is_multipart}")
                print(f"  Conflicting Length Headers: {conflicting_length}")
                print(f"  Body structurally valid: {body_valid}")
                print(f"  Overall request valid: {overall_valid}")

                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Length: 2\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "OK"
                )
                conn.sendall(response.encode())
                conn.close()


if __name__ == "__main__":
    run_server()