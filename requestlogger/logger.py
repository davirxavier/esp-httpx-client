from flask import Flask, request, jsonify
import logging

app = Flask(__name__)

# Set up logging to a file
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(message)s')
logger = logging.getLogger()


@app.before_request
def log_request():
    try:
        # Log headers
        logger.info("Received Headers:")
        for header, value in request.headers.items():
            logger.info(f"{header}: {value}")

        # Log the raw body (including \r\n)
        logger.info("\nReceived Body:")
        raw_body = request.get_data(as_text=False)  # Get the raw body
        logger.info(raw_body.decode('latin1'))  # Decode as latin1 to prevent data corruption

    except Exception as e:
        logger.error(f"Error logging request: {e}")


@app.route("/", methods=["POST"])
def receive_request():
    try:
        # If the request is valid, Flask will process it and return a response
        return jsonify({"message": "Received successfully"}), 200
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Bad request"}), 400


@app.errorhandler(400)
def bad_request(error):
    # In case of invalid request (status 400)
    logger.error(f"Bad request error: {error}")
    return jsonify({"error": "Bad request"}), 400


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)