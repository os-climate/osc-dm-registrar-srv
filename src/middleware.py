import logging
from fastapi import Request
import base64
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import StreamingResponse
from starlette.types import Send
from starlette.datastructures import MutableHeaders
import uuid

import state

STATE_TRACEID = "state-traceid"
STATE_METRICS = "state-metrics"

HEADER_USERNAME = "OSC-DM-Username"
HEADER_CORRELATION_ID = "OSC-DM-Correlation-ID"
USERNAME_UNKNOWN = "unknown"

class LoggingMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware is used to add processing to
    each request.  This is used to perform several capabilities:
    - add "TRACE" identifiers to request and responses that
    link requests to their responses
    - track basic statistics about service usage for
    URLs and username (HEADER_USERNAME in header)
    - create correlation id that can allow messages
    to be tracked end-to-end (assuming each communication
    participate propagates key headers)
    """
    async def dispatch(self, request: Request, call_next):
        logger = logging.getLogger(__name__)

        body = {}
        if request.method not in ["GET", "HEAD", "OPTIONS"]:
            try:
                body = await request.json()
            except Exception:
                try:
                    body = await request.body()
                    body = _safe_decode(body)
                except Exception as e:
                    body = f"Failed to read body: {str(e)}"

        # Get the correlation id, and add it if it does not exist
        correlation_id = request.headers.get(HEADER_CORRELATION_ID)
        if correlation_id is None:
            logger.warning(f"Missing header:{HEADER_CORRELATION_ID} url:{str(request.url)} headers:{request.headers} ")
            correlation_id = str(uuid.uuid4())
            headers = MutableHeaders(request._headers)
            headers[HEADER_CORRELATION_ID] = correlation_id
            request._headers = headers
            logger.warning(f"Added header:{HEADER_CORRELATION_ID}:{correlation_id} url:{str(request.url)} headers:{request.headers} ")

        # Get the username, and add it if it does not exist
        username = request.headers.get(HEADER_USERNAME)
        if username is None:
            logger.warning(f"Missing header:{HEADER_USERNAME} url:{str(request.url)} headers:{request.headers} ")
            username = USERNAME_UNKNOWN
            headers = MutableHeaders(request._headers)
            headers[HEADER_USERNAME] = username
            request._headers = headers
            logger.warning(f"Added header:{HEADER_USERNAME}:{username} url:{str(request.url)} headers:{request.headers} ")

        # Get a trace identifier to track requests and responses logs
        trace_id = state.gstate(STATE_TRACEID)
        if not trace_id:
            trace_id = 0
            state.gstate(STATE_TRACEID, trace_id)
        trace_id = state.gstate(STATE_TRACEID)

        url = str(request.url)
        request_info = {
            "url": url,
            "method": request.method,
            "headers": dict(request.headers),
            "parameters": dict(request.query_params),
            "body": body
        }
        logger.info(f"TRACE-{trace_id}:{correlation_id}-REQ:{request_info}")

        response = await call_next(request)
        status_code = response.status_code

        # Add the correlation id and username to the response
        response.headers[HEADER_CORRELATION_ID] = correlation_id
        response.headers[HEADER_USERNAME] = username

        # Handle username counts
        metrics = state.gstate(STATE_METRICS)
        if not metrics:
            metrics = {}
            state.gstate(STATE_METRICS, metrics)
        metrics = state.gstate(STATE_METRICS)

        # Update counts for username
        username = request.headers.get(HEADER_USERNAME)
        if not username:
            username = USERNAME_UNKNOWN
        if username not in metrics:
            metrics[username] = {}
        if url not in metrics[username]:
            metrics[username][url] = {}
        if status_code not in metrics[username][url]:
            metrics[username][url][status_code] = 0
        metrics[username][url][status_code] += 1
        logger.info(f"Using metrics:{metrics}")

        # Log response
        response_body = ""
        if isinstance(response, StreamingResponse):
            original_body_iterator = response.body_iterator
            logging_response = _LoggingStreamingResponse(original_body_iterator, status_code=response.status_code, headers=dict(response.headers))
            response_body = logging_response.body
        else:
            response_body = response.body.decode("utf-8") if hasattr(response, 'body') else str(response)

        response_info = {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response_body
        }
        logger.info(f"TRACE-{trace_id}:{correlation_id}-RSP:{response_info}")

        state.gstate(STATE_TRACEID, trace_id + 1)

        return response

    @staticmethod
    def get_metrics():
        usernames = state.gstate(STATE_METRICS)
        return usernames


class _LoggingStreamingResponse(StreamingResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.body_chunks = []

    async def stream_response(self, send: Send):
        async for chunk in self.body_iterator:
            self.body_chunks.append(chunk)
            await send({
                "type": "http.response.body",
                "body": chunk,
                "more_body": True
            })

        await send({
            "type": "http.response.body",
            "body": b"",
            "more_body": False
        })

    @property
    def body(self):
        return b"".join(self.body_chunks).decode("utf-8")

def _safe_decode(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return base64.b64encode(data).decode('utf-8')
