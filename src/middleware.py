import logging
from fastapi import Request, Response, Depends
import base64
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, StreamingResponse, PlainTextResponse

import state

STATE_TRACEID = "state-traceid"

def safe_decode(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return base64.b64encode(data).decode('utf-8')

class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger = logging.getLogger(__name__)

        body = {}
        if request.method not in ["GET", "HEAD", "OPTIONS"]:
            try:
                body = await request.json()
            except Exception:
                try:
                    body = await request.body()
                    body = safe_decode(body)
                except Exception as e:
                    body = f"Failed to read body: {str(e)}"

        # Get a trace identifier to correlate requests and responses
        trace_id = state.gstate(STATE_TRACEID)
        if not trace_id:
            trace_id = 0
            state.gstate(STATE_TRACEID, trace_id)
        trace_id = state.gstate(STATE_TRACEID)

        request_info = {
            "url": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "parameters": dict(request.query_params),
            "body": body
        }
        logger.info(f"TRACE-{trace_id}-REQ: {request_info}")

        response = await call_next(request)

        response_body = ""
        if isinstance(response, StreamingResponse):
            original_body_iterator = response.body_iterator
            logging_response = LoggingStreamingResponse(original_body_iterator, status_code=response.status_code, headers=dict(response.headers))
            response_body = logging_response.body
        else:
            response_body = response.body.decode("utf-8") if hasattr(response, 'body') else str(response)


        response_info = {
            "status_code": response.status_code,
            "body": response_body
        }
        logger.info(f"TRACE-{trace_id}-RSP: {response_info}")

        state.gstate(STATE_TRACEID, trace_id + 1)

        return response

from starlette.types import Send, Message
import asyncio

class LoggingStreamingResponse(StreamingResponse):
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