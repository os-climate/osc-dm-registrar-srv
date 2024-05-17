import logging
from functools import wraps
from fastapi import Request, Response, Depends
from typing import Callable
import base64

import state

STATE_TRACEID = "state-traceid"

def safe_decode(data):
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        # Return a base64 encoded string if UTF-8 decoding fails
        return base64.b64encode(data).decode('utf-8')

def tracer(func: Callable):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        logger = logging.getLogger(__name__)

        logger.info(f"using args:{args} kwargs:{kwargs}")

        # Find the request object in args or kwargs
        request = kwargs.get('request') if 'request' in kwargs else None
        if request is None:
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

        # Extract body if the request is found
        if request:
            body = {}
            # Check if the request is likely to have a body
            if request.method not in ["GET", "HEAD", "OPTIONS"]:
                try:
                    body = await request.json()
                except Exception:
                    # Handle other content types like form-data or raw bodies
                    try:
                        body = await request.body()
                        body = safe_decode(body)  # Decode safely
                    except Exception as e:
                        body = f"Failed to read body: {str(e)}"

            # Get a trace identifier to correlate requests and responses
            trace_id = state.gstate(STATE_TRACEID)
            if not trace_id:
                trace_id = 0
                state.gstate(STATE_TRACEID, trace_id)
            trace_id = state.gstate(STATE_TRACEID)

            # Log response in TRACE
            request_info = {
                "url": str(request.url),
                "method": request.method,
                "headers": dict(request.headers),
                "parameters": dict(request.query_params),
                "body": body
            }
            logger.info(f"TRACE REQ-{trace_id}: {request_info}")

            # Call the actual endpoint
            try:
                response = await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Exception: {str(e)}")
                # Log error in TRACE and increment and save the next trace ID
                logger.info(f"TRACE RSP-{trace_id}: exception:{e}")
                state.gstate(STATE_TRACEID, trace_id+1)
                raise e

            # Log response in TRACE and increment and save the next trace ID
            if isinstance(response, Response):
                response_info = {
                    "status_code": response.status_code,
                    "body": safe_decode(response.body) if response.body else "No Body"
                }
                logger.info(f"TRACE RSP-{trace_id}: {response_info}")
            else:
                logger.info(f"TRACE RSP-{trace_id}: {response}")

            # Increment and save the next trace ID
            state.gstate(STATE_TRACEID, trace_id+1)

            return response
        else:
            return await func(*args, **kwargs)

    return wrapper