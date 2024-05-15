# Copyright 2024 Broda Group Software Inc.
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Created:  2024-04-15 by eric.broda@brodagroupsoftware.com

from typing import List, Optional, Dict, Any
import httpx
import logging

from bgsexception import BgsException, BgsNotFoundException

LOGGING_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)

async def httprequest(host: str, port: int, service: str, method: str,
             data: Optional[Any]=None, obj: Optional[Dict]=None,
             files: Optional[Any]=None, headers: Optional[Dict]=None) -> Any:
    """
    Generic request function using the ASYNC httpx library.

    Parameters:
    - service (str): The URL of the service to which the request is made
    - method (str): The HTTP method to use (e.g., GET, POST, PUT, DELETE)
    - data (any, optional): Data to send in the request body, typically for POST requests
    - obj (dict, optional): JSON object to send in the request body
    - files (any, optional): Files to send in the request body

    Returns:
    - requests.Response: The response object
    """
    logger.info(f"Issue request, method:{method} data:{data} obj:{obj} files:{files}")

    url = f"http://{host}:{port}{service}"
    method = method.upper()
    logger.info(f"Request method:{method} url:{url}")

    if not headers:
        headers = {"Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, headers=headers, json=obj, data=data, files=files)
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as e:
        details = e.response.json().get("detail", str(e))
        msg = f"HTTP status error for {url}: {details}"
        logger.error(msg)
        raise BgsException(msg)

    except httpx.ConnectTimeout:
        msg = f"Connection timeout for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except httpx.ConnectError:
        msg = f"Connection error for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except httpx.NetworkError:
        msg = f"Network error for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except httpx.ReadTimeout:
        msg = f"Read timeout for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except Exception as e:
        msg = f"Unexpected error for {url}: {e}"
        logger.error(msg)
        raise BgsException(msg)

def shttprequest(host: str, port: int, service: str, method: str,
             data: Optional[Any]=None, obj: Optional[Dict]=None,
             files: Optional[Any]=None, headers: Optional[Dict]=None) -> Any:
    """
    Generic request function using the SYNCHRONOUS requests library.

    Parameters:
    - service (str): The URL of the service to which the request is made
    - method (str): The HTTP method to use (e.g., GET, POST, PUT, DELETE)
    - data (any, optional): Data to send in the request body, typically for POST requests
    - obj (dict, optional): JSON object to send in the request body
    - files (any, optional): Files to send in the request body

    Returns:
    - requests.Response: The response object
    """
    logger.info(f"Issue request, method:{method} data:{data} obj:{obj} files:{files}")

    url = f"http://{host}:{port}{service}"
    method = method.upper()
    logger.info(f"Request method:{method} url:{url}")

    if not headers:
        headers = {"Content-Type": "application/json"}

    try:
        import requests
        response = requests.request(method, url, headers=headers, json=obj, data=data, files=files)
        response.raise_for_status()
        return response.json()

    except requests.HTTPError as e:
        details = e.response.json().get("detail", str(e))
        msg = f"HTTP status error for {url}: {details}"
        logger.error(msg)
        raise BgsException(msg)

    except requests.Timeout:
        msg = f"Connection timeout for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except requests.ConnectionError:
        msg = f"Connection error for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except requests.RequestException:
        msg = f"Request error for {url}"
        logger.error(msg)
        raise BgsException(msg)

    except Exception as e:
        msg = f"Unexpected error for {url}: {e}"
        logger.error(msg)
        raise BgsException(msg)