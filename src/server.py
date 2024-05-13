# Copyright 2024 Broda Group Software Inc.
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Created:  2024-04-15 by eric.broda@brodagroupsoftware.com

import logging
from datetime import datetime
from typing import List, Dict
import os
import uuid
import yaml

from fastapi import FastAPI, Request, WebSocket, HTTPException
from fastapi.websockets import WebSocketDisconnect
import uvicorn

# Make accessible other source directories (as needed)
# script_dir = os.path.dirname(__file__)  # Path to the directory of server.py
# parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
# sys.path.insert(0, parent_dir)

import models
from bgsexception import BgsException, BgsNotFoundException
import state
from registry import Registry


# Set up logging
LOGGING_FORMAT = "%(asctime)s - %(module)s:%(funcName)s %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)


ENDPOINT_REGISTRAR = "/registrar"
ENDPOINT_PREFIX = "/api" + ENDPOINT_REGISTRAR

DEFAULT_CONFIG="./config/config.yaml"
DEFAULT_HOST="0.0.0.0"
DEFAULT_PORT=8000

STATE_ROUTES="routes"
STATE_REGISTRY="registry"
STATE_ROOT="root"
STATE_DOMAINS="domains"


# Set up server
app = FastAPI()


#####
# UTILITY
#####


@app.post(ENDPOINT_PREFIX + "/initialization")
async def initialize_post():
    """
    Initialize server
    """
    response = None
    logger.info("START: Initialization")

    logger.info("DONE: Initialization")
    return response


@app.get(ENDPOINT_PREFIX + "/dump")
async def registrar_dump_get():
    """
    Dump all keys
    """
    logger.info("START: Dump all keys")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.dump()

    logger.info(f"DONE: Dump all keys, response:{response}")
    return response


#####
# PRODUCTS
#####


@app.post(ENDPOINT_PREFIX + "/products")
async def registrar_products_post(product: models.Product):
    """
    Register product
    """
    logger.info(f"START: Register product:{product}")

    response = None
    try:
        registry: Registry = state.gstate(STATE_REGISTRY)
        response = await registry.register_product(product)
    except BgsException as e:
        msg = f"Run-time exception:{str(e)}"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    logger.info(f"DONE: Register product:{product}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/products")
async def registrar_products_get():
    """
    Get registered products
    """
    logger.info("START: Get registered products")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_products()

    logger.info(f"DONE: Get Get registered products, response:{response}")
    return response


@app.post(ENDPOINT_PREFIX + "/products/uuids/")
async def registrar_products_uuids_post(request: Dict):
    """
    Get registered products matching UUIDs

    Note that the UUID list may be very large and hence a GET
    request may not work, hence we are using a POST request.

    Also note, that when retrieving data, REST conventions
    recommend using a trailing "/" for the endpoint; Hence
    the endpoint is "/products/uuids/" instead of "/products/uuids".
    """
    logger.info(f"START: Get registered products request:{request}")

    uuids = request["uuids"]
    logger.info(f"using uuids:{uuids}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_products_uuids(uuids)

    logger.info(f"DONE: Get registered products uuids:{uuids}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/products/namespace/{namespace}")
async def registrar_products_namespace_get(namespace: str):
    """
    Get registered products by namespace
    """
    logger.info(f"START: Get registered products namespace:{namespace}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_product_namespace(namespace)

    logger.info(f"DONE: Get registered products namespace:{namespace}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/products/namespace/{namespace}/name/{name}")
async def registrar_products_namespace_name_get(namespace: str, name: str):
    """
    Get registered product by namespace and name
    """
    logger.info(f"START: Get registered products namespace:{namespace} name:{name}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_product_namespace_name(namespace, name)

    logger.info(f"DONE: Get registered products namespace:{namespace} name:{name}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/products/email/{email}")
async def registrar_products_email_get(email: str):
    """
    Get registered product by namespace and name
    """
    logger.info(f"START: Get registered products email:{email}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_product_email(email)

    logger.info(f"DONE: Get registered products email:{email}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/products/uuid/{uuid}")
async def registrar_products_uuid_get(uuid: str):
    """
    Get registered product
    """
    logger.info(f"START: Get registered product uuid:{uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_product_uuid(uuid)
    if not response:
        msg = f"Product not found, uuid:{uuid}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered products uuid:{uuid}, response:{response}")
    return response


@app.post(ENDPOINT_PREFIX + "/products/search")
async def registrar_products_search_get(request: Dict):
    """
    Search products
    """
    logger.info(f"START: Search product request:{request}")

    if "query" not in request:
        msg = "Missing parameter:query"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    # Execute search
    response = {
        "text": "Search is not implemented"
    }

    logger.info(f"DONE: Search product request:{request}, response:{response}")
    return response



#####
# USERS
#####


@app.post(ENDPOINT_PREFIX + "/users")
async def registrar_users_post(user: models.User):
    """
    Register user
    """
    logger.info(f"START: Register user:{user}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.register_user(user)

    logger.info(f"DONE: Register user:{user}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/users")
async def registrar_users_get():
    """
    Get registered user
    """
    logger.info("START: Get registered users")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_users()

    logger.info(f"DONE: Get registered users, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/users/uuid/{uuid}")
async def registrar_users_uuid_get(uuid: str):
    """
    Get registered user
    """
    logger.info(f"START: Get registered user uuid:{uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_user_uuid(uuid)
    if not response:
        msg = f"User not found, uuid:{uuid}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered user uuid:{uuid}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/users/email/{email}")
async def registrar_users_email_get(email: str):
    """
    Get registered users by email (user can be registered with
    multiple roles)
    """
    logger.info(f"START: Get registered users email:{email}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_user_email(email)
    if not response:
        msg = f"User not found, email:{email}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered users email:{email}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/users/role/{role}/email/{email}")
async def registrar_users_role_email_get(role: str, email: str):
    """
    Get registered user by role/email (must be exact match)
    """
    logger.info(f"START: Get registered user role:{role} email:{email}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_user_role_email(role, email)
    if not response:
        msg = f"User not found, role:{role} email:{email}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered user role:{role} email:{email}, response:{response}")
    return response


#####
# AUTH (login/logout)
#####


@app.post(ENDPOINT_PREFIX + "/auth/login")
async def registrar_auth_login_post(request: Dict):
    """
    Get registered guest
    """
    logger.info(f"START: Login registered user request:{request}")

    if "role" not in request:
        msg = "Missing parameter:role"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    if "email" not in request:
        msg = "Missing parameter:email"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    if "password" not in request:
        msg = "Missing parameter:password"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    response = None
    try:

        role = request["role"]
        email = request["email"]
        password = request["password"]

        registry: Registry = state.gstate(STATE_REGISTRY)
        response = await registry.auth_login_user(role, email, password)

    except BgsNotFoundException as e:
        msg = f"Invalid login, exception:{e}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    except Exception as e:
        msg = f"Error executing login, exception:{e}"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    logger.info(f"DONE: Login registered user request:{request}, response:{response}")
    return response


@app.post(ENDPOINT_PREFIX + "/auth/logout")
async def registrar_auth_logout_post(request: Dict):
    """
    Get registered guest
    """
    logger.info(f"START: Logout registered user request:{request}")

    if "role" not in request:
        msg = "Missing parameter:role"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    if "email" not in request:
        msg = "Missing parameter:email"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    response = None
    try:
        role = request["role"]
        email = request["email"]

        registry: Registry = state.gstate(STATE_REGISTRY)
        response = await registry.auth_logout_user(role, email)

    except BgsNotFoundException as e:
        msg = f"Invalid logout, exception:{e}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    except Exception as e:
        msg = f"Error executing logout, exception:{e}"
        logger.error(msg)
        raise HTTPException(status_code=500, detail=msg)

    logger.info(f"DONE: Logout registered user request:{request}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/auth/statistics")
async def registrar_getauth_statistics_get():
    """
    Get registered guest
    """
    logger.info(f"START: Auth statistics")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.auth_statistics()

    logger.info(f"DONE: Auth statistics, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/auth/status/{email}")
async def registrar_auth_status_get(email: str):
    """
    Get registered guest
    """
    logger.info(f"START: Auth status")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.auth_status(email)

    logger.info(f"DONE: Auth statistics, response:{response}")
    return response


#####
# CARTS
#####

@app.post(ENDPOINT_PREFIX + "/carts/purchase/")
async def registrar_cart_post(cart: models.Cart):
    """
    Register a cart... NOT SUPPORTED(note: registering cart is not
    available as carts are created when user(subscriber role)
    are registered)
    """
    logger.info(f"START: Register cart:{cart}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.register_cart(cart)

    logger.info(f"DONE: Register cart:{cart}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/carts")
async def registrar_carts_get():
    """
    Get registered carts
    """
    logger.info("START: Get registered carts")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_carts()

    logger.info(f"DONE: Get registered carts, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/carts/uuid/{uuid}")
async def registrar_carts_uuid_get(uuid: str):
    """
    Get registered cart by uuid
    """
    logger.info(f"START: Get registered cart uuid:{uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_cart_uuid(uuid)
    if not response:
        msg = f"Cart not found, uuid:{uuid}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered cart uuid:{uuid}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/carts/email/{email}")
async def registrar_carts_email_get(email: str):
    """
    Get registered cart by email
    """
    logger.info(f"START: Get registered cart email:{email}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_cart_email(email)
    if not response:
        msg = f"Cart not found, email:{email}"
        logger.error(msg)
        raise HTTPException(status_code=404, detail=msg)

    logger.info(f"DONE: Get registered cart email:{email}, response:{response}")
    return response


@app.post(ENDPOINT_PREFIX + "/carts/uuid/{uuid}/{product_uuid}/{artifact_uuid}")
async def registrar_cart_uuid_item_post(uuid: str, product_uuid: str, artifact_uuid: str):
    """
    Add item to a cart using UUID
    """
    logger.info(f"START: Add item to a cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.register_cart_item_uuid(uuid, product_uuid, artifact_uuid)

    logger.info(f"DONE: Add item to a cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")
    return response


@app.delete(ENDPOINT_PREFIX + "/carts/uuid/{uuid}/{product_uuid}/{artifact_uuid}")
async def unregistrar_cart_uuid_item_delete(uuid: str, product_uuid: str, artifact_uuid: str):
    """
    Remove an item from a cart
    """
    logger.info(f"START: Delete an item from a cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.unregister_cart_item_uuid(uuid, product_uuid, artifact_uuid)

    logger.info(f"DONE: Delete an item from a cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")
    return response


@app.post(ENDPOINT_PREFIX + "/carts/email/{email}/{product_uuid}/{artifact_uuid}")
async def registrar_cart_email_item_post(email: str, product_uuid: str, artifact_uuid: str):
    """
    Add item to a cart using EMAIL
    """
    logger.info(f"START: Add item to a cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.register_cart_item_email(email, product_uuid, artifact_uuid)

    logger.info(f"DONE: Add item to a cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")
    return response


@app.delete(ENDPOINT_PREFIX + "/carts/email/{email}/{product_uuid}/{artifact_uuid}")
async def unregistrar_cart_email_item_delete(email: str, product_uuid: str, artifact_uuid: str):
    """
    Delete an item from a cart
    """
    logger.info(f"START: Delete an item from a cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.unregister_cart_item_email(email, product_uuid, artifact_uuid)

    logger.info(f"DONE: Delete an item from a cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")
    return response


#####
# ORDERS
#####


@app.post(ENDPOINT_PREFIX + "/orders")
async def registrar_order_post(request: Dict):
    """
    Register order (ie. purchase cart)
    """
    logger.info(f"START: Register order request:{request}")

    cart_uuid = _verify_parameter(request, "cartuuid")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.register_order(cart_uuid)

    logger.info(f"DONE: Register order request:{request}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/orders")
async def registrar_orders_get():
    """
    Get registered orders
    """
    logger.info("START: Get registered orders")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_orders()

    logger.info(f"DONE: Get registered orders, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/orders/uuid/{uuid}")
async def registrar_orders_uuid_get(uuid: str):
    """
    Get registered order by uuid
    """
    logger.info(f"START: Get registered order uuid:{uuid}")

    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_order_uuid(uuid)

    logger.info(f"DONE: Get registered order uuid:{uuid}, response:{response}")
    return response


@app.get(ENDPOINT_PREFIX + "/orders/email/{email}")
async def registrar_orders_email_get(email: str):
    """
    Get registered order history by email
    """
    logger.info(f"START: Get registered orders (history) email:{email}")

    # Note that all orders for this email are returned
    # and hence the response is a List
    response = None
    registry: Registry = state.gstate(STATE_REGISTRY)
    response = await registry.retrieve_orders_email(email)

    logger.info(f"DONE: Get registered orders (history) email:{email}, response:{response}")
    return response


#####
# INTERNAL
#####

def _verify_parameter(request, name):
    if name not in request:
        msg = f"Invalid request, missing '{name}' parameter"
        logger.error(msg)
        raise HTTPException(msg)
    return request[name]

#####
# MAINLINE
#####


if __name__ == "__main__":

    # Set up argument parsing
    import argparse
    parser = argparse.ArgumentParser(description="Run the FastAPI server.")
    parser.add_argument("--host", type=str, default=DEFAULT_HOST, help=f"Host for the server (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port for the server (default: {DEFAULT_PORT})")
    parser.add_argument("--configuration", default=DEFAULT_CONFIG, help=f"Configuration file (default: {DEFAULT_CONFIG})")
    args = parser.parse_args()

    # Read the configuration file
    configuration = None
    with open(args.configuration, 'r') as file:
        configuration = yaml.safe_load(file)

    # Get root key for registry
    root = configuration["registry"]["root"]
    state.gstate(STATE_ROOT, root)
    logger.info(f"Using root:{root}")

    # Get domains for registry
    domains = configuration["registry"]["domains"]
    state.gstate(STATE_DOMAINS, domains)
    logger.info(f"Using domains:{domains}")

    # Get ETCD registry info
    logger.info(f"Using registry configuration:{configuration['registry']}")
    registryhost = configuration["registry"]["host"]
    registryport = configuration["registry"]["port"]

    # Get proxy info
    logger.info(f"Using proxy configuration:{configuration['proxy']}")
    proxyhost = configuration["proxy"]["host"]
    proxyport = configuration["proxy"]["port"]

    registry = Registry({
        "registryhost": registryhost,
        "registryport": registryport,
        "proxyhost": proxyhost,
        "proxyport": proxyport,
        "root": root,
        "domains": domains
    })
    state.gstate(STATE_REGISTRY, registry)
    logger.info(f"Using registry:{registry}")

    logger.info(f"Using current working directory:{os.getcwd()}")
    logger.info(f"START: Starting service on host:{args.host} port:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port)

    logger.info(f"DONE: Starting service on host:{args.host} port:{args.port}")

