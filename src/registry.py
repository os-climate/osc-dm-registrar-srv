# Copyright 2024 Broda Group Software Inc.
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Created:  2024-04-15 by eric.broda@brodagroupsoftware.com

import logging
import uuid
from datetime import datetime
from typing import List

import utilities
import models

# Set up logging
LOGGING_FORMAT = "%(asctime)s - %(module)s:%(funcName)s %(levelname)s - %(message)s"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)

import models
from etcd import Etcd
from bgsexception import BgsException, BgsNotFoundException

ENDPOINT_PREFIX = "/api"
ENPOINT_DATAPRODUCT = ENDPOINT_PREFIX + "/dataproducts"

STATUS_AUTHORIZED = "authorized"
STATUS_UNAUTHORIZED = "unauthorized"

RESULT_SUCCESS = "OK"
RESULT_FAILED = "FAILED"

VALID_ROLES = [
    models.ROLE_ADMINISTRATOR.lower(),
    models.ROLE_GUEST.lower(),
    models.ROLE_PUBLISHER.lower(),
    models.ROLE_SUBSCRIBER.lower()
]

class Registry():

    def __init__(self, config: dict):
        """
        Connect to ETCD (our service registry)
        """
        logger.info(f"Using config:{config}")
        self.registryhost = config["registryhost"]
        self.registryport = config["registryport"]
        self.proxyhost = config["proxyhost"]
        self.proxyport = config["proxyport"]
        self.root = config["root"]
        self.domains = config["domains"]
        self.etcd = Etcd({
            "host": self.registryhost,
            "port": self.registryport
        })

    #####
    # PRODUCTS
    #####

    async def register_product(self, product: models.Product):
        logger.info(f"Registering product:{product}")

        # FIX: When security is introduced, then ensure
        # only authenticated user are able to register

        if not product.address:
            msg = f"Product is missing mandatory address:{product}"
            logger.info(msg)
            raise BgsException(msg)

        xproduct = await self.retrieve_product_namespace_name(
            product.namespace, product.name)
        if xproduct:
            logger.info(f"Product registering (update) product:{product}")
        else:
            logger.info(f"Product registering (new) product:{product}")

        # Verify that the user is a publisher
        publisher_exists = await self._verify_user_email(
            models.ROLE_PUBLISHER,
            product.publisher)
        if not publisher_exists:
            msg = f"User:{product.publisher} is not registered in role:{models.ROLE_PUBLISHER}"
            logger.info(msg)
            raise BgsException(msg)

        # Update the product create/update times
        product.createtimestamp = datetime.now().isoformat(sep=' ', timespec='milliseconds')
        product.updatetimestamp = product.createtimestamp

        # Add the item to the registry
        logger.info(f"Registering product uuid:{product.uuid}")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/" + product.uuid
        value = product.model_dump()
        self.etcd.upsert(key, value)

        # Return the full product (which now has create/udpate time)
        response = product.model_dump()
        logger.info(f"Registering product:{product}, response:{response}")

        return response

    async def retrieve_products(self):
        logger.info("Retrieving products")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/*"
        items = self.etcd.retrieve_wildcard(key)
        products = [item["value"] for item in items]
        response = products
        logger.info(f"Retrieved products, response:{response}")
        return response

    async def retrieve_products_uuids(self, uuids: List[str]):
        logger.info(f"Retrieving products for uuids:{uuids}")

        domain_key = self.domains["products"]["key"]
        key = domain_key + "/*"
        items = self.etcd.retrieve_wildcard(key)
        logger.info(f"items:{items}")
        items = [item["value"] for item in items]
        products = [x for x in items if x["uuid"] in uuids]
        logger.info(f"products:{products}")
        response = products

        logger.info(f"Retrieved products for uuids:{uuids}, response:{response}")
        return response

    async def retrieve_product_namespace(self, namespace: str):
        logger.info(f"Retrieving product namespace:{namespace}")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/*"
        logger.info(f"key:{key}")

        items = self.etcd.retrieve_wildcard(key)
        items = [item["value"] for item in items]

        products = []
        logger.info(f"items:{items}")
        if items:
            xitems = [x for x in items if x["namespace"] == namespace]
            logger.info(f"xitems:{xitems}")
            if len(xitems) > 0:
                # Names are unique within a product; use the first one
                xitem = xitems[0]
                logger.info(f"xitem:{xitem}")
                product = models.Product(**xitem)
                logger.info(f"product:{product}")
                products.append(product)
        logger.info(f"Retrieving products namespace:{namespace}, products:{products}")
        return products

    async def retrieve_product_namespace_name(self, namespace: str, name: str):
        logger.info(f"Retrieving product namespace:{namespace} name:{name}")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/*"
        logger.info(f"key:{key}")

        items = self.etcd.retrieve_wildcard(key)
        items = [item["value"] for item in items]

        product: models.Product = None
        logger.info(f"items:{items}")
        if items:
            xitems = [x for x in items if x["namespace"] == namespace and x["name"] == name]
            logger.info(f"xitems:{xitems}")
            if len(xitems) > 0:
                # Names are unique within a product; use the first one
                xitem = xitems[0]
                logger.info(f"xitem:{xitem}")
                product = models.Product(**xitem)
                logger.info(f"product:{product}")
        logger.info(f"Retrieving product namespace:{namespace} name:{name}, product:{product}")
        return product

    async def retrieve_product_email(self, email: str):
        logger.info(f"Retrieving all products email:{email}")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/*"
        logger.info(f"key:{key}")

        items = self.etcd.retrieve_wildcard(key)
        items = [item["value"] for item in items]

        products = []
        logger.info(f"items:{items}")
        if items:
            xitems = [x for x in items if x[models.ROLE_PUBLISHER] == email]
            logger.info(f"xitems:{xitems}")
            if len(xitems) > 0:
                # Names are unique within a product; use the first one
                xitem = xitems[0]
                logger.info(f"xitem:{xitem}")
                product = models.Product(**xitem)
                logger.info(f"product:{product}")
                products.append(product)
        logger.info(f"Retrieved product email:{email}, products:{products}")
        return products

    async def retrieve_product_uuid(self, uuid: str):
        logger.info(f"Retrieving product uuid:{uuid}")
        domain_key = self.domains["products"]["key"]
        key = domain_key + "/" + uuid
        product = self.etcd.retrieve(key)
        logger.info(f"Retrieved product uuid:{uuid}, product:{product}")
        return product

    #####
    # USERS
    #####

    async def register_user(self, user: models.User):
        logger.info(f"Registering user:{user}")

        # FIX: When security is introduced, then ensure
        # only authenticated user are able to register

        role_valid = await self._verify_role(user.role)
        if not role_valid:
            msg = f"Invalid role, must be one of:{VALID_ROLES}"
            raise BgsException(msg)

        # Return the user uuid if they have already registered
        xuser = await self.retrieve_user_role_email(user.role, user.contact.email)
        if xuser:
            response = {
                "uuid": xuser.uuid
            }
            msg = f"User already exists role:{user.role} email:{user.contact.email} xuser:{xuser}"
            logger.info(msg)
            return response

        ## Create the user
        xuuid = f"{uuid.uuid4()}"
        user.uuid = xuuid
        user.createtimestamp = datetime.now().isoformat(sep=' ', timespec='milliseconds')
        user.updatetimestamp = user.createtimestamp
        domain_key = self.domains["users"]["key"]
        key = domain_key + "/" + user.role + "/" + xuuid
        value = user.model_dump()
        self.etcd.upsert(key, value)
        logger.info(f"Completed registering user:{user}")

        # Note that subscribers automatically get a cart.
        # Create the cart for the subscriber user.
        if user.role == models.ROLE_SUBSCRIBER.lower():
            logger.info(f"User is a subscriber user:{user}")
            cart_uuid = f"{uuid.uuid4()}"
            cart = models.Cart(
                uuid=cart_uuid,
                subscriber=user.contact.email,
                items=[],
                createtimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds'),
                updatetimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds')
            )
            domain_key = self.domains["carts"]["key"]
            cart_key = domain_key + "/" + cart_uuid
            cart_value = cart.model_dump()
            self.etcd.upsert(cart_key, cart_value)
            logger.info(f"Create created user:{user} cart:{cart}")

        response = {
            "uuid": xuuid
        }
        return response

    async def retrieve_users(self):
        logger.info("Retrieving users")
        domain_key = self.domains["users"]["key"]
        key = domain_key + "/*/*"
        items = self.etcd.retrieve_wildcard(key)
        users = [item["value"] for item in items]
        response = users
        logger.info(f"Retrieved users, response:{response}")
        return response

    async def retrieve_user_uuid(self, uuid: str):
        logger.info(f"Retrieving user uuid:{uuid}")
        domain_key = self.domains["users"]["key"]
        key = domain_key + "/*/" + uuid
        items = self.etcd.retrieve_wildcard(key)
        if len(items) == 0:
            return None
        users = [item["value"] for item in items]
        # Wildcards return multiple items, but retrieving
        # by UUID can only return one item, so use the first one.
        user = users[0]
        logger.info(f"Retrieved user uuid:{uuid}, user:{user}")
        return user

    async def retrieve_user_email(self, email: str):
        logger.info(f"Retrieving user email:{email}")
        domain_key = self.domains["users"]["key"]
        key = domain_key + "/*/*"
        logger.info(f"key:{key}")

        items = self.etcd.retrieve_wildcard(key)

        # Users can be registered in multiple emails,
        # so the email is not unique for a user, but unique
        # only for a role/email... hence multiple users are returned
        users: models.User = []
        if items:
            items = [item["value"] for item in items]
            logger.info(f"items:{items}")
            xitems = [x for x in items if x["contact"]["email"] == email]
            logger.info(f"xitems:{xitems}")
            for item in xitems:
                logger.info(f"item:{item}")
                user = models.User(**item)
                logger.info(f"user:{user}")
                users.append(user)

        logger.info(f"Retrieved users email:{email}, users:{users}")
        return users

    async def retrieve_user_role_email(self, role: str, email: str):
        logger.info(f"Retrieving user role:{role} email:{email}")
        domain_key = self.domains["users"]["key"]
        key = domain_key + "/*/*"
        logger.info(f"key:{key}")

        items = self.etcd.retrieve_wildcard(key)
        if not items:
            return None

        # Users are unique for a role/email
        user: models.User = None
        items = [item["value"] for item in items]
        logger.info(f"items:{items}")
        xitems = [x for x in items if x["role"] == role and x["contact"]["email"] == email]
        logger.info(f"xitems:{xitems}")
        if len(xitems) > 0:
            item = xitems[0]
            logger.info(f"item:{item}")
            user = models.User(**item)
            logger.info(f"user:{user}")

        logger.info(f"Retrieved users email:{email}, user:{user}")
        return user

    #####
    # AUTH (login/logout)
    #####

    async def auth_login_user(self, role: str, email: str, password: str):
        logger.info(f"Auth login user role:{role} email:{email} password:{password}")

        user_exists = await self._verify_user_email(role, email)
        if not user_exists:
            msg = f"User not found, role:{role} email:{email}"
            raise BgsNotFoundException(msg)
        logger.info(f"Using verified user role:{role} email:{email}")

        # Mark the user as status: STATUS_AUTHORIZED
        domain_key = self.domains["auths"]["key"]
        key = domain_key + "/" + role + "/" + email
        value = STATUS_AUTHORIZED
        self.etcd.upsert(key, value)

        response = {
            "status": RESULT_SUCCESS
        }

        logger.info(f"Auth login successful user role:{role} email:{email} password:{password}, response:{response}")
        return response

    async def auth_logout_user(self, role: str, email: str):
        logger.info(f"Auth logout user role:{role} email:{email}")

        user_exists = await self._verify_user_email(role, email)
        if not user_exists:
            msg = f"User not found, role:{role} email:{email}"
            raise BgsNotFoundException(msg)
        logger.info(f"Using verified user role:{role} email:{email}")

        # Mark the user as status: STATUS_UNAUTHORIZED
        domain_key = self.domains["auths"]["key"]
        key = domain_key + "/" + role + "/" + email
        value = STATUS_UNAUTHORIZED
        self.etcd.upsert(key, value)

        response = {
            "status": RESULT_SUCCESS
        }

        logger.info(f"Auth logout successful user role:{role} email:{email}, response:{response}")
        return response

    async def auth_statistics(self):
        logger.info("Retrieving auth statistics")

        auths = []
        domain_key = self.domains["auths"]["key"]
        key = domain_key + "/*/*"
        logger.info(f"Using key:{key}")
        items = self.etcd.retrieve_wildcard(key)
        logger.info(f"Using items:{items}")
        for item in items:
            logger.info(f"Using item:{item}")
            item_key = item["key"]
            item_value = item["value"]
            logger.info(f"Using item_key:{item_key} item_value:{item_value}")

            # Split the item key (it is a path,
            # like "/auths/guest/guest@brodagroupsoftware.com")
            # but note that the split's first value is " ", the second
            # is "auths" and we are only interested in the
            # role and email parts
            *_, role, email = item_key.split("/")

            auth = {
                "role": role,
                "email": email,
                "status": item_value
            }
            auths.append(auth)

        logger.info(f"Retrieving auth statistics, response:{items}")
        return auths

    async def auth_status(self, email: str):
        logger.info(f"Retrieving auth status email:{email}")

        # Note that a user can be logged in using multiple roles
        # and hence a list of status are returned instead of a single item
        auths = await self.auth_statistics()
        items = []
        for auth in auths:
            if auth["email"] == email:
                items.append(auth)

        logger.info(f"Retrieving auth status email:{email}, items:{items}")
        return items

    #####
    # CARTS
    #####

    async def register_cart(self, cart: models.Cart):
        # Note: this is here for completeness... Carts
        # are only created for subscribers when the
        # subscriber user is registered
        logger.info(f"Registering cart:{cart}")

        xuuid = f"{uuid.uuid4()}"
        cart.uuid = xuuid
        cart.createtimestamp = datetime.now().isoformat(sep=' ', timespec='milliseconds')
        cart.updatetimestamp = cart.createtimestamp
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + xuuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = {
            "uuid": xuuid
        }
        logger.info(f"Registering cart:{cart}, response:{response}")

        return response

    async def retrieve_carts(self):
        logger.info("Retrieving carts")
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/*"
        items = self.etcd.retrieve_wildcard(key)
        users = [item["value"] for item in items]
        response = users
        logger.info(f"Retrieved carts, response:{response}")
        return response

    async def retrieve_cart_uuid(self, uuid: str):
        logger.info(f"Retrieving cart uuid:{uuid}")
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + uuid
        cart = self.etcd.retrieve(key)
        logger.info(f"Retrieved cart uuid:{uuid}, cart:{cart}")
        return cart

    async def retrieve_cart_email(self, email: str):
        logger.info(f"Retrieving cart email:{email}")
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/*"
        logger.info(f"key:{key}")

        # Can only have a single cart for a user
        items = self.etcd.retrieve_wildcard(key)
        cart: models.Cart = None
        if items:
            items = [item["value"] for item in items]
            logger.info(f"items:{items}")
            xitems = [x for x in items if x["subscriber"] == email]
            logger.info(f"xitems:{xitems}")
            for item in items:
                logger.info(f"item:{item}")
                cart = models.Cart(**item)
                logger.info(f"cart:{cart}")
                break

        logger.info(f"Retrieved carts email:{email}, cart:{cart}")
        return cart

    async def register_cart_item_uuid(self, uuid:str, product_uuid: str, artifact_uuid):
        logger.info(f"Registering item in cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

        # FIX: Verify that the product and artifcat UUIDs are valid

        # Get the cart
        cart_dict = await self.retrieve_cart_uuid(uuid)
        if not cart_dict:
            msg = f"Cart not found:{uuid}"
            logger.error(msg)
            raise BgsNotFoundException(msg)
        cart = models.Cart(**cart_dict)

        logger.info(f"Using cart:{cart}")
        logger.info(f"Using cart uuid:{cart.uuid}")

        # Create the item
        item = models.Item(
            product_uuid=product_uuid,
            artifact_uuid=artifact_uuid
        )
        logger.info(f"Using item:{item}")

        # Add item to the cart
        cart.items.append(item)

        # UPSERT the cart
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart.uuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = cart
        logger.info(f"Registering item in cart uuid:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")

        return response

    async def register_cart_item_email(self, email:str, product_uuid: str, artifact_uuid):
        logger.info(f"Registering item in cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

        # FIX: Verify that the product and artifcat UUIDs are valid

        # Verify the email is for a subscriber
        user: models.User = await self.retrieve_user_role_email(models.ROLE_SUBSCRIBER, email)
        if not user:
            msg = f"Email not found:{email}"
            logger.error(msg)
            raise BgsNotFoundException(msg)

        if user.role != models.ROLE_SUBSCRIBER:
            msg = f"Invalid email, not in role:{models.ROLE_SUBSCRIBER}"
            logger.error(msg)
            raise BgsNotFoundException(msg)

        # Get the subscribers cart (and UUID)
        cart: models.Cart = await self.retrieve_cart_email(email)
        if not cart:
            msg = f"Cart does not exist for email:{email}"
            logger.error(msg)
            raise BgsException(msg)

        # Create the item
        item = models.Item(
            product_uuid=product_uuid,
            artifact_uuid=artifact_uuid
        )

        # Add item to the cart
        cart.items.append(item)

        # UPSERT the cart
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart.uuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = cart
        logger.info(f"Registering item in cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")

        return response

    async def unregister_cart_item_uuid(self, uuid:str, product_uuid: str, artifact_uuid):
        logger.info(f"Unregistering item in cart:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

        # FIX: Verify that the product and artifcat UUIDs are valid

        # Get the cart
        cart_dict = await self.retrieve_cart_uuid(uuid)
        if not cart_dict:
            msg = f"Cart not found:{uuid}"
            logger.error(msg)
            raise BgsNotFoundException(msg)
        cart = models.Cart(**cart_dict)

        # Create the item
        item = models.Item(
            product_uuid=product_uuid,
            artifact_uuid=artifact_uuid
        )

        # Remove item to the cart
        cart.items.remove(item)

        # UPSERT the cart
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart.uuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = cart
        logger.info(f"Unregistering item in cart:{uuid} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")

        return response

    async def unregister_cart_item_email(self, email:str, product_uuid: str, artifact_uuid):
        logger.info(f"Unregistering item in cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}")

        # FIX: Verify that the product and artifcat UUIDs are valid

        # Verify the email is for a subscriber
        user: models.User = await self.retrieve_user_role_email(models.ROLE_SUBSCRIBER, email)
        if not user:
            msg = f"Email not found:{email}"
            logger.error(msg)
            raise BgsNotFoundException(msg)

        if user.role != models.ROLE_SUBSCRIBER:
            msg = f"Invalid email, not in role:{models.ROLE_SUBSCRIBER}"
            logger.error(msg)
            raise BgsNotFoundException(msg)

        # Get the subscribers cart (and UUID)
        cart: models.Cart = await self.retrieve_cart_email(email)
        if not cart:
            msg = f"Cart does not exist for email:{email}"
            logger.error(msg)
            raise BgsException(msg)

        # Create the item
        item = models.Item(
            product_uuid=product_uuid,
            artifact_uuid=artifact_uuid
        )

        # Remove item to the cart
        cart.items.remove(item)

        # UPSERT the cart
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart.uuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = cart
        logger.info(f"Unregistering item in cart email:{email} product_uuid:{product_uuid} artifact_uuid:{artifact_uuid}, response:{response}")

        return response

    #####
    # ORDERS
    #####

    async def register_order(self, cart_uuid: str):
        logger.info(f"Registering order cart_uuid:{cart_uuid}")

        # FIX: Need to verify carts, user, etc...

        # Get the cart information
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart_uuid
        logger.info(f"Using key:{key}")
        cart_dict = self.etcd.retrieve(key)
        logger.info(f"Using cart_dict:{cart_dict}")
        cart = models.Cart(**cart_dict)

        # Remove the old cart for the user
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + cart.uuid
        self.etcd.remove(key)

        # Create the order
        immutable_order = await self._create_immutable_order(cart)
        domain_key = self.domains["orders"]["key"]
        key = domain_key + "/" + immutable_order.uuid
        value = immutable_order.model_dump()
        self.etcd.upsert(key, value)

        # Create a new cart for the user
        new_cart_uuid = f"{uuid.uuid4()}"
        cart = models.Cart(
            uuid=new_cart_uuid,
            subscriber=immutable_order.subscriber,
            items=[],
            createtimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds'),
            updatetimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds')
        )
        domain_key = self.domains["carts"]["key"]
        key = domain_key + "/" + new_cart_uuid
        value = cart.model_dump()
        self.etcd.upsert(key, value)

        response = {
            "uuid": immutable_order.uuid
        }
        logger.info(f"Registering order cart_uuid:{cart_uuid}, response:{response}")

        return response

    async def retrieve_orders(self):
        logger.info("Retrieving orders")
        domain_key = self.domains["orders"]["key"]
        key = domain_key + "/*/*"
        items = self.etcd.retrieve_wildcard(key)
        users = [item["value"] for item in items]
        response = users
        logger.info(f"Retrieved orders, response:{response}")
        return response

    async def retrieve_order_uuid(self, uuid: str):
        logger.info(f"Retrieving order uuid:{uuid}")
        domain_key = self.domains["orders"]["key"]
        key = domain_key + "/" + uuid
        order = self.etcd.retrieve(key)
        logger.info(f"Retrieved order uuid:{uuid}, order:{order}")
        return order

    async def retrieve_orders_email(self, email: str):
        logger.info(f"Retrieving order email:{email}")
        domain_key = self.domains["orders"]["key"]
        key = domain_key + "/*"
        logger.info(f"key:{key}")

        # Multiple orders for a single user
        items = self.etcd.retrieve_wildcard(key)
        orders: List[models.OrderImmutable] = []
        if items:
            items = [item["value"] for item in items]
            logger.info(f"items:{items}")
            xitems = [x for x in items if x["subscriber"] == email]
            logger.info(f"xitems:{xitems}")
            for item in items:
                logger.info(f"item:{item}")
                order = models.OrderImmutable(**item)
                logger.info(f"order:{order}")
                orders.append(order)

        logger.info(f"Retrieved orders email:{email}, orders:{orders}")
        return orders

    #####
    # UTILITY
    #####

    async def dump(self):
        logger.info("Dumping registry")
        key = "/"
        items = self.etcd.retrieve_prefix(key)
        logger.info(f"Dumping registry, items:{items}")
        return items

    #####
    # INTERNAL
    #####

    async def _verify_role(self, role: str):
        if role.lower() in VALID_ROLES:
            return True
        else:
            return False

    async def _verify_product(self, product: models.Product):
        # Verify that the product already exists
        xproduct = await self.retrieve_product_namespace_name(
                    product.namespace,
                    product.name)
        return bool(xproduct)

    async def _verify_user_email(self, role: str, email: str):
        # Verify that the product already exists
        xuser = await self.retrieve_user_role_email(role, email)
        return bool(xuser)

    async def _create_immutable_order(self, cart: models.Cart) -> models.OrderImmutable:
        """
        Create an immutable order.

        Note that orders are immutable as they are
        a part of the historical record.  This means that
        any UUID references (which can change or be deleted
        over time) must be resolved into full and de-referenced
        objects.
        """
        logger.info(f"Creating immutable order from cart:{cart}")

        # Transform each item (product uuid, cart uuid)
        # into an immutable item
        immutable_items: List[models.ItemImmutable] = []
        for item in cart.items:
            product_uuid = item.product_uuid
            artifact_uuid = item.artifact_uuid

            # Validate the product
            logger.info(f"Validating product_uuid:{product_uuid}")
            product_domain_key = self.domains["products"]["key"]
            product_key = product_domain_key + "/" + product_uuid
            product_dict = self.etcd.retrieve(product_key)
            product = models.Product(**product_dict)
            logger.info(f"Found registered product:{product}")
            # Check if product exists (raise not found)

            # Get fully qualified product information
            logger.info(f"Acquiring fully qualified product:{product}")
            artifact: models.Artifact = await self._retreve_artifact(product_uuid, artifact_uuid)
            # Check if fqproduct exists (raise not found)

            # Create the immutable item and add it
            # to the list of items
            immutable_item = models.ItemImmutable(
                product=product,
                artifact=artifact
            )
            immutable_items.append(immutable_item)

        # Create an immutable cart (note: use the same
        # cart UUID to maintain continuity to original cart)
        immutable_cart = models.CartImmutable(
            uuid=cart.uuid,
            subscriber=cart.subscriber,
            items=immutable_items,
            createtimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds'),
            updatetimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds')
        )

        # Create an immutable order (new UUID is needed)
        immutable_order_uuid = f"{uuid.uuid4()}"
        immutable_order = models.OrderImmutable(
            uuid=immutable_order_uuid,
            subscriber=cart.subscriber,
            cart=immutable_cart,
            createtimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds'),
            updatetimestamp=datetime.now().isoformat(sep=' ', timespec='milliseconds')
        )
        return immutable_order

    async def _retreve_artifact(self, productuuid: str, artifactuuid: str) -> models.Artifact:
        """Discover artifact"""
        logger.info(f"Discover artifact productuuid:{productuuid} artifactuuid:{artifactuuid}")
        service = ENPOINT_DATAPRODUCT + f"/uuid/{productuuid}/artifacts/{artifactuuid}"
        method = "GET"
        artifact_dict = await utilities.httprequest(self.proxyhost, self.proxyport, service, method)
        artifact = models.Artifact(**artifact_dict)

        logger.info(f"Discover artifact productuuid:{productuuid} artifactuuid:{artifactuuid}, response:{artifact}")
        return artifact


