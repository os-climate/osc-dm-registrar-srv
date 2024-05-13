# Copyright 2024 Broda Group Software Inc.
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
#
# Created:  2024-04-15 by eric.broda@brodagroupsoftware.com

# NOTE: It is important to ensure this file is identical to that
# in the bgssrv-dmregistry server models.py or you will
# get 422 Unprocessed Entity errors

from pydantic import BaseModel, HttpUrl, Field
from typing import List, Optional, Dict
from enum import Enum

ROLE_GUEST = "guest"
ROLE_PUBLISHER = "publisher"
ROLE_SUBSCRIBER = "subscriber"
ROLE_ADMINISTRATOR = "administrator"

#####
# PRODUCT
#####

# Core product
class Product(BaseModel):
    uuid: Optional[str] = None
    namespace: str
    name: str
    publisher: str
    description: str
    tags: List[str]
    address: Optional[str] = None
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Resource(BaseModel):
    relationship: str
    mimetype: str
    url: str

class Artifact(BaseModel):
    uuid: Optional[str] = None
    productuuid: Optional[str] = None
    productnamespace: Optional[str] = None
    productname: Optional[str] = None
    name: str
    description: str
    tags: List[str]
    license: str
    securitypolicy: str
    links: List[Resource]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class FQProduct(BaseModel):
    product: Product
    artifacts: List[Artifact]

#####
# USER
#####

# Contact information
class Contact(BaseModel):
    name: str
    email: str
    phone: str

# A User of the Data Mesh
class User(BaseModel):
    uuid: Optional[str] = None
    contact: Contact  # Assuming Contact is a defined Pydantic model
    # address: Address  # Assuming Address is a defined Pydantic model
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None
    role: str  # Add the 'role' attribute here

# An operations event (login/logout etc)
class Event(BaseModel):
    type: str
    email: str
    logintimestamp: Optional[str] = None

# Product registration (product and all its artifact names)
class Registration(BaseModel):
    product: Product
    artifact_names: List[str]

# Registration UUIDs for product and each artifact
class UUIDs(BaseModel):
    product_uuid: str
    artifact_uuids: List[Dict[str, str]]

#####
# CARTS and ORDERS
#####

# Cart item
class Item(BaseModel):
    product_uuid: str
    artifact_uuid: str

# Cart containing items
class Cart(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    items: List[Item]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

# Order containing a cart that has been purchased
class Order(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    cartuuid: str
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

# An immutable item representation of a cart item
class ItemImmutable(BaseModel):
    product: Product
    artifact: Artifact

# An immutable representation of a Cart
class CartImmutable(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    items: List[ItemImmutable]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

# An immutable reprentation of an order
class OrderImmutable(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    cart: CartImmutable
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None
