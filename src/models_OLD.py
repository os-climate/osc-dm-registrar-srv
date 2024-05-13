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
from typing import List, Union, Optional, Dict
from enum import Enum

class Product(BaseModel):
    uuid: Optional[str] = None
    namespace: str
    name: str
    publisher: str
    description: str
    tags: List[str]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Resource(BaseModel):
    mimetype: str
    url: str

class Artifact(BaseModel):
    uuid: Optional[str] = None
    productnamespace: Optional[str] = None
    productname: Optional[str] = None
    name: str
    description: str
    tags: List[str]
    license: str
    securitypolicy: str
    data: Optional[Resource] = None
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Cart(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    items: List[str]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Order(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    cartuuid: str
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class ItemImmutable(BaseModel):
    product: Product
    artifact: Artifact

class CartImmutable(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    items: List[ItemImmutable]
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class OrderImmutable(BaseModel):
    uuid: Optional[str] = None
    subscriber: str
    cart: CartImmutable
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Contact(BaseModel):
    name: str
    email: str
    phone: str

# class Address(BaseModel):
#     country: str
#     province_state: str
#     city: str
#     street: List[str]
#     postal_zipcode: str

class FQProduct(BaseModel):
    product: Product
    artifacts: List[Artifact]

class Entity(BaseModel):
    uuid: Optional[str] = None
    email: str
    role: str
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class User(BaseModel):
    uuid: Optional[str] = None
    contact: Contact
    # address: Address
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Publisher(BaseModel):
    uuid: Optional[str] = None
    contact: Contact
    # address: Address
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Subscriber(BaseModel):
    uuid: Optional[str] = None
    contact: Contact
    # address: Address
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Administrator(BaseModel):
    uuid: Optional[str] = None
    contact: Contact
    # address: Address
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Registration(BaseModel):
    uuid: Optional[str] = None
    publisher: Publisher
    fqproduct: FQProduct
    createtimestamp: Optional[str] = None
    updatetimestamp: Optional[str] = None

class Event(BaseModel):
    uuid: Optional[str] = None
    name: str
    data: Union[Dict, List]
    createtimestamp: Optional[str] = None
