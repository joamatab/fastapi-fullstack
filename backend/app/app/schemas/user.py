from typing import Any, Dict, Optional, List, TypedDict

from pydantic import BaseModel, Field, EmailStr, validator
from bson.objectid import ObjectId

from app.schemas.utils import PyObjectId, Scope
from app.core.config import settings
from app.core.security import get_password_hash


# Shared properties
class UserBase(BaseModel):
    email: Optional[EmailStr] = None
    is_active: bool = True
    is_superuser: bool = False
    # regex meaning
    # first str before ':' should only be in a-z, 0-9, -, _
    # second or after str after first ':' should only be in a-z, 0-9, -, _, @, . (think of email)
    # ':some_str' should appear at least 1, and can appear more than 1
    scopes: Optional[List[Scope]] = None

    @validator("email")
    def email_validate_provider(cls, v: EmailStr) -> EmailStr:
        if settings.EMAIL_PROVIDER_RESTRICTION and all(
            provider not in v for provider in settings.ALLOWED_EMAIL_PROVIDER_LIST
        ):
            raise ValueError("Invalid email provider")
        return v


# Properties to receive via API on creation
class UserCreate(UserBase):
    email: EmailStr
    password: str

    """
    You'll often want to use this together with pre,
    since otherwise with always=True pydantic would try to validate the default None
    which would cause an error.
    """

    @validator("scopes", pre=True, always=True)
    def scopes_validate_default_value(
        cls, v: Optional[List[str]], values: Dict[str, Any]
    ) -> List[str]:
        if v is None:
            v = []
        default_scope = "user:" + values["email"]
        if default_scope not in v:
            v.append(default_scope)
        if values["is_superuser"] is True:
            v.append("role:admin")
        return v


# Properties to receive via API on update
class UserUpdate(UserBase):
    password: Optional[str] = None


# Additional properties stored in DB
class UserToDB(UserBase):
    hashed_password: Optional[str] = Field(None, alias="password")

    class Config:
        allow_population_by_field_name = True

    @validator("hashed_password")
    def hash_password(cls, v: str) -> str:
        return get_password_hash(v)


# Additional properties to return via API
# not showing password or hashed_password
class UserFromDB(UserBase):
    id: Optional[PyObjectId] = Field(None, alias="_id")

    class Config:
        """
        Reference: https://pydantic-docs.helpmanual.io/usage/model_config/
        allow_population_by_field_name: whether an aliased field may be populated by its name as given by the model attribute, as well as the alias
        arbitrary_types_allowed: If False, RuntimeError will be raised on model declaration if the value is not an instance of the type
        json_encoders: a dict used to customise the way types are encoded to JSON
        """

        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {ObjectId: str}


class UserCheckScopes(BaseModel):
    email: Optional[EmailStr] = None
    scopes: Optional[List[Scope]] = None


# just for type check in crud
class UserInDB(TypedDict):
    _id: ObjectId
    email: EmailStr
    hashed_password: str
    is_active: bool
    is_superuser: bool
    scopes: List[Scope]
