from typing import Any, Dict, Optional, Union

from pydantic import EmailStr

from app import schemas
from app.core.security import get_password_hash, verify_password
from app.crud.base import CRUDBase


class CRUDUser(CRUDBase[schemas.UserInDB, schemas.UserCreate, schemas.UserUpdate]):
    def get_by_email(
        self, collection: Any, email: Union[str, EmailStr]
    ) -> Optional[schemas.UserInDB]:
        return collection.find_one({"email": email})

    def authenticate(
        self, collection: Any, email: Union[str, EmailStr], password: str
    ) -> Optional[schemas.UserInDB]:
        if user := self.get_by_email(collection, email=email):
            return user if verify_password(password, user["hashed_password"]) else None
        else:
            return None

    def is_active(self, user: schemas.UserInDB) -> bool:
        return user["is_active"]

    def is_superuser(self, user: schemas.UserInDB) -> bool:
        return user["is_superuser"]


user = CRUDUser(schemas.UserToDB)
