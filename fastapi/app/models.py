from sqlalchemy.orm import relationship, as_declarative
from sqlalchemy import (
    Column,
    Integer,
    String,
    ForeignKey,
    DateTime,
    Text,
    SmallInteger,
    CheckConstraint,
    Boolean,
)
from datetime import datetime, timedelta
from database import Base
import uuid


# Base class override
@as_declarative()
class Base:
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    __name__: str


class User(Base):
    __tablename__ = "users_user"

    member_id = Column(Integer, primary_key=True, index=True)
    member_email = Column(String(length=100), nullable=False, index=True)
    img_uuid = Column(String(36), default=str(uuid.uuid4()))
    img_generate_count = Column(SmallInteger, default=0)
    is_staff = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    mem_waiting = Column(Boolean, default=False)
    mem_number = Column(String(20), nullable=True)

    # Define the relationship with Image
    images = relationship("Image", back_populates="member")

    def __repr__(self):
        return f"<User(member_email='{self.member_email}', is_admin={self.is_admin})>"


class Image(Base):
    __tablename__ = "users_image"
    img_id = Column(Integer, primary_key=True, index=True)
    member_id = Column(Integer, ForeignKey("users_user.member_id"))
    img_url = Column(String(length=255))
    keyword_input = Column(Text)
    generating_count = Column(SmallInteger, default=0)
    style_code = Column(String(length=20))
    expiration_date = Column(DateTime, default=datetime.now() + timedelta(days=7))

    member = relationship("User", back_populates="images")
