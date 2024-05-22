from pydantic import BaseModel
from fastapi import Form
from typing import Optional
from datetime import datetime


class UserForm(BaseModel):
    member_email: str

    @classmethod
    def as_form(cls, member_email: str = Form(...)):
        return cls(member_email=member_email)


class UserBoard(BaseModel):
    member_id: int
    member_email: str
    img_uuid: str
    created_at: datetime


class ImageForm(BaseModel):
    keyword_input: str
    style_code: str

    @classmethod
    def as_form(cls, keyword_input: str = Form(...), style_code: str = Form(...)):
        return cls(keyword_input=keyword_input, style_code=style_code)


class ImageSave(BaseModel):
    member_id: int
    img_url: str
    keyword_input: str
    style_code: str


class ImageTshirtShow(BaseModel):
    img_id: int
    member_id: int
    img_url: str


class ImageShow(ImageTshirtShow):
    keyword_input: Optional[str] = None
    style_code: Optional[str] = None


class ImageUpdate(BaseModel):
    generating_count: int
