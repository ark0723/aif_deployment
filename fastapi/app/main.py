from fastapi import FastAPI, Request, Depends, Response, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pathlib import Path
from starlette.templating import Jinja2Templates
from schemas import UserForm, UserBoard, ImageTshirtShow
from routers import img_router
from sqlalchemy.orm import Session
from database import get_db
import re
import crud
import datetime


app = FastAPI()
app.include_router(img_router)

templates = Jinja2Templates(directory="templates")

# CORS settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", response_model=list[ImageTshirtShow], status_code=200)
def show_tshirt_sample_images(db: Session = Depends(get_db)):
    included_pattern = "tshirt-"

    image_list = crud.get_sample_image_list(
        db, limit_num=10, including=included_pattern
    )

    if not image_list:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sample Iamge does not exist!",
        )

    return image_list


