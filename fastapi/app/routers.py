from fastapi import (
    APIRouter,
    Depends,
    Form,
    UploadFile,
    HTTPException,
    status,
)
from fastapi.responses import JSONResponse
from typing import Annotated
from sqlalchemy.orm import Session
from database import get_db
import os

from pathlib import Path
from starlette.templating import Jinja2Templates
from generator import generate_ai_image_community_model, generate_ai_image
from s3_utils import upload_byte_to_s3
import crud, schemas
from authentication import get_current_user

# router setting
img_router = APIRouter(prefix="/image")


@img_router.post("/create", status_code=201)
def get_ai_images(
    # email: Annotated[str | None, Cookie()] = None,
    keyword: str = Form(...),
    style: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    email = current_user["member_email"]
    print(current_user)
    print(email)
    # 1. user email을 쿠키로부터 받아온후, email을 이용해서 user id를 db에서 받아온다
    if not email:
        raise HTTPException(status_code=400, detail="You are not an authorized user!")

    if not (keyword and style):
        raise HTTPException(
            status_code=400, detail="keyword and style are required, please try again."
        )

    user = crud.get_user_by_email(db=db, user_email=email)
    if user and (user.img_generate_count < 2):

        # 2. 이미지를 생성한다
        img_urls = generate_ai_image_community_model(keyword, style)
        print(img_urls)

        # 프롬프트로부터 생성된 이미지 url이 없는 경우
        if not img_urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image was not created based on your prompt, please try again!",
            )

        # 3. 이미지 info를 db에 insert한다
        for url in img_urls:
            db_img = crud.create_image(db, user.member_id, url, keyword, style)

        # 4. user table의 count 1 증가
        crud.update_user_count(db, user.member_id)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Images have been created successfully!"},
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="You have reached the maxium attempts (2) of generating AI images.",
    )


@img_router.post("/tmp_create", status_code=201)
def get_ai_images(
    # email: Annotated[str | None, Cookie()] = None,
    keyword: str = Form(...),
    style: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    # 1. user email을 쿠키로부터 받아온후, email을 이용해서 user id를 db에서 받아온다
    email = current_user["member_email"]
    if not email:
        raise HTTPException(status_code=400, detail="Your are not an authorized user!")

    if not (keyword and style):
        raise HTTPException(
            status_code=400, detail="keyword and style are required, please try again."
        )

    user = crud.get_user_by_email(db=db, user_email=email)
    if user:

        # 2. 이미지를 생성한다
        img_urls = generate_ai_image_community_model(keyword, style)
        print(img_urls)

        # 프롬프트로부터 생성된 이미지 url이 없는 경우
        if not img_urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image was not created based on your prompt, please try again!",
            )

        # 3. 이미지 info를 db에 insert한다
        for url in img_urls:
            db_img = crud.create_image(db, user.member_id, url, keyword, style)

        # 4. user table의 count 1 증가
        crud.update_user_count(db, user.member_id)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={"message": "Images have been created successfully!"},
        )


@img_router.get(
    "/show-samples", response_model=list[schemas.ImageShow], status_code=200
)
def show_sample_images_by_user(
    # email: Annotated[str | None, Cookie()] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    # 1. user email을 쿠키로부터 받아온후, email을 이용해서 user id를 db에서 받아온다
    email = current_user["member_email"]
    if not email:
        raise HTTPException(status_code=400, detail="You are not an authorized user!")
    user = crud.get_user_by_email(db=db, user_email=email)

    if user:
        # load ai images created by user
        excluded = "tshirt"
        print("current user's email : ", user.member_email)
        image_list = crud.get_sample_image_by_user(db, user.member_id, excluded)
        if not image_list:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample Iamge does not exist!",
            )

        return image_list


@img_router.post("/save-images", status_code=201)
def upload_multiple_files(
    files: list[UploadFile],
    # email: Annotated[str | None, Cookie()] = None,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):

    # user email을 쿠키로부터 받아온다
    email = current_user["member_email"]
    if not email:
        raise HTTPException(
            status_code=400, detail="Your email info does not exists in cookie!"
        )
    # email 주소를 통해 해당 유저 불러오기
    user = crud.get_user_by_email(db=db, user_email=email)
    print("current user's email : ", user.member_email)

    url_list = []

    bucket_name = os.getenv("S3_BUCKET_NAME")
    base_dir = "img/tshirt-"

    for file in files:
        # 파일 타입이 이미지인지 확인 (예: JPEG, PNG 등)
        allowed_image_types = ["image/jpg", "image/webp", "image/jpeg", "image/png"]
        if file.content_type not in allowed_image_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Only PNG, JPEG, JPG and WEBP images are supported!",
            )

        img_url = upload_byte_to_s3(
            filedata=file.file, bucket=bucket_name, base_dir=base_dir
        )

        # insert t-shirt image info into database
        crud.create_tshirt_image(db, user.member_id, img_url)
        url_list.append(img_url)

    # return images' urls
    return {"url": url_list}


@img_router.get(
    "/load-imginfo", response_model=list[schemas.ImageShow], status_code=200
)
def show_sample_images_by_user(img_uuid: str, db: Session = Depends(get_db)):
    # 1. uuid를 이용하여 user 찾기
    user = crud.get_user_by_uuid(db=db, img_uuid=img_uuid)

    if not user:
        raise HTTPException(status_code=400, detail="The user does not exist!")

    else:
        # 2. 이미지 불러오기
        # load all images created by user
        print("current user's email : ", user.member_email)
        image_list = crud.get_all_images(db, user_id=user.member_id)
        if not image_list:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Image does not exist!",
            )

        return image_list

@img_router.post(
    "/create-load", response_model=list[schemas.ImageTshirtShow], status_code=201
)
def create_and_save_ai_images(
    # email: Annotated[str | None, Cookie()] = None,
    keyword: str = Form(...),
    style: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    email = current_user["member_email"]
    print(current_user)
    print(email)
    # 1. user email을 쿠키로부터 받아온후, email을 이용해서 user id를 db에서 받아온다
    if not email:
        raise HTTPException(status_code=400, detail="You are not an authorized user!")

    if not (keyword and style):
        raise HTTPException(
            status_code=400, detail="keyword and style are required, please try again."
        )

    user = crud.get_user_by_email(db=db, user_email=email)
    if user and (user.img_generate_count < 2):

        # 2. 이미지를 생성한다
        img_urls = generate_ai_image_community_model(keyword, style)
        print(img_urls)

        # 프롬프트로부터 생성된 이미지 url이 없는 경우
        if not img_urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image was not created based on your prompt, please try again!",
            )

        # 3. 이미지 info를 db에 insert한다
        for url in img_urls:
            db_img = crud.create_image(db, user.member_id, url, keyword, style)

        # 4. user table의 count 1 증가
        crud.update_user_count(db, user.member_id)

        # 5. load ai images
        pattern = "tshirt-"
        image_list = crud.get_sample_image_by_user(
            db, user.member_id, exclude_pattern=pattern
        )
        if not image_list:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample Image does not exist!",
            )
        return image_list

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="You have reached the maxium attempts (2) of generating AI images.",
    )

@img_router.post(
    "/tmp-create-load", response_model=list[schemas.ImageTshirtShow], status_code=201
)
def create_and_save_ai_images(
    # email: Annotated[str | None, Cookie()] = None,
    keyword: str = Form(...),
    style: str = Form(...),
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    email = current_user["member_email"]
    print(current_user)
    print(email)
    # 1. user email을 쿠키로부터 받아온후, email을 이용해서 user id를 db에서 받아온다
    if not email:
        raise HTTPException(status_code=400, detail="You are not an authorized user!")

    if not (keyword and style):
        raise HTTPException(
            status_code=400, detail="keyword and style are required, please try again."
        )

    user = crud.get_user_by_email(db=db, user_email=email)
    if user and (user.img_generate_count < 2):

        # 2. 이미지를 생성한다
        img_urls = generate_ai_image_community_model(keyword, style)
        print(img_urls)

        # 프롬프트로부터 생성된 이미지 url이 없는 경우
        if not img_urls:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Image was not created based on your prompt, please try again!",
            )

        # 3. 이미지 info를 db에 insert한다
        for url in img_urls:
            db_img = crud.create_image(db, user.member_id, url, keyword, style)

        # 4. user table의 count 1 증가
        crud.update_user_count(db, user.member_id)

        # 5. load ai images
        pattern = "tshirt-"
        image_list = crud.get_sample_image_by_user(
            db, user.member_id, exclude_pattern=pattern
        )
        if not image_list:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Sample Image does not exist!",
            )
        return image_list

