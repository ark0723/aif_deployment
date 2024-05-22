from models import User, Image
from schemas import UserForm
from sqlalchemy.orm import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import (
    SQLAlchemyError,
    IntegrityError,
    DataError,
    OperationalError,
    InvalidRequestError,
)
from fastapi import HTTPException, status
from fastapi import Form


# 유저 생성
def create_user(db: Session, user: UserForm):
    db_user = User(member_email=user.member_email)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# 유저 조회 by email
def get_user_by_email(db: Session, user_email: str):
    try:
        user = db.query(User).filter(User.member_email == user_email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with email '{user_email}' not found",
            )
        return user
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred",
        ) from e


# 유저 조회 by img_uuid
def get_user_by_uuid(db: Session, img_uuid: str):
    try:
        user = db.query(User).filter(User.img_uuid == img_uuid).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"User with UUID '{img_uuid}' not found",
            )
        return user
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred",
        ) from e


# 전체 유저 리스트
def get_all_users(db: Session):
    try:
        users = db.query(User).all()
        return users
    except SQLAlchemyError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred",
        ) from e


# 이미지생성
def create_image(
    db: Session,
    user_id: int,
    url: str,
    keyword: str = Form(...),
    style: str = Form(...),
):
    try:
        db_img = Image(
            member_id=user_id,
            img_url=url,
            keyword_input=keyword,
            style_code=style,
        )
        db.add(db_img)
        db.commit()
        db.refresh(db_img)
        return db_img
    except (IntegrityError, DataError) as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=f"Failed to create image: {str(e)}")


# 이미지생성
def create_tshirt_image(
    db: Session,
    user_id: int,
    url: str,
):
    try:
        db_img = Image(
            member_id=user_id, img_url=url, keyword_input="t-shirt", style_code="null"
        )
        db.add(db_img)
        db.commit()
        db.refresh(db_img)
        return db_img
    except (IntegrityError, DataError) as e:
        db.rollback()
        raise HTTPException(
            status_code=400, detail=f"Failed to create t-shirt image: {str(e)}"
        )


# 이미지 생성시 count 1씩 증가, max = 2
def update_user_count(db: Session, user_id: int):
    try:
        db_user = db.query(User).filter(User.member_id == user_id).first()

        if not db_user:
            raise HTTPException(
                status_code=404, detail=f"User with ID {user_id} not found"
            )

        # 최대 생성 가능 횟수: 2
        if db_user.img_generate_count >= 2:
            return  # Maximum count reached, no update needed

        db_user.img_generate_count += 1
        db.commit()
        db.refresh(db_user)

        return db_user
    except NoResultFound:
        db.rollback()
    raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")


# 모든 이미지 조회 by user_id
def get_all_images(db: Session, user_id: int):
    try:
        img_list = db.query(Image).filter(Image.member_id == user_id).all()
        return img_list
    except (OperationalError, InvalidRequestError) as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# 전체 사용자들의 티셔츠 샘플 이미지 최신순 조회
def get_sample_image_list(db: Session, limit_num: int, including: str):
    img_sample_list = (
        db.query(Image)
        .filter(Image.img_url.contains(including))
        .order_by(Image.created_at.desc())
        .limit(limit_num)
        .all()
    )
    return img_sample_list


# 특정 유저가 생성한 샘플 이미지 최신순 조회(티셔츠 이미지 불포함)
def get_sample_image_by_user(db: Session, user_id: int, exclude_pattern: str):
    img_sample_list = (
        db.query(Image)
        .filter(Image.member_id == user_id)
        .filter(~Image.img_url.contains(exclude_pattern))
        .order_by(Image.created_at.desc())
        .all()
    )
    return img_sample_list
