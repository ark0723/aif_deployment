import boto3
import os
import uuid
from dotenv import load_dotenv

"""
author: Ahla Ko
date: 04/28/2024
s3 documentation: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html
"""

load_dotenv()

bucket_name = os.getenv("S3_BUCKET_NAME")


def s3_connection():
    try:
        # create s3 client
        s3 = boto3.client(
            service_name="s3",
            region_name=os.getenv("REGION_NAME"),
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        )

    except Exception as e:
        # 어떤 에러가 발생하면 에러를 프린트
        print(e)

    else:
        print("s3 bucket connected")
        return s3


"""
ALLOWED_UPLOAD_ARGS = ['ACL', 'CacheControl', 'ChecksumAlgorithm', 'ContentDisposition', 'ContentEncoding', 'ContentLanguage', 'ContentType', 'ExpectedBucketOwner', 'Expires', 'GrantFullControl', 'GrantRead', 'GrantReadACP', 'GrantWriteACP', 'Metadata', 'ObjectLockLegalHoldStatus', 'ObjectLockMode', 'ObjectLockRetainUntilDate', 'RequestPayer', 'ServerSideEncryption', 'StorageClass', 'SSECustomerAlgorithm', 'SSECustomerKey', 'SSECustomerKeyMD5', 'SSEKMSKeyId', 'SSEKMSEncryptionContext', 'Tagging', 'WebsiteRedirectLocation']
"""


def upload_file_to_s3(bucket, file_dir):
    # S3.Client.upload_file(Filename, Bucket, Key, ExtraArgs=None, Callback=None, Config=None)
    # s3 client connection
    s3 = s3_connection()

    base_file_name = "img/tshirt-"

    try:
        # 이미지 업로드시 content_type을 지정하지 않으면 버킷에서 url_img클릭하면 이미지 다운로드로 작동함
        # 브라우저에서 이미지 오픈하려면 content_type 지정 필요
        if "png" in file_dir:
            content_type = "image/png"
        elif "jpg" in file_dir:
            content_type = "image/jpg"
        elif "jpeg" in file_dir:
            content_type = "image/jpeg"
        elif "webp" in file_dir:
            content_type = "image/webp"
        else:
            content_type = ""

        # s3.upload_file("{로컬에서 올릴 파일이름}","{버킷 이름}","{버킷에 저장될 파일 이름}")
        s3.upload_file(
            file_dir,
            bucket,
            base_file_name + file_dir,
            ExtraArgs={"ContentType": content_type},
        )
        img_s3_url = os.getenv("S3_URL") + base_file_name + file_dir

    except Exception as e:
        print(e)

    else:
        print("file uploaded to s3 bucket!")
        return img_s3_url


# file upload to s3
def upload_byte_to_s3(filedata, bucket, base_dir):
    # s3 client connection
    s3 = s3_connection()

    # randomly created uuid -> filename
    filename = base_dir + f"{str(uuid.uuid4())}.png"
    print(filename)
    print(type(filename))
    content_type = "image/png"

    try:
        # s3.upload_fileobj(Fileobj, Bucket, Key, ExtraArgs=None, Callback=None, Config=None)
        s3.upload_fileobj(
            filedata,
            bucket,
            filename,
            ExtraArgs={"ContentType": content_type},
        )
        img_s3_url = os.getenv("S3_URL") + filename

    except Exception as e:
        print(e)

    else:
        print("file uploaded to s3 bucket!")
        return img_s3_url


def download_file_from_s3(bucket, filename, save_dir):
    # S3.Client.download_file(Bucket, Key, Filename, ExtraArgs=None, Callback=None, Config=None)
    # save_dir: 다운받은 이미지 저장 경로
    s3 = s3_connection()
    try:
        s3.download_file(bucket, filename, save_dir)
    except Exception as e:
        print(e)
    else:
        print("file downloaded from s3 bucket!")


def get_obj_list_from_s3(prefix="img/"):
    # S3 client connection
    s3 = s3_connection()

    # bucket name
    bucket_name = os.getenv("S3_BUCKET_NAME")

    # objects list in bucket
    obj_list = s3.list_objects(Bucket=bucket_name, Prefix=prefix)["Contents"]

    return obj_list


def get_obj_from_s3(bucket, objectname):
    s3 = s3_connection()
    obj = s3.get_object(Bucket=bucket, Key=objectname)
    return obj


def get_img_type(obj):
    # get filename extension
    return obj["ContentType"][6:]


def get_img_date(obj):

    from datetime import timedelta

    """
    return lastmodified time 
    time: UTC  -> Seoul Time
    """
    obj_time = obj["LastModified"]
    seoul_time = str(obj_time + timedelta(hours=9)).split()
    date, time = seoul_time[0], seoul_time[1]
    return date, time


# img_obj = get_obj_from_s3(bucket=bucket_name, objectname="img/tshirt-example.png")
# print(get_img_type(img_obj))
# date, time = get_img_date(img_obj)
# print(date, time)


# uploaded = upload_file_to_s3(bucket=bucket_name, file_dir="example.png")
# obj_list = get_obj_list_from_s3()
# print(obj_list)
