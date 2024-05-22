from django.db import models


class CommonModel(models.Model):
    # auto_now_add : 현재 데이터 생성시간 기준 이후 수정 x
    created_at = models.DateTimeField(auto_now_add=True)
    # auto_now : 현제 데이터 생성 이후 데이터 업데이트시 시간도 업데이트 !
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True  # 데이터베이스에 컬럼이 추가되지않는다
