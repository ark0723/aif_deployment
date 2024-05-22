from django.contrib import admin
from .models import Question, Answer


@admin.register(Question)
class QuestionAdmin(admin.ModelAdmin):
    # display fields
    list_display = ["question_id", "question_content", "is_active"]
    # created_at descending order
    ordering = ("question_id",)


@admin.register(Answer)
class AnswerAdmin(admin.ModelAdmin):
    pass
