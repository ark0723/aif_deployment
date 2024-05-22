from rest_framework.serializers import ModelSerializer
from .models import Question, Answer
from users.serializers import UserAnswerSerializer


class AnswerSerializer(ModelSerializer):
    # Answer의 user모델을 직렬화 하기 위해 필요한 코드
    user = UserAnswerSerializer(read_only=True)

    class Meta:
        model = Answer
        fields = "__all__"
        depth = 1


class AnswerForQuestionSerializer(ModelSerializer):
    # Answer의 user모델을 직렬화 하기 위해 필요한 코드
    user = UserAnswerSerializer(read_only=True)

    class Meta:
        model = Answer
        fields = ("answer_id", "user", "text")
        depth = 1


class QuestionSerializer(ModelSerializer):
    answers = AnswerForQuestionSerializer(read_only=True, many=True)

    class Meta:
        model = Question
        fields = "__all__"  # 전체 필드 직렬화
