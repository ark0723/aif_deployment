from .models import Question, Answer, User
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from app.authentication import JWTAuthentication
from users.permissions import IsSuperUserOrAdmin
from .serializers import QuestionSerializer, AnswerSerializer
import json


class Questions(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 전체 질문 리스트
    def get(self, request):
        questions = Question.objects.all()
        serializer = QuestionSerializer(questions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # 질문 생성
    def post(self, request):
        # jsont -> object
        serializer = QuestionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# /surveys/<int:question_id>
class QuestionDetail(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 특정 질문 불러오기
    def get_question(self, question_id):
        try:
            return Question.objects.get(question_id=question_id)
        except Question.DoesNotExist:
            raise NotFound

    # 특정 질문과 질문에 대한 답변들 불러오기
    def get(self, request, question_id):
        question = self.get_question(question_id=question_id)
        # serializer : object -> json
        serializer = QuestionSerializer(question)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, question_id):
        question = self.get_question(question_id=question_id)
        serializer = AnswerSerializer(data=request.data)

        if serializer.is_valid():
            answer = serializer.save(user=request.user, question=question)
            # Serialize the created Answer and return as response
            serializer = AnswerSerializer(answer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# /surveys/answers
class Answers(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 모든 답변 불러오기
    def get(self, request):
        answers = Answer.objects.all()
        serializer = AnswerSerializer(answers, many=True)

        return Response(serializer.data)


# /surveys/answer-by-user/<int:member_id>
class AnswersByUser(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    # 특정 유저가 대답한 모든 질문 불러오기
    def get_answers_by_user(self, member_id):
        try:
            user = User.objects.get(member_id=member_id)

        except User.DoesNotExist:
            raise NotFound

        return Answer.objects.filter(user=User.objects.get(member_id=member_id))

    # /surveys/answer-by-user/<int:member_id>
    def get(self, request, member_id):
        answers = self.get_answers_by_user(member_id)
        serializer = AnswerSerializer(answers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


# /surveys/answer-by-question/<int:question_id>
class AnswersByQuestion(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated, IsSuperUserOrAdmin]

    def get_answers_by_question(self, question_id):
        try:
            question = Question.objects.get(question_id=question_id)

        except question.DoesNotExist:
            raise NotFound

        return Answer.objects.filter(
            question=Question.objects.get(question_id=question_id)
        )

    # /surveys/answer-by-question/<int:question_id>
    def get(self, request, question_id):
        # 특정 질문에 대한 answers 모두 불러오기
        answers = self.get_answers_by_question(question_id)
        serializer = AnswerSerializer(answers, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    # /surveys/answer-by-question/<int:question_id>
    def post(self, request, question_id):

        question = Question.objects.get(question_id=question_id)
        serializer = AnswerSerializer(data=request.data)

        if serializer.is_valid():
            answer = serializer.save(user=request.user, question=question)
            # Serialize the created Answer and return as response
            serializer = AnswerSerializer(answer)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# /surveys/submit : 일반유저가 서베이 폼 제출
@api_view(["POST"])
def survey_answers(request):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    if request.method == "POST":

        data = json.loads(request.body)

        age = data.get("1")
        price = data.get("2")
        satisfied = data.get("3")
        to_improve = data.get("4")
        willing_to_use = data.get("5")
        why = data.get("6")

        # load user data
        user = request.user
        print(user)

        q1 = Question.objects.get(question_id=1)
        answer1 = Answer(question=q1, user=user, text=age)
        answer1.save()

        q2 = Question.objects.get(question_id=2)
        answer2 = Answer(question=q2, user=user, text=price)
        answer2.save()

        q3 = Question.objects.get(question_id=3)
        answer3 = Answer(question=q3, user=user, text=satisfied)
        answer3.save()

        q4 = Question.objects.get(question_id=4)
        answer4 = Answer(question=q4, user=user, text=to_improve)
        answer4.save()

        q5 = Question.objects.get(question_id=5)
        answer5 = Answer(question=q5, user=user, text=willing_to_use)
        answer5.save()

        q6 = Question.objects.get(question_id=6)
        answer6 = Answer(question=q6, user=user, text=why)
        answer6.save()

        return Response({"message": "Survey submitted successfully!"})

    return Response(status=405)  # Method Not Allowed
