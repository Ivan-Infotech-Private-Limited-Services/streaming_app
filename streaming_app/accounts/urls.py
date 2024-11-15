from django.urls import path
from .views import RegisterUserView, VerifyEmailView

urlpatterns=[
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify'),
]