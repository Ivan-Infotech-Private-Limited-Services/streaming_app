from django.urls import path
from .views import RegisterUserView, VerifyEmailView, LoginUserView, TestAuthenticationView

urlpatterns=[
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('test-auth/', TestAuthenticationView.as_view(), name='granted'),
]