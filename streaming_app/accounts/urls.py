from django.urls import path
from .views import RegisterUserView, VerifyEmailView, LoginUserView, TestAuthenticationView, PasswordResetConfirm, PasswordResetRequestView, SetNewPassword, LogoutUserView, LoginAdminView

urlpatterns=[
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('profile/', TestAuthenticationView.as_view(), name='granted'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(), name='password-reset-confirm'),
    path('set-new-password/', SetNewPassword.as_view(), name='set-new-password'),
    path('logout/', LogoutUserView.as_view(), name='logout'),
    path('login-admin/', LoginAdminView.as_view(), name='login-admin')
]