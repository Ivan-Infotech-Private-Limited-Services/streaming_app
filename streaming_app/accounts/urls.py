from django.urls import path
from .views import (
    GenreDetailView,
    GenreView,
    MovieDetailView,
    MovieListCreateView, 
    RegisterUserView, 
    VerifyEmailView, 
    LoginUserView, 
    TestAuthenticationView, 
    PasswordResetConfirm, 
    PasswordResetRequestView, 
    SetNewPassword, 
    LogoutUserView, 
    LoginAdminView, 
    LogoutAdminView
)

urlpatterns=[
    path('register/', RegisterUserView.as_view(), name='register'),
    path('verify-email/', VerifyEmailView.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('profile/', TestAuthenticationView.as_view(), name='granted'),
    path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/', PasswordResetConfirm.as_view(), name='password-reset-confirm'),
    path('set-new-password/', SetNewPassword.as_view(), name='set-new-password'),
    path('logout/', LogoutUserView.as_view(), name='logout'),
    path('login-admin/', LoginAdminView.as_view(), name='login-admin'),
    path('logout-admin/', LogoutAdminView.as_view(), name='logout-admin'),
    path('genre/', GenreView.as_view(), name='genre-list-create'),
    path('genre/<int:id>/', GenreDetailView.as_view(), name='genre-detail'),
    path('movies/', MovieListCreateView.as_view(), name='movie-list-create'),
    path('movies/<int:pk>/', MovieDetailView.as_view(), name='movie-detail'),
]