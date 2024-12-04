from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializers import GenreSerializer, MovieSerializer, PasswordResetRequestSerializer, UserRegisterSerializer, LoginSerializer, SetNewPasswordSerializer, LogoutUserSerializer, LoginAdminSerializer, WatchedlistSerializer, WatchlistSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from .utils import send_code_to_user
from .models import Genre, Movie, OneTimePassword, User, watchedlist, watchlist
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
# Create your views here.

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer
    
    def post(self, request):
        user_data=request.data
        serializer=UserRegisterSerializer(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user=serializer.data
            send_code_to_user(user['email'])
            return Response({
                'data': user,
                'message': 'User registered successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(GenericAPIView):
    def post(self, request):
        otpcode=request.data.get('otp')
        try:
            user_code_obj=OneTimePassword.objects.get(code=otpcode)
            user=user_code_obj.user
            if not user.is_verified:
                user.is_verified=True
                user.save()
                return Response({
                    'message': 'Email verified successfully'
                }, status=status.HTTP_200_OK)
            return Response({
                'message': 'code is invalid user already verified'
            }, status=status.HTTP_204_NO_CONTENT)
        except OneTimePassword.DoesNotExist as identifier:
            return Response({
                'message': 'passcode not provided'
            }, status=status.HTTP_404_NOT_FOUND)

class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class LoginAdminView(GenericAPIView):
   serializer_class = LoginAdminSerializer
    
   def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        data = {'msg':'its works'}
        return Response(data, status=status.HTTP_200_OK)

class PasswordResetRequestView(GenericAPIView):
    serializer_class=PasswordResetRequestSerializer
    
    def post(self, request):
        serializer=self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response({'message':"a link has been sent to your email to reset your password"}, status=status.HTTP_200_OK)

class PasswordResetConfirm(GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            user_id=smart_str(urlsafe_base64_decode(uidb64))
            user=User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'message':"token is invalid or has expired"}, status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True, 'message':'credentials is valid', 'uidb64':uidb64, 'token':token}, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message':"token is invalid or has expired"}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)

class LogoutUserView(GenericAPIView):
    serializer_class=LogoutUserSerializer
    permission_classes=[IsAuthenticated]
    def post(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

class LogoutAdminView(GenericAPIView):
    serializer_class=LogoutUserSerializer
    permission_classes=[IsAuthenticated]
    def post(self, request):
        if request.user.is_superuser:
            serializer=self.serializer_class(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)

class GenreView(GenericAPIView):
    serializer_class = GenreSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request):
        """ Retrieve all genres """
        genres = Genre.objects.all()
        serializer = GenreSerializer(genres, many=True)
        return Response({
            'data': serializer.data,
            'message': 'Genres retrieved successfully'
        }, status=status.HTTP_200_OK)

    def post(self, request):
        """ Create a new genre """
        genre_data = request.data
        serializer = GenreSerializer(data=genre_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({
                'data': serializer.data,
                'message': 'Genre created successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GenreDetailView(GenericAPIView):
    serializer_class = GenreSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, id):
        """Retrieve a genre by ID"""
        try:
            genre = Genre.objects.get(id=id)
            serializer = self.serializer_class(genre)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Genre.DoesNotExist:
            return Response({'message': 'Genre not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, id):
        """Update a genre by ID"""
        try:
            genre = Genre.objects.get(id=id)
            serializer = self.serializer_class(genre, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({
                    'data': serializer.data,
                    'message': 'Genre updated successfully'
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Genre.DoesNotExist:
            return Response({'message': 'Genre not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, id):
        """Delete a genre by ID"""
        try:
            genre = Genre.objects.get(id=id)
            genre.delete()
            return Response({'message': 'Genre deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Genre.DoesNotExist:
            return Response({'message': 'Genre not found'}, status=status.HTTP_404_NOT_FOUND)

class MovieListCreateView(GenericAPIView):
    serializer_class = MovieSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def post(self, request):
        """Create a new movie"""
        movie_data = request.data
        serializer = self.serializer_class(data=movie_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({
                'data': serializer.data,
                'message': 'Movie created successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        """Retrieve all movies"""
        movies = Movie.objects.all()
        serializer = self.serializer_class(movies, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class MovieDetailView(GenericAPIView):
    serializer_class = MovieSerializer
    permission_classes = [IsAuthenticated, IsAdminUser]

    def get(self, request, pk):
        """Retrieve a single movie by ID"""
        try:
            movie = Movie.objects.get(pk=pk)
            serializer = self.serializer_class(movie)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Movie.DoesNotExist:
            return Response({'message': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)

    def put(self, request, pk):
        """Update a movie by ID"""
        try:
            movie = Movie.objects.get(pk=pk)
            serializer = self.serializer_class(movie, data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({
                    'data': serializer.data,
                    'message': 'Movie updated successfully'
                }, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Movie.DoesNotExist:
            return Response({'message': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)

    def delete(self, request, pk):
        """Delete a movie by ID"""
        try:
            movie = Movie.objects.get(pk=pk)
            movie.delete()
            return Response({'message': 'Movie deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Movie.DoesNotExist:
            return Response({'message': 'Movie not found'}, status=status.HTTP_404_NOT_FOUND)

class WatchlistView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WatchlistSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return Response({'message': 'Movie added to watchlist'}, status=status.HTTP_201_CREATED)
    
    def get(self, request):
        watchlist = watchlist.objects.filter(user=request.user)
        serializer = WatchlistSerializer(watchlist, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class WatchlistDetailView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WatchlistSerializer

    def delete(self, request, pk):
        try:
            watchlist_item = watchlist.objects.get(user=request.user, movie_id=pk)
            watchlist_item.delete()
            return Response({'message': 'Movie removed from watchlist'}, status=status.HTTP_204_NO_CONTENT)
        except watchlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchlist'}, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request, pk):
        try:
            watchlist_item = watchlist.objects.get(user=request.user, movie_id=pk)
            serializer = WatchlistSerializer(watchlist_item, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'message': 'Watchlist updated successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except watchlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchlist'}, status=status.HTTP_404_NOT_FOUND)
    
    def get(self, request, pk):
        try:
            watchlist_item = watchlist.objects.get(user=request.user, movie_id=pk)
            serializer = WatchlistSerializer(watchlist_item)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except watchlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchlist'}, status=status.HTTP_404_NOT_FOUND)

class WatchedlistView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WatchedlistSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(user=request.user)
        return Response({'message': 'Movie added to watchedlist'}, status=status.HTTP_201_CREATED)
    
    def get(self, request):
        watchedlist = watchedlist.objects.filter(user=request.user)
        serializer = WatchedlistSerializer(watchedlist, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class WatchedlistDetailView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = WatchedlistSerializer

    def delete(self, request, pk):
        try:
            watchedlist_item = watchedlist.objects.get(user=request.user, movie_id=pk)
            watchedlist_item.delete()
            return Response({'message': 'Movie removed from watchedlist'}, status=status.HTTP_204_NO_CONTENT)
        except watchedlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchedlist'}, status=status.HTTP_404_NOT_FOUND)
    
    def put(self, request, pk):
        try:
            watchedlist_item = watchedlist.objects.get(user=request.user, movie_id=pk)
            serializer = WatchedlistSerializer(watchedlist_item, data=request.data, partial=True)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response({'message': 'Watchedlist updated successfully'}, status=status.HTTP_200_OK)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except watchedlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchedlist'}, status=status.HTTP_404_NOT_FOUND)
    
    def get(self, request, pk):
        try:
            watchedlist_item = watchedlist.objects.get(user=request.user, movie_id=pk)
            serializer = WatchedlistSerializer(watchedlist_item)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except watchedlist.DoesNotExist:
            return Response({'message': 'Movie not found in watchedlist'}, status=status.HTTP_404_NOT_FOUND)