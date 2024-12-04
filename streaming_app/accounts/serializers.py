from rest_framework import serializers
from .models import Genre, Movie, User, watchedlist, watchlist
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import smart_str, smart_bytes, force_str
from django.urls import reverse
from .utils import send_normal_email
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']

    def validate(self, attrs):
        password = attrs.get('password', '')
        password2 = attrs.get('password2', '')
        if password!= password2:
            raise serializers.ValidationError('Passwords do not match')
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            password=validated_data.get('password')
        )
        return user

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6)
    password=serializers.CharField(max_length=68, write_only=True)
    full_name=serializers.CharField(max_length=255, read_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']

    

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        tokens=user.tokens()
        return {
            'email':user.email,
            'full_name':user.get_full_name,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
        }

class LoginAdminSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6)
    password=serializers.CharField(max_length=68, write_only=True)
    full_name=serializers.CharField(max_length=255, read_only=True)
    access_token=serializers.CharField(max_length=255, read_only=True)
    refresh_token=serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'access_token', 'refresh_token']

    

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request=self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        if not user.is_superuser:
            raise AuthenticationFailed("You are not an admin. Use user login.")
        tokens=user.tokens()
        return {
            'email':user.email,
            'full_name':user.get_full_name,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
        }

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate_email(self, email):
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return email

    def validate(self, attrs):
        email = attrs['email']
        user = User.objects.get(email=email)
        
        uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
        token = PasswordResetTokenGenerator().make_token(user)
        request = self.context.get('request')
        site_domain = get_current_site(request).domain
        relative_link = reverse('password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
        abslink = f"http://{site_domain}{relative_link}"
        
        email_body = f"Hi, use the link below to reset your password:\n{abslink}"
        data = {
            'email_body': email_body,
            'to_email': user.email,
            'email_subject': 'Reset Your Password',
        }
        send_normal_email(data)

        return attrs

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uidb64', 'token']

    def validate(self, attrs):
        try:
            uidb64 = attrs.get('uidb64')
            token = attrs.get('token')
            password = attrs.get('password')
            confirm_password = attrs.get('confirm_password')

            if password != confirm_password:
                raise serializers.ValidationError("Passwords do not match.")

            user_id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("The reset link is invalid or has expired.")
            
            attrs['user'] = user  # Add user to validated data for further processing in the `save` method.

            return attrs
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid user.")
        except Exception as e:
            raise serializers.ValidationError("The reset link is invalid or has expired.")

    def save(self):
        password = self.validated_data['password']
        user = self.validated_data['user']
        user.set_password(password)
        user.save()

class LogoutUserSerializer(serializers.Serializer):
    refresh_token=serializers.CharField()
    default_error_messages = {
        'bad_token': ('Token is invalid or expired')
    }
    def validate(self, attrs):
        self.token=attrs.get('refresh_token')
        return attrs
    def save(self, **kwargs):
        try:
            refresh_token=self.token
            token=RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')

class GenreSerializer(serializers.ModelSerializer):
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=1000, allow_blank=True)

    class Meta:
        model = Genre
        fields = ['id', 'name', 'description']

    def validate_name(self, value):
        if self.instance and self.instance.name == value:
            return value
        if Genre.objects.filter(name=value).exists():
            raise serializers.ValidationError("A genre with this name already exists.")
        return value

    def create(self, validated_data):
        genre = Genre.objects.create(
            name=validated_data['name'],
            description=validated_data.get('description', '')
        )
        return genre

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.description = validated_data.get('description', instance.description)
        instance.save()
        return instance

    def delete(self, instance):
        instance.delete()

class MovieSerializer(serializers.ModelSerializer):
    title = serializers.CharField(max_length=255)
    description = serializers.CharField(max_length=1000, allow_blank=True)
    genre = serializers.PrimaryKeyRelatedField(queryset=Genre.objects.all())
    release_date = serializers.DateField()
    rating = serializers.FloatField(min_value=0.0, max_value=10.0)

    class Meta:
        model = Movie
        fields = ['id', 'title', 'description', 'genre', 'release_date', 'rating']

    def validate(self, attrs):
        title = attrs.get('title', '').strip()
        release_date = attrs.get('release_date', None)

        if Movie.objects.filter(title=title, release_date=release_date).exists():
            raise serializers.ValidationError("A movie with this title and release date already exists.")
        
        return attrs

    def create(self, validated_data):
        """ Handle creation of a new movie """
        movie = Movie.objects.create(
            title=validated_data['title'],
            description=validated_data.get('description', ''),
            genre=validated_data['genre'],
            release_date=validated_data['release_date'],
            rating=validated_data['rating']
        )
        return movie

    def update(self, instance, validated_data):
        """ Handle updates to an existing movie instance """
        instance.title = validated_data.get('title', instance.title)
        instance.description = validated_data.get('description', instance.description)
        instance.genre = validated_data.get('genre', instance.genre)
        instance.release_date = validated_data.get('release_date', instance.release_date)
        instance.rating = validated_data.get('rating', instance.rating)
        instance.save()
        return instance

    def delete(self, instance):
        """ Handle deletion of a movie instance """
        instance.delete()

class WatchlistSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    movie = serializers.PrimaryKeyRelatedField(queryset=Movie.objects.all())

    class Meta:
        model = watchlist
        fields = ['id', 'user', 'movie']
        read_only_fields = ['id']
        extra_kwargs = {
            'user': {'required': True},
            'movie': {'required': True}
        }
    
    def create(self, validated_data):
        watchlist = watchlist.objects.create(**validated_data)
        return watchlist
    
    def update(self, instance, validated_data):
        instance.user = validated_data.get('user', instance.user)
        instance.movie = validated_data.get('movie', instance.movie)
        instance.save()
        return instance
    
    def delete(self, instance):
        instance.delete()

class WatchedlistSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())
    movie = serializers.PrimaryKeyRelatedField(queryset=Movie.objects.all())
    class Meta:
        model = watchedlist
        fields = ['id', 'user', 'movie']
        read_only_fields = ['id']
        extra_kwargs = {
            'user': {'required': True},
            'movie': {'required': True}
        }
    
    def create(self, validated_data):
        watchedlist = watchedlist.objects.create(**validated_data)
        return watchedlist
    
    def update(self, instance, validated_data):
        instance.user = validated_data.get('user', instance.user)
        instance.movie = validated_data.get('movie', instance.movie)
        instance.save()
        return instance
    
    def delete(self, instance):
        instance.delete()