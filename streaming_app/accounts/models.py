from datetime import datetime
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.forms import ValidationError
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
# Create your models here.

class UserManager(BaseUserManager):

    use_in_migration = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is Required')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff = True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser = True')

        return self.create_user(email, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=255, unique=True, verbose_name=_("Email Address"))
    first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']
    
    objects = UserManager()
    
    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

class OneTimePassword(models.Model):
    user=models.OneToOneField(User, on_delete=models.CASCADE)
    code=models.CharField(max_length=6, unique=True)

    def __str__(self):
        return f"{self.user.first_name}-passcode"

class Genre(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class Movie(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField()
    genres = models.ManyToManyField(Genre, related_name="movies")
    release_date = models.DateField()
    director = models.CharField(max_length=255, null=True)
    cast = models.TextField(blank=True, null=True)
    rating = models.DecimalField(max_digits=3, decimal_places=1, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title
    def clean(self):
        if self.rating and (self.rating < 0 or self.rating > 10):
            raise ValidationError(_("Rating must be between 0 and 10"))
        if self.release_date and self.release_date > datetime.date.today():
            raise ValidationError(_("Release date cannot be in the future"))
        return super().clean()
    @property
    def average_rating(self):
        if self.rating:
            return sum([float(r) for r in self.rating.split(',')]) / len(self.rating.split(','))
        return 0.0
    @property
    def is_released(self):
        return self.release_date <= datetime.date.today()
    @property
    def duration(self):
        if self.release_date:
            return (datetime.date.today() - self.release_date).days
        return 0
    @property
    def actors(self):
        return [cast.strip() for cast in self.cast.split(',') if cast.strip()]
    @property
    def genres_list(self):
        return [genre.name for genre in self.genres.all()]
    @property
    def director_and_cast(self):
        return f"{self.director} ({', '.join(self.actors)})"
    @property
    def formatted_release_date(self):
        return self.release_date.strftime("%B %d, %Y")
    @property
    def formatted_rating(self):
        if self.rating:
            return f"{self.rating:.1f}/10"
        return "N/A"
    @property
    def formatted_duration(self):
        if self.release_date:
            return f"{self.duration} days"
        return "N/A"
    @property
    def formatted_cast(self):
        if self.cast:
            return ", ".join(self.actors)
        return "N/A"
    @property
    def formatted_genres(self):
        if self.genres.all():
            return ", ".join(self.genres_list)
        return "N/A"
    @property
    def formatted_director_and_cast(self):
        if self.director and self.cast:
            return f"{self.director} ({self.formatted_cast})"
        return "N/A"
    @property
    def formatted_average_rating(self):
        if self.rating:
            return f"{self.average_rating:.1f}/10"
        return "N/A"
    @property
    def formatted_is_released(self):
        if self.is_released:
            return "Yes"
        return "No"
    @property
    def formatted_created_at(self):
        return self.created_at.strftime("%B %d, %Y %I:%M:%S %p")
    @property
    def formatted_updated_at(self):
        return self.updated_at.strftime("%B %d, %Y %I:%M:%S %p")

class StreamingLink(models.Model):
    movie = models.ForeignKey(Movie, related_name='streaming_links', on_delete=models.CASCADE)
    url = models.URLField()
    quality = models.CharField(max_length=50, choices=[('HD', 'HD'), ('SD', 'SD')])
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        unique_together = ('movie', 'quality')
    def __str__(self):
        return f"{self.movie.title} - {self.quality} - {self.url}"
    @property
    def formatted_created_at(self):
        return self.created_at.strftime("%B %d, %Y %I:%M:%S %p")
    @property
    def formatted_updated_at(self):
        return self.updated_at.strftime("%B %d, %Y %I:%M:%S %p")
    @property
    def formatted_url(self):
        return self.url.replace("https://", "").replace("http://", "")
    @property
    def formatted_quality(self):
        return self.quality
    @property
    def formatted_movie_title(self):
        return self.movie.title
    @property
    def formatted_movie_director_and_cast(self):
        return self.movie.director_and_cast
    @property
    def formatted_movie_release_date(self):
        return self.movie.formatted_release_date
    @property
    def formatted_movie_duration(self):
        return self.movie.formatted_duration
    @property
    def formatted_movie_cast(self):
        return self.movie.formatted_cast
    @property
    def formatted_movie_genres(self):
        return self.movie.formatted_genres
    @property
    def formatted_movie_director_and_cast(self):
        return self.movie.formatted_director_and_cast
    @property
    def formatted_movie_average_rating(self):
        return self.movie.formatted_average_rating
    @property
    def formatted_movie_is_released(self):
        return self.movie.formatted_is_released
    @property
    def formatted_movie_created_at(self):
        return self.movie.formatted_created_at
    @property
    def formatted_movie_updated_at(self):
        return self.movie.formatted_updated_at
    @property
    def formatted_streaming_link_url(self):
        return self.url.replace("https://", "").replace("http://", "")
    @property
    def formatted_streaming_link_quality(self):
        return self.quality
    @property
    def formatted_streaming_link_movie_title(self):
        return self.movie.title
    @property
    def formatted_streaming_link_movie_director_and_cast(self):
        return self.movie.director_and_cast
    @property
    def formatted_streaming_link_movie_release_date(self):
        return self.movie.formatted_release_date
    @property
    def formatted_streaming_link_movie_duration(self):
        return self.movie.formatted_duration