from django.contrib import admin
from django.urls import path
from .views import UrlValidateippath, UrlValidatedomainpath, UrlValidatePost, UrlValidateParams


urlpatterns = [
    path('ip/<str:url_string>/', UrlValidateippath.as_view()),
    path('domain/<str:url_string>/', UrlValidatedomainpath.as_view()),
    path('validate/', UrlValidatePost.as_view()),
    path('params/', UrlValidateParams.as_view())

]
