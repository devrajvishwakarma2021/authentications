from django.urls import path
from capp.views import UserLoginView, UserRegistrationView,UserProfileView,UserChangePasswordView,SendPasswordResetEmailView,UserPasswordResetView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('profile/', UserProfileView.as_view(), name = 'userprofile'),
    path('change/', UserChangePasswordView.as_view(), name = 'changepassword'),
    path('reset/', SendPasswordResetEmailView.as_view(), name = 'reset'),
    path('userrest/<uid>/<token>/',UserPasswordResetView.as_view(), name ='userrest'),
]
