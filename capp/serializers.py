from django.core.exceptions import ValidationError
from unittest.util import _MAX_LENGTH
from rest_framework import serializers
from capp.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from capp.utils  import util
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type' :'password'},
     write_only = True)
    class Meta:
        model = User
        fields = ['email','name', 'password', 'password2', 'tc']
        extra_kwargs={
            'password' :{'write_only' :True}
        }

# validation password
    def validate(self, data):
      password = data.get('password')
      password2 = data.get('password2')
      if password  != password2:
        raise serializers.ValidationError("password and confirm password does not match")
      # return super().validate(data)
      return data

    def create(self, validate_data):
      return User.objects.create_user(**validate_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
      model = User
      fields = ['email', 'password']

class UserprofileSerializer(serializers.ModelSerializer):
     class Meta:
        model = User 
        fields  = ['id', 'email', 'name']

class UserChangePasswordSerializer(serializers.Serializer):
  password =serializers.CharField(max_length=255, style=
   {'input_type' : 'password'}, write_only=True)
  password2 =serializers.CharField(max_length=255, style=
   {'input_type' : 'password'}, write_only=True)
  class Meta:
     fields = ['password', 'password2']


# change password
  def validate(self, data):
      password = data.get('password')
      password2 = data.get('password2')
      user = self.context.get('user')
      if password  != password2:
        raise serializers.ValidationError("password and confirm password does not match")
      user.set_password(password)
      user.save( )
      return data


# reset password send to email
class SendPasswordResetEmailSerializer (serializers.Serializer):
  email= serializers.EmailField(max_length=255)
  class Meta:
    fields =['email']

  def validate(self, data):
      email = data.get('email')
      if User.objects.filter(email=email).exists():
         user = User.objects.get(email=email)
         uid = urlsafe_base64_encode(force_bytes(user.id))
         print('Encoded uid', uid)
         token = PasswordResetTokenGenerator().make_token(user)
         print('password Reset token', token)
         link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
         print('password reset link', link)
         

         body = 'click following link to Reset your password' +link
         data ={
             'subject' : 'Reset your Password',
              'body' : body,
              'to_email' : user.email
         }

         util.send_email(data)
         return data
      else:
         raise ValidationError('you are not a Register User')


class UserPasswordResetSerializer(serializers.Serializer):
  password =serializers.CharField(max_length=255, style=
   {'input_type' : 'password'}, write_only=True)
  password2 =serializers.CharField(max_length=255, style=
   {'input_type' : 'password'}, write_only=True)
  class Meta:
     fields = ['password', 'password2']


# change password
  def validate(self, data):
    try:
      password = data.get('password')
      password2 = data.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('uid')
      if password  != password2:
        raise serializers.ValidationError("password and confirm password does not match")
      id  = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise ValidationError('Token is not valid or Expired')
      user.set_password(password)
      user.save( )
      return data

    except DjangoUnicodeDecodeError as identifier:
       PasswordResetTokenGenerator().check_token(user, token)
       raise ValidationError('Token is not valid or Expired')
       
