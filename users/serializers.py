from rest_framework import serializers
from users.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from users.utils import Util

class SocialRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(required=True)
    full_name = serializers.CharField(required=False, allow_blank=True)
    origin = serializers.CharField(required=False, allow_blank=True)
    uid = serializers.CharField(required=False, allow_blank=True)
    image = serializers.URLField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['email', 'full_name', 'origin', 'uid', 'image']

    def create(self, validated_data):
        """
        Create a new user or update the existing user based on email.
        """
        email = validated_data.get('email')
        full_name = validated_data.get('full_name', '')
        origin = validated_data.get('origin', '')
        uid = validated_data.get('uid', '')
        image = validated_data.get('image', '')

        # Check if the user already exists
        user, created = User.objects.get_or_create(email=email, defaults={
            'full_name': full_name,
            'origin': origin,
            'uid': uid,
            'image': image,
        })

        # If user already exists, update the fields
        if not created:
            user.full_name = full_name
            user.origin = origin
            user.uid = uid
            user.image = image
            user.save()

        return user

  
class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username','email','user_type', 'image','device_token','longitude','latitude','Trade_radius','address']
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'user_type', 'image', 'device_token', 'full_name', 'address','longitude','latitude','contact' ]
        extra_kwargs = {
            'user_type': {'default': 'client'},  # Set default value for user_type if not provided
            'image': {'required': False},  # Allow image to be optional
            'device_token': {'required': False},
            'full_name': {'required': False},  # Allow first_name to be optional
              # Allow last_name to be optional
            'address': {'required': False},
            'longitude': {'required': False},  # Allow last_name to be optional
            'latitude': {'required': False},
             'contact' : {'required': False},
           







            # Allow device_token to be optional
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User.objects.create_user(password=password, **validated_data)
        return user
class UserLoginSerializer(serializers.ModelSerializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    model = User
    fields = ['email', 'password']

# class UserProfileSerializer(serializers.ModelSerializer):
#   class Meta:
#     model = User
#     fields = ['id', 'email', 'name','image']
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'user_type', 'is_active', 'is_admin', 'created_at', 'updated_at', 'image','is_registered','is_deleted','full_name', 'address','longitude','latitude')
class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    new_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    def validate(self, attrs):
        user = self.context.get('user')
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')

        if not user.check_password(old_password):
            raise serializers.ValidationError("Incorrect old password")

        if old_password == new_password:
            raise serializers.ValidationError("New password must be different from old password")

        return attrs

    def save(self):
        user = self.context.get('user')
        new_password = self.validated_data.get('new_password')
        user.set_password(new_password)
        user.save()

class UserChangeP4asswordSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    password = attrs.get('password')
    password2 = attrs.get('password2')
    user = self.context.get('user')
    if password != password2:
      raise serializers.ValidationError("Password and Confirm Password doesn't match")
    user.set_password(password)
    user.save()
    return attrs

class SendPasswordResetEmailSerializer(serializers.Serializer):
  email = serializers.EmailField(max_length=255)
  class Meta:
    fields = ['email']

  def validate(self, attrs):
    email = attrs.get('email')
    if User.objects.filter(email=email).exists():
      user = User.objects.get(email = email)
      uid = urlsafe_base64_encode(force_bytes(user.id))
      print('Encoded UID', uid)
      token = PasswordResetTokenGenerator().make_token(user)
      print('Password Reset Token', token)
      link = 'http://localhost:3000/api/user/reset/'+uid+'/'+token
      print('Password Reset Link', link)
      # Send EMail
      body = 'Click Following Link to Reset Your Password '+link
      data = {
        'subject':'Reset Your Password',
        'body':body,
        'to_email':user.email
      }
      # Util.send_email(data)
      return attrs
    else:
      raise serializers.ValidationError('You are not a Registered User')
from rest_framework import serializers

class PasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, max_length=128)
    confirm_password = serializers.CharField(min_length=8, max_length=128)

    def validate(self, data):
        password = data.get('password')
        confirm_password = data.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match")

        return data

class UserPasswordResetSerializer(serializers.Serializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
  class Meta:
    fields = ['password', 'password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')
      token = self.context.get('token')
      if password != password2:
        raise serializers.ValidationError("Password and Confirm Password doesn't match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise serializers.ValidationError('Token is not Valid or Expired')
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user, token)
      raise serializers.ValidationError('Token is not Valid or Expired')
class DriverSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'contact', 'image']