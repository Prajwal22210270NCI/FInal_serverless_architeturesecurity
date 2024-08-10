from django.db import models
from django.contrib.auth.models import User

# DB of registered users
class Profile(models.Model):
    staff = models.OneToOneField(User, on_delete=models.CASCADE, null=True)
    address = models.CharField(max_length=500, null=True)
    phone = models.CharField(max_length=20, null=True)
    image = models.ImageField(default='default.jpg', upload_to='Profile_Images')

    def __str__(self):
        return f'{self.staff.username}--Profile'

