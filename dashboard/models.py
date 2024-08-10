from django.db import models
from django.contrib.auth.models import User
#from .order_sns import send_order_email  # Old implementation before creating my library
#from django_aws_integrate.order_sns import send_order_email #Calling SNS service from my own library

# Drop down list for Categories section of App
CATEGORY = (
    ('Cement', 'Cement'),
    ('Bricks', 'Bricks'),
    ('Tools', 'Tools'),
    ('Paint', 'Paint'),
    ('Sand', 'Sand')
)

# Product Table of DB
class Product(models.Model):
    name = models.CharField(max_length=200, null=True)
    category = models.CharField(max_length=50, choices=CATEGORY, null=True)
    quantity = models.PositiveIntegerField(null=True)

    # To view Product name and quantity on Product Model Admin page
    def __str__(self):
        return f'{self.name} - {self.quantity}'
    
# Orders Table of DB
class Order(models.Model):
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)
    staff = models.ForeignKey(User, models.CASCADE, null=True)
    order_quantity = models.PositiveIntegerField(null=True)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.product} ordered by {self.staff.username}'
    
    def send_confirmation_email(self):
        print(self.email)
        send_order_email(self.email)
