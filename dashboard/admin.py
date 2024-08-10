from django.contrib import admin
from .models import Product, Order

# Renaming Admin Site Header
admin.site.site_header = 'HFA Inventory Admin Site'

class ProductAdmin(admin.ModelAdmin):
    list_display = ('name', 'category', 'quantity', )
    list_filter = ('category',)

# Regitering Product Model (DB) on Admin Site
admin.site.register(Product, ProductAdmin)
admin.site.register(Order)
