import json
import logging


#from IPython.utils import data
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from .models import Product, Order
from .forms import ProductForm, OrderForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core.validators import validate_email, URLValidator, RegexValidator
import re
import pandas as pd
import joblib
import boto3
from sklearn.ensemble import IsolationForest

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Load the trained model
model = joblib.load('ml_model/isolation_forest_model.pkl')


# Validate input function
def validate_input(data):
    if not isinstance(data, str):
        raise ValidationError("Invalid input: input must be a string")

    # Anomaly detection
    data_list = [float(ord(char)) for char in data]
    anomaly = model.predict([data_list])

    if anomaly == -1:
        logger.warning(f"Anomaly detected: {data}")
        cloudwatch.put_log_events(
            logGroupName='/aws/lambda/inventory-manag-dev',

            logEvents=[
                {
                    'timestamp': int(time.time() * 1000),
                    'message': f"Anomaly detected: {data}"
                },
            ]
        )
        raise ValidationError("Anomalous input detected")


    # Check for SQL Injection patterns
    sql_injection_patterns = [
        re.compile(r'(--|\b(select|union|insert|update|delete|drop|alter)\b)', re.IGNORECASE),
        re.compile(r'(\bexec\b|\bexecute\b)', re.IGNORECASE)
    ]
    for pattern in sql_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible SQL injection detected")

    # Check for XSS patterns
    xss_patterns = [
        re.compile(r'<script.*?>.*?</script>', re.IGNORECASE),
        re.compile(r'javascript:', re.IGNORECASE)
    ]
    for pattern in xss_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible XSS detected")

    # Check for command injection patterns
    command_injection_patterns = [
        re.compile(r'(\||;|&|`|\$|\(|\)|<|>|\[|\]|\{|\}|\*|\?|!|~)', re.IGNORECASE),
        re.compile(r'(\bsh\b|\bbash\b|\bperl\b|\bpython\b|\bphp\b)', re.IGNORECASE)
    ]
    for pattern in command_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible command injection detected")

    # Check for LDAP injection patterns
    ldap_injection_patterns = [
        re.compile(r'(\(|\)|&|\||=)', re.IGNORECASE)
    ]
    for pattern in ldap_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible LDAP injection detected")

    # Check for XML injection patterns
    xml_injection_patterns = [
        re.compile(r'(<\?xml|<!DOCTYPE|<!ENTITY)', re.IGNORECASE)
    ]
    for pattern in xml_injection_patterns:
        if pattern.search(data):
            raise ValidationError("Invalid input: possible XML injection detected")

    return data

# Index Page
@login_required(login_url='user-login')
def index(request):
    orders = Order.objects.all()
    products = Product.objects.all()
    orders_count = orders.count()
    products_count = products.count()
    workers_count = User.objects.all().count()

    if request.method == 'POST':
        form = OrderForm(request.POST)
        if form.is_valid():
            try:
                instance = form.save(commit=False)
                instance.staff = request.user
                instance.save()
                messages.success(request, 'Order has been placed successfully! Email has been sent to Admin.')
                logger.info(f"Order placed by {request.user}")
            except Exception as e:
                messages.error(request, f'Error placing order: {e}')
                logger.error(f"Error placing order: {e}")
            return redirect('dashboard-index')
    else:
        form = OrderForm()

    context = {
        'orders': orders,
        'form': form,
        'products': products,
        'orders_count': orders_count,
        'workers_count': workers_count,
        'products_count': products_count,
    }
    return render(request, 'dashboard/index.html', context)

# Staff Details Page
@login_required(login_url='user-login')
def staff(request):
    workers = User.objects.all()
    workers_count = workers.count()
    orders_count = Order.objects.all().count()
    products_count = Product.objects.all().count()

    context = {
        'workers': workers,
        'workers_count': workers_count,
        'orders_count': orders_count,
        'products_count': products_count,
    }
    return render(request, 'dashboard/staff.html', context)

# Product Details Page
@login_required(login_url='user-login')
def product(request):
    items = Product.objects.all()
    products_count = items.count()
    workers_count = User.objects.all().count()
    orders_count = Order.objects.all().count()

    if request.method == 'POST':
        form = ProductForm(request.POST)
        if form.is_valid():
            try:
                product_name = validate_input(form.cleaned_data.get('name'))
                form.save()
                messages.success(request, f'{product_name} has been added successfully!')
                logger.info(f"Product added: {product_name}")
            except ValidationError as e:
                messages.error(request, f'Invalid input: {e}')
                logger.error(f"Invalid input for product name: {e}")
            except Exception as e:
                messages.error(request, f'Error adding product: {e}')
                logger.error(f"Error adding product: {e}")
            return redirect('dashboard-product')
    else:
        form = ProductForm()

    context = {
        'items': items,
        'form': form,
        'workers_count': workers_count,
        'orders_count': orders_count,
        'products_count': products_count,
    }
    return render(request, 'dashboard/product.html', context)

# Deleting Product Page
@login_required(login_url='user-login')
def product_delete(request, pk):
    item = get_object_or_404(Product, id=pk)
    if request.method == 'POST':
        try:
            item.delete()
            messages.warning(request, 'Product has been deleted successfully!')
            logger.info(f"Product deleted: {pk}")
        except Exception as e:
            messages.error(request, f'Error deleting product: {e}')
            logger.error(f"Error deleting product {pk}: {e}")
        return redirect('dashboard-product')
    return render(request, 'dashboard/product_delete.html')

# Editing Product Page
@login_required(login_url='user-login')
def product_update(request, pk):
    item = get_object_or_404(Product, id=pk)
    if request.method == 'POST':
        form = ProductForm(request.POST, instance=item)
        if form.is_valid():
            try:
                form.save()
                messages.success(request, 'Product has been updated successfully!')
                logger.info(f"Product updated: {pk}")
            except Exception as e:
                messages.error(request, f'Error updating product: {e}')
                logger.error(f"Error updating product {pk}: {e}")
            return redirect('dashboard-product')
    else:
        form = ProductForm(instance=item)
    context = {
        'form': form,
    }
    return render(request, 'dashboard/product_update.html', context)

# Order Details Page
@login_required(login_url='user-login')
def order(request):
    orders = Order.objects.all()
    orders_count = Order.objects.count()
    workers_count = User.objects.all().count()
    products_count = Product.objects.all().count()

    context = {
        'orders': orders,
        'workers_count': workers_count,
        'orders_count': orders_count,
        'products_count': products_count,
    }
    return render(request, 'dashboard/order.html', context)

# Staff Details Page
@login_required(login_url='user-login')
def staff_detail(request, pk):
    worker = get_object_or_404(User, id=pk)
    workers = User.objects.all()
    workers_count = workers.count()
    orders_count = Order.objects.all().count()
    products_count = Product.objects.all().count()

    context = {
        'worker': worker,
        'workers': workers,
        'workers_count': workers_count,
        'orders_count': orders_count,
        'products_count': products_count,
    }
    return render(request, 'dashboard/staff_detail.html', context)
