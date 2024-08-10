from django.urls import path
from . import views

urlpatterns = [
    #Index Page Url
    path('dashboard/', views.index, name='dashboard-index'),

    #Staff Page Url
    path('staff/', views.staff, name='dashboard-staff'),

    #Product Page Url
    path('product/', views.product, name='dashboard-product'),

    #Orders Page Url
    path('order/', views.order, name='dashboard-order'),

    #Delete Products Page Url
    path('product/delete/<int:pk>', views.product_delete, name='dashboard-product-delete'),

    #Update Products Page Url
    path('product/update/<int:pk>', views.product_update, name='dashboard-product-update'),

    #Staff Details Page Url
    path('staff/details/<int:pk>', views.staff_detail, name='dashboard-staff-detail'),

]