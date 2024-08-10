"""
URL configuration for inventory_main project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from user import views as user_view
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    
    #Route to urls from dashboard.urls.py file
    path('', include('dashboard.urls')),

    #Route to urls from users.urls.py file- User Registration Page
    path('register/', user_view.register, name='user-register'),

    #Route to urls from users.urls.py file- Login Page at start of application
    path('', auth_views.LoginView.as_view(template_name='user/login.html'), name='user-login'),

    #Route to urls from users.urls.py file- Logout Page
    path('logout/', auth_views.LogoutView.as_view(template_name='user/logout.html'), name='user-logout'),

    #Route to urls from users.urls.py file- Profile page
    path('profile/', user_view.profile, name='user-profile'),

    #Route to urls from users.urls.py file- Profile-Update page
    path('profile/update/', user_view.profile_update, name='user-profile-update'),

] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
