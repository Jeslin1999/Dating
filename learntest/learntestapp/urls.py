from django.urls import path
from .views import *
from django.conf import settings
from django.conf.urls.static import static

app_name = 'learntestapp'

urlpatterns = [
    path('',index, name='index'),
    path('send_otp/', send_otp, name='send_otp'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    path('logina/', RegisterLogin.as_view(), name='logina'),
    path('register/',RegisterView.as_view(), name='register'),
    path('employeeinfo/',EmployeeinfoView.as_view(), name='employeeinfo'),
    path('relationship/',RelationshipView.as_view(), name='relationship'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('login/', LoginView.as_view(), name='login'),
]
