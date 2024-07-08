from django.shortcuts import render, redirect, HttpResponse
from django.views import View
from django.contrib.auth import authenticate, login, logout
from django.urls import reverse_lazy
from .forms import EmailForm, LoginForm, RegisterForm, OTPForm, EmployeeForm, JobseekerForm
from django.views.generic import FormView, TemplateView, ListView, CreateView, UpdateView
from .models import User, EmailOTP, Relationship
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.contrib import messages
from .utils import send_otp_via_email


def index(request):
    return render(request,'learntest/index.html')


        