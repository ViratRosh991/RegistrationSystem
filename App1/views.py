from django.shortcuts import render
from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import redirect,render
from django.contrib.auth import authenticate
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout

from RegistrationSystem import settings
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text
from tokens import generate_token
from django.core.mail import EmailMessage,send_mail

from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode

# Create your views here.
def index(request):
    return render(request,'Authentication/index.html')

def signup(request):

    if request.method == "POST":
        #username = request.POST.get('username')
        username = request.POST['username']
        fname = request. POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

    #Authentication
        if User.objects.filter(username=username):
            messages.error(request,"Username already exist!! Please try another username")
            return redirect('index')

        if User.objects.filter(email=email):
            messages.error(request, "Email Already Registered ")
            return redirect('index')

        if len(username) > 10:
            messages.error(request,"Username must be under 10 characters")

        if pass1 != pass1:
            messages.error(request,"Password didn't match!")

        if not username.isalnum():
            messages.error(request,"Username must be Aplha-Numeric!!")
            return redirect('home')


        myuser = User.objects.create_user(username,email,pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        messages.success(request,"Your Acc. has been Successfully Created. We have sent you a confirmation email, please confirm ypur email in order to activate your account.")

    #Welcome Email:

        subject = "Welcome to RegistrationSystem!!"
        message = "Hello" + myuser.first_name + "!! \n" + "Welcome to RegistrationSystem!! \n Thank you for visiting our website \n we have also sent you a configuration email,please confirm your email address in order to activate your account. \n\n Thanking You\n Roshan"
        from_email = settings.EMAIL_HOST_USER
        to_list = [myuser.email]
        send_mail(subject,message,from_email,to_list,fail_silently=True)

    #Email Address Confirmation Email
        current_site = get_current_site(request)
        email_subject = "Confirm Your Email @RegistratinSystem!!"
        message2 = render_to_string('email_confirmation.html',{
            'name': myuser.first_name,
            'domain': current_site_domain,
            'uid' : urlsafe_base64_encode(force_bytes(myuser.pk)),
            'token' : generate_token.make_token(myuser)
        })
        email = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [myuser.email],
        )
        email.fail_silently = True
        email.send()

        return redirect('login')

    return render(request,'Authentication/signup.html')

from django.contrib.auth import authenticate,login

def login(request):
    if request.method == 'POST':
        username = request.POST['username']
        pass1 = request.POST['pass1']

        #Authenticate The User
        user = authenticate(username=username, password=pass1)

        if user is not None:    #if user enter corret-credentials it will return not non object
            auth_login(request,user)
            fname = user.first_name
            return render(request,"Authentication/index.html",{'fname':fname})
        else:
            messages.error(request, "Wrong Credentials")
            return redirect('index')

    return render(request,'Authentication/login.html')

def signout(request):
    logout(request)
    messages.success(request,"Logged Out Successfully!")
    return redirect('index')


def activate(request,uidb64,token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        myuser = User.objects.get(pk=uid)
    except(TypeError,ValueError,OverflowError,User.DoesNotExist):
        myuser = None

    if myuser is not None and generate_token.check_token(myuser,token):
        myuser.is_active = True
        myuser.save()
        login(request,myuser)
        return redirect('index')
    else:
        return render(request,'activation_failed.html')

