from django.shortcuts import render
from . models import Product,Category
from . serializers import ProductSerializer,CategorySerializer,OrderSerializer,PasswordResetSerializer,CartItemSerializer
from rest_framework import generics, status,permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, login
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from .models import User 
from .serializers import UserRegistrationSerializer, UserLoginSerializer
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes
from .models import Cart, CartItem,Order, OrderItem
from django_filters.rest_framework import DjangoFilterBackend
from .filters import ProductFilter
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from django.core.mail import send_mail
from .serializers import PromotionalEmailSerializer
from rest_framework.permissions import IsAdminUser
from django.contrib.auth import get_user_model
from .serializers import UserSerializer
from rest_framework.pagination import PageNumberPagination
from rest_framework.views import APIView
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import get_template
from django.contrib.auth.tokens import PasswordResetTokenGenerator




class IsAdminUser(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_staff
    
class LandingPageView(APIView):
    def get(self, request):
        data = {
            'message': 'Welcome to our E-commerce API!',
            'endpoints': {
                'products': 'products/',
                'users': 'users/',
            }
        }
        return Response(data, status=status.HTTP_200_OK)


class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        email_subject = 'Welcome to our Blogging Platform'
        email_context = {
            'username': user.username,
        }
        email_html_message = render_to_string('mail.html', email_context)
        email_plain_message = strip_tags(email_html_message)  
        email = EmailMultiAlternatives(
            subject=email_subject,
            body=email_plain_message,
            from_email=settings.EMAIL_HOST_USER,
            to=[user.email],
        )
        email.attach_alternative(email_html_message, "text/html") 
        email.send()

        return Response('Registration successful. An email has been sent to your registered email address.', status=status.HTTP_201_CREATED)



class UserLoginView(generics.CreateAPIView):
    serializer_class = UserLoginSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        username = serializer.validated_data.get('username')
        password = serializer.validated_data.get('password')

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            refresh = RefreshToken.for_user(user)
            return Response({'refresh': str(refresh), 'access': str(refresh.access_token)}, status=status.HTTP_200_OK)

        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)



class PasswordResetRequestView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = get_user_model().objects.get(email=email)
                token_generator = PasswordResetTokenGenerator()
                uid = urlsafe_base64_encode(str(user.pk).encode())
                token = token_generator.make_token(user)
                reset_link = f'http://127.0.0.1:8000/user/password-reset-confirm/{uid}/{token}/'
                ctx = {
                    'user': user.username,
                    'reset_link': reset_link,
                    'uid': uid,
                    'token': token,
                }
                subject = "Password Reset Request"
                email_template = get_template('password_reset_email.html')
                email_content = email_template.render(ctx)
                from_email = settings.DEFAULT_FROM_EMAIL
                to_email = user.email
                send_mail(subject, '', from_email, [to_email], html_message=email_content)
                return Response({'message': 'Password reset email sent successfully'}, status=status.HTTP_200_OK)
            except get_user_model().DoesNotExist:
                return Response({'error': 'No user with that email address'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64)
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            user = None

        if user is not None and PasswordResetTokenGenerator().check_token(user, token):
            new_password = request.data.get('new_password')
            if new_password:
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'New password is required'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)



class CustomPageNumberPagination(PageNumberPagination):
    page_size = 5  
    page_size_query_param = 'page_size' 
    max_page_size = 100  

class CategoryListView(generics.ListCreateAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAdminUser]
class CategoryRetrieveUpdateView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [permissions.IsAdminUser]

class ProductCreateView(generics.CreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAdminUser]



class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPageNumberPagination  


class ProductDetailView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAuthenticated]


class ProductUpdateView(generics.UpdateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAdminUser]




class ProductDeleteView(generics.DestroyAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [permissions.IsAdminUser]

class OrderListView(generics.ListAPIView):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [permissions.IsAdminUser]

class ProductFilterView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_class = ProductFilter
    permission_classes = [permissions.IsAuthenticated]


class UserListView(generics.ListCreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAdminUser]


#cart
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def add_to_cart(request):
    product_ids = request.data.get('product_ids', [])

    if not product_ids:
        return Response({'error': 'No products provided.'}, status=status.HTTP_400_BAD_REQUEST)

    cart, created = Cart.objects.get_or_create(user=request.user)
    added_products = []

    for product_id in product_ids:
        try:
            product = Product.objects.get(pk=product_id)
            cart_item, item_created = CartItem.objects.get_or_create(cart=cart, product=product)

            if not item_created:
                cart_item.quantity += 1
                cart_item.save()

            added_products.append({
                'product': ProductSerializer(product).data,
                'cart_item': CartItemSerializer(cart_item).data
            })

        except Product.DoesNotExist:
            pass 

    return Response({'message': 'Products added to cart successfully.', 'added_products': added_products}, status=status.HTTP_200_OK)




@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def view_cart(request):
    try:
        cart = Cart.objects.get(user=request.user)
        cart_items = CartItem.objects.filter(cart=cart)
        cart_item_serializer = CartItemSerializer(cart_items, many=True)
        
        total_price = sum(item.product.price * item.quantity for item in cart_items)
        
        return Response({
            'cart_items': cart_item_serializer.data,
            'total_price': total_price  
        }, status=status.HTTP_200_OK)
    except Cart.DoesNotExist:
        return Response({'error': 'Cart not found.'}, status=status.HTTP_404_NOT_FOUND)



@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def update_cart_item(request, cart_item_id):
    try:
        cart_item = CartItem.objects.get(id=cart_item_id, cart__user=request.user)
    except CartItem.DoesNotExist:
        return Response({'error': 'Cart item not found.'}, status=status.HTTP_404_NOT_FOUND)

    quantity = request.data.get('quantity', None)
    if quantity is not None:
        if quantity <= 0:
            cart_item.delete()
        else:
            cart_item.quantity = quantity
            cart_item.save()

    cart_item_serializer = CartItemSerializer(cart_item)
    return Response({'cart_item': cart_item_serializer.data}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def remove_cart_item(request, cart_item_id):
    try:
        cart_item = CartItem.objects.get(id=cart_item_id, cart__user=request.user)
        cart_item.delete()
        return Response({'message': 'Cart item removed successfully.'}, status=status.HTTP_200_OK)
    except CartItem.DoesNotExist:
        return Response({'error': 'Cart item not found.'}, status=status.HTTP_404_NOT_FOUND)




#order
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def place_order(request):
    user = request.user
    cart = Cart.objects.get(user=user)
    cart_items = CartItem.objects.filter(cart=cart)

    total_amount = sum(item.product.price * item.quantity for item in cart_items)

    order = Order.objects.create(user=user, total_amount=total_amount)
    for cart_item in cart_items:
        product = cart_item.product
        order_item = OrderItem.objects.create(order=order, product=product, quantity=cart_item.quantity)

        product.quantity -= cart_item.quantity
        product.save()

    cart_items.delete()

    send_order_notification_email(user, order)

    return Response({'message': 'Order placed successfully.'}, status=status.HTTP_201_CREATED)


def send_order_notification_email(user, order):
    subject = 'Order Placed Successfully'

    html_message = render_to_string('order_notification_email.html', {'order': order})
    text_message = f"Order ID: {order.id}\nTotal Amount: {order.total_amount}"

    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]

    msg = EmailMultiAlternatives(subject, text_message, from_email, recipient_list)
    msg.attach_alternative(html_message, "text/html")
    msg.send()

    admins = User.objects.filter(is_staff=True)
    admin_recipients = [admin.email for admin in admins]

    admin_msg = EmailMultiAlternatives(subject, text_message, from_email, admin_recipients)
    admin_msg.attach_alternative(html_message, "text/html")
    admin_msg.send()



@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def order_history(request):
    user = request.user
    orders = Order.objects.filter(user=user)
    order_serializer = OrderSerializer(orders, many=True)
    return Response({'orders': order_serializer.data}, status=status.HTTP_200_OK)





@api_view(['PATCH'])
@permission_classes([IsAdminUser])
def update_order_status(request, pk):
    try:
        order = Order.objects.get(pk=pk)
    except Order.DoesNotExist:
        return Response({'error': 'Order not found.'}, status=status.HTTP_404_NOT_FOUND)

    new_status = request.data.get('status')
    if not new_status:
        return Response({'error': 'Status field is required.'}, status=status.HTTP_400_BAD_REQUEST)

    valid_statuses = [status[0] for status in Order.STATUS_CHOICES]

    if new_status in valid_statuses:
        old_status = order.status
        order.status = new_status
        order.save()

        send_order_status_notification(order, old_status, new_status)

        return Response({'message': f'Order status updated to "{new_status}" successfully.'}, status=status.HTTP_200_OK)
    else:
        return Response({'error': 'Invalid status value.'}, status=status.HTTP_400_BAD_REQUEST)

def send_order_status_notification(order, old_status, new_status):
    subject = f'Order Status Update - Order #{order.pk}'
    message = f'Order #{order.pk} status has been updated from "{old_status}" to "{new_status}".'
    recipient_list = [order.user.email] 

    html_message = render_to_string('order_status_email_template.html', {'order': order, 'old_status': old_status, 'new_status': new_status})

    send_mail(subject, message, 'admin@example.com', recipient_list, html_message=html_message)





@api_view(['POST'])
@permission_classes([IsAuthenticated])
def send_promotional_email(request):
    if request.user.is_staff: 
        serializer = PromotionalEmailSerializer(data=request.data)
        if serializer.is_valid():
            subject = serializer.validated_data['subject']
            message = serializer.validated_data['message']
            recipient_list = [user.email for user in User.objects.all()]  

            html_message = render_to_string('promotional_email_template.html', {'message': message})

            send_mail(subject, '', 'admin@example.com', recipient_list, html_message=html_message)

            return Response({'message': 'Promotional email sent successfully.'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    else:
        return Response({'error': 'You do not have permission to send promotional emails.'}, status=status.HTTP_403_FORBIDDEN)
