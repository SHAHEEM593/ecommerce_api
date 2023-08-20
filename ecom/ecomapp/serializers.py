from rest_framework import serializers
from . models import Product,User,Category,Cart,CartItem,Order,OrderItem
from django.contrib.auth import get_user_model



class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    

class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)
    
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'full_name']


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
        
class ProductSerializer(serializers.ModelSerializer):
    categories = serializers.SlugRelatedField(
        queryset=Category.objects.all(),
        many=True,
        slug_field='name'  
    )

    class Meta:
        model = Product
        fields = '__all__'



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'date_joined', 'is_active']


class CartItemSerializer(serializers.ModelSerializer):
    cart = serializers.StringRelatedField()
    product = serializers.StringRelatedField()

    class Meta:
        model = CartItem
        fields = ['id', 'cart', 'product', 'quantity']



class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True)

    class Meta:
        model = Cart
        fields = '__all__'


class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()
    class Meta:
        model = OrderItem
        fields = ['product', 'quantity']

class OrderSerializer(serializers.ModelSerializer):
    order_items = OrderItemSerializer(many=True, source='orderitem_set')

    class Meta:
        model = Order
        fields = ['id', 'total_amount', 'created_at', 'status', 'order_items']

        
class PromotionalEmailSerializer(serializers.Serializer):
    subject = serializers.CharField(max_length=200)
    message = serializers.CharField()

