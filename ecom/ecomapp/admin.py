from django.contrib import admin
from .models import User, Category, Product,CartItem,Cart,Order,OrderItem

# Register your models here
admin.site.register(User)
admin.site.register(Category)
admin.site.register(Product)
admin.site.register(CartItem)
admin.site.register(Cart)
admin.site.register(OrderItem)
admin.site.register(Order)
