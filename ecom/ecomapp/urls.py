from django.urls import path, include
from . import views
from rest_framework_simplejwt import views as jwt_views


urlpatterns=[
    path('', views.LandingPageView.as_view(), name='landing-page'),
    path('register/', views.UserRegistrationView.as_view(), name='user-registration'),
    path('login/', views.UserLoginView.as_view(), name='user-login'),
    path('user/password-reset/', views.PasswordResetRequestView.as_view(), name='password-reset'),
    path('user/password-reset-confirm/<str:uidb64>/<str:token>/', views.PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    path('category/', views.CategoryListView.as_view(), name='category-list'),
    path('category/<int:pk>/', views.CategoryRetrieveUpdateView.as_view(), name='category-detail'),

    path('products/create/', views.ProductCreateView.as_view(), name='product-list'),
    path('products/', views.ProductListView.as_view(), name='product-list'),
    path('products/<int:pk>/', views.ProductDetailView.as_view(), name='product-detail'),
    path('products/<int:pk>/update/', views.ProductUpdateView.as_view(), name='product-update'),
    path('products/<int:pk>/delete/', views.ProductDeleteView.as_view(), name='product-delete'),
    path('products/filter/', views.ProductFilterView.as_view(), name='product-filter'),

    path('cart/add/', views.add_to_cart, name='add-to-cart'),
    path('cart/view/', views.view_cart, name='view-cart'),
    path('cart/item/<int:cart_item_id>/update/', views.update_cart_item, name='update-cart-item'),
    path('cart/item/<int:cart_item_id>/remove/', views.remove_cart_item, name='remove-cart-item'),

    path('order/place/', views.place_order, name='place-order'),
    path('order/', views.OrderListView.as_view(), name='order-list'),
    path('order/history/', views.order_history, name='order-history'),
    path('order/<int:pk>/update_status/', views.update_order_status, name='update-order-status'),

    path('users/', views.UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),

    path('send_promotional_email/', views.send_promotional_email, name='send-promotional-email'),
]

