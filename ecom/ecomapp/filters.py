import django_filters
from django.db.models import Q
from .models import Product

class ProductFilter(django_filters.FilterSet):
    category_name = django_filters.CharFilter(method='filter_by_category_name')
    min_price = django_filters.NumberFilter(field_name='price', lookup_expr='gte')
    max_price = django_filters.NumberFilter(field_name='price', lookup_expr='lte')

    class Meta:
        model = Product
        fields = []

    def filter_by_category_name(self, queryset, name, value):
        return queryset.filter(categories__name__iexact=value)

    def filter(self, queryset, *args, **kwargs):
        queryset = super().filter(queryset, *args, **kwargs)
        
        min_price = self.data.get('min_price')
        max_price = self.data.get('max_price')

        if min_price:
            queryset = queryset.filter(price__gte=min_price)
        if max_price:
            queryset = queryset.filter(price__lte=max_price)

        return queryset
