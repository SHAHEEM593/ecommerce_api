# Generated by Django 4.2.4 on 2023-08-10 13:10

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ecomapp', '0003_remove_product_category_product_categories'),
    ]

    operations = [
        migrations.CreateModel(
            name='Cart',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
            ],
        ),
        migrations.CreateModel(
            name='CartItem',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('quantity', models.PositiveIntegerField(default=1)),
                ('cart', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ecomapp.cart')),
                ('product', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='ecomapp.product')),
            ],
        ),
        migrations.AddField(
            model_name='cart',
            name='items',
            field=models.ManyToManyField(through='ecomapp.CartItem', to='ecomapp.product'),
        ),
        migrations.AddField(
            model_name='cart',
            name='user',
            field=models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
    ]
