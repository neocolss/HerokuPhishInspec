# -*- coding: utf-8 -*-
# Generated by Django 1.11.7 on 2017-12-19 20:41
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('phish_inspec', '0002_auto_20171219_2029'),
    ]

    operations = [
        migrations.AlterField(
            model_name='urlmodel',
            name='created_date',
            field=models.DateTimeField(auto_now_add=True),
        ),
    ]
