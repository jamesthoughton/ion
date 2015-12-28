# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('polls', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='choice',
            name='free_resp',
            field=models.CharField(max_length=1000, blank=True),
        ),
        migrations.AlterField(
            model_name='choice',
            name='short_resp',
            field=models.CharField(max_length=100, blank=True),
        ),
        migrations.AlterField(
            model_name='choice',
            name='std_other',
            field=models.CharField(max_length=100, blank=True),
        ),
    ]
