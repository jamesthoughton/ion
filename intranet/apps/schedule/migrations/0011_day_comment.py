# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('schedule', '0010_auto_20150806_1547'),
    ]

    operations = [
        migrations.AddField(
            model_name='day',
            name='comment',
            field=models.CharField(max_length=1000, blank=True),
        ),
    ]
