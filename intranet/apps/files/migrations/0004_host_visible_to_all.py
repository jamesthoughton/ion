# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('files', '0003_auto_20150809_0057'),
    ]

    operations = [
        migrations.AddField(
            model_name='host',
            name='visible_to_all',
            field=models.BooleanField(default=False),
        ),
    ]
