# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('printing', '0003_printjob_num_pages'),
    ]

    operations = [
        migrations.AlterField(
            model_name='printjob',
            name='file',
            field=models.FileField(upload_to='uploads/'),
        ),
    ]
