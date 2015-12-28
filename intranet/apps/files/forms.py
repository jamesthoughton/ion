# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django import forms
import logging
from intranet import settings

logger = logging.getLogger(__name__)


class UploadFileForm(forms.Form):

    def validate_size(obj):
        filesize = obj.file.__sizeof__()
        if filesize > settings.FILES_MAX_UPLOAD_SIZE:
            raise forms.ValidationError("The file uploaded is above the maximum upload size ({}MB). " +
                                        "Use a desktop client to upload this file.".format(
                                            settings.FILES_MAX_UPLOAD_SIZE / 1024 / 1024))
    file = forms.FileField(validators=[validate_size])
