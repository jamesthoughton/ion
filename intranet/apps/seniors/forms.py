# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django import forms
from .models import Senior
from ..users.models import User


class SeniorForm(forms.ModelForm):

    def __init__(self, *args, **kwargs):
        super(SeniorForm, self).__init__(*args, **kwargs)
        self.fields["college"].help_text = "CollegeBoard CEEB numbers are in parentheses."
        self.fields["college"].empty_label = "Undecided"
        self.fields["college_sure"].label = "Sure?"
        self.fields["major_sure"].label = "Sure?"

    class Meta:
        model = Senior
        fields = ["college",
                  "college_sure",
                  "major",
                  "major_sure"]
