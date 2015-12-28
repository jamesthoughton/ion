# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
from django import template

register = template.Library()
logger = logging.getLogger(__name__)


@register.filter
def contains_digit(s):
    return any(c.isdigit() for c in s)


@register.filter
def endswith(val, arg):
    return val.endswith(arg)
