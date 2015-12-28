# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import logging

from django.http import Http404
from rest_framework import generics, views, status
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from intranet.apps.users.models import User
from .models import Day, DayType, CodeName, Block, Time
from .serializers import DaySerializer, DayTypeSerializer

logger = logging.getLogger(__name__)


class OnePagePagination(PageNumberPagination):
    page_size = 1
    page_size_query_param = 'page_size'
    max_page_size = 7


class DayList(generics.ListAPIView):
    queryset = Day.objects.get_future_days()
    serializer_class = DaySerializer
    permission_classes = (AllowAny,)
    pagination_class = OnePagePagination


class DayDetail(generics.RetrieveAPIView):
    queryset = Day.objects.all()
    serializer_class = DaySerializer
    lookup_field = "date"
    permission_classes = (AllowAny,)

    def get_object(self):
        try:
            day = Day.objects.get(date=self.kwargs['date'])
            return day
        except Day.DoesNotExist:
            return None
