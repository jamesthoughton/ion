# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import logging

from django.http import Http404
from rest_framework import generics, views, status
from rest_framework.response import Response
from intranet.apps.users.models import User
from ..models import EighthActivity, EighthBlock, EighthSignup, EighthScheduledActivity
from ..serializers import EighthBlockListSerializer, EighthBlockDetailSerializer, EighthActivityListSerializer, EighthActivityDetailSerializer, EighthSignupSerializer, EighthAddSignupSerializer, EighthScheduledActivitySerializer

logger = logging.getLogger(__name__)


# class EighthActivityList(generics.ListAPIView):
#     """API endpoint that allows viewing a list of eighth activities
#     """
#     queryset = EighthActivity.undeleted_objects.all()
#     serializer_class = EighthActivityDetailSerializer


class EighthActivityList(generics.ListAPIView):
    queryset = EighthActivity.undeleted_objects.all()
    serializer_class = EighthActivityListSerializer


class EighthActivityDetail(generics.RetrieveAPIView):

    """API endpoint that shows details of an eighth activity.
    """
    queryset = EighthActivity.undeleted_objects.all()
    serializer_class = EighthActivityDetailSerializer


class EighthBlockList(generics.ListAPIView):

    """API endpoint that lists all eighth blocks
    """
    # FIXME: this call throws sphinx for a loop
    queryset = EighthBlock.objects.get_current_blocks()
    serializer_class = EighthBlockListSerializer


class EighthBlockDetail(views.APIView):

    """API endpoint that shows details for an eighth block
    """

    def get(self, request, pk):
        try:
            block = EighthBlock.objects.prefetch_related("eighthscheduledactivity_set").get(pk=pk)
        except EighthBlock.DoesNotExist:
            raise Http404

        serializer = EighthBlockDetailSerializer(block, context={"request": request})
        return Response(serializer.data)


class EighthUserSignupListAdd(generics.ListCreateAPIView):
    serializer_class = EighthAddSignupSerializer

    def list(self, request, user_id=None):
        if not user_id:
            user_id = request.user.id

        signups = EighthSignup.objects.filter(user_id=user_id).prefetch_related("scheduled_activity__block").select_related("scheduled_activity__activity")

        serialized = EighthSignupSerializer(signups, context={"request": request}, many=True)

        return Response(serialized.data)

    def create(self, request, user_id=None):
        if user_id:
            user = User.objects.get(id=user_id)
        else:
            user = request.user

        serializer = EighthAddSignupSerializer(data=request.data, context={"request": request})
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        if "activity" not in serializer.validated_data or "block" not in serializer.validated_data or serializer.validated_data.get("use_scheduled_activity", False):
            schactivity = serializer.validated_data["scheduled_activity"]
        else:
            schactivity = EighthScheduledActivity.objects.filter(activity=serializer.validated_data["activity"]).filter(block=serializer.validated_data["block"]).get()
        if 'force' in serializer.validated_data:
            force = serializer.validated_data['force']
        else:
            force = False

        if force and not request.user.is_eighth_admin:
            return Response({"error": "You are not an administrator."}, status=status.HTTP_400_BAD_REQUEST)

        schactivity.add_user(user, request, force=force)

        return Response(EighthActivityDetailSerializer(schactivity.activity, context={"request": request}).data, status=status.HTTP_201_CREATED)


class EighthScheduledActivitySignupList(views.APIView):

    """API endpoint that lists all signups for a certain scheduled activity
    """

    def get(self, request, scheduled_activity_id):
        scheduled_activity = EighthScheduledActivity.objects.get(id=scheduled_activity_id)
        serializer = EighthScheduledActivitySerializer(scheduled_activity, context={"request": request})

        return Response(serializer.data)


class EighthSignupDetail(generics.RetrieveAPIView):

    """API endpoint that shows details of an eighth signup
    """
    queryset = EighthSignup.objects.all()
    serializer_class = EighthSignupSerializer
