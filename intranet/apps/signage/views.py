# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import logging
import datetime
from django import http
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.utils import timezone
from intranet import settings
from .models import Sign
from ..users.models import User
from ..eighth.models import EighthBlock, EighthSignup
from ..eighth.serializers import EighthBlockDetailSerializer
from ..schedule.views import schedule_context
from ...utils.serialization import safe_json

logger = logging.getLogger(__name__)


def check_show_eighth(now):
    next_block = EighthBlock.objects.get_first_upcoming_block()
    if next_block:
        if next_block.date != now.date():
            return False

    return (8 < now.time().hour < 16)


def signage_display(request, display_id=None):
    try:
        sign = Sign.objects.get(display=display_id)
        sign_status = sign.status
    except Sign.DoesNotExist:
        sign = None
        sign_status = "auto"

    if "status" in request.GET:
        sign_status = request.GET.get("status")

    suffix = "id={}".format(display_id)
    if "mac" in request.GET:
        suffix += "&mac={}".format(request.GET["mac"])

    now = datetime.datetime.now()
    if sign_status == "eighth":
        # return eighth_signage(request, None, sign.block_increment)
        if sign and sign.eighth_block_increment:
            iframe = "/signage/eighth?no_reload&block_increment={}&".format(sign.eighth_block_increment)
        else:
            iframe = "/signage/eighth?no_reload&"
        return iframe_signage(request, iframe)
    elif sign_status == "schedule":
        return schedule_signage(request)
    elif sign_status == "status":
        return status_signage(request)
    elif sign_status == "url" or "url" in request.GET:
        return iframe_signage(request, request.GET.get('url') or (sign.url if sign else "about:blank"))
    else:
        if check_show_eighth(now):
            if sign and sign.eighth_block_increment:
                iframe = "/signage/eighth?block_increment={}&".format(sign.eighth_block_increment)
            else:
                iframe = "/signage/eighth?no_reload&"
            return iframe_signage(request, iframe)
        else:
            return status_signage(request)

    return redirect(url)


def schedule_signage(request):
    context = schedule_context(request)
    context["signage"] = True
    context["hide_arrows"] = True
    return render(request, "schedule/embed.html", context)


def status_signage(request):
    context = schedule_context(request)
    context["signage"] = True
    return render(request, "signage/status.html", context)


def iframe_signage(request, url):
    context = schedule_context(request)
    context["signage"] = True
    context["url"] = url
    return render(request, "signage/iframe.html", context)


def eighth_signage(request, block_id=None, block_increment=0):
    remote_addr = (request.META["HTTP_X_FORWARDED_FOR"] if "HTTP_X_FORWARDED_FOR" in request.META else request.META.get("REMOTE_ADDR", ""))
    if not request.user.is_authenticated() and remote_addr not in settings.INTERNAL_IPS:
        return render(request, "error/403.html", {
            "reason": "You are not authorized to view this page."
        }, status=403)

    if block_id is None:
        next_block = EighthBlock.objects.get_first_upcoming_block()
        if next_block is not None:
            block_id = next_block.id
        else:
            last_block = EighthBlock.objects.order_by("date").last()
            if last_block is not None:
                block_id = last_block.id

    if "block_increment" in request.GET:
        block_increment = request.GET.get("block_increment", 0)

    try:
        block_increment = int(block_increment)
    except ValueError:
        block_increment = 0

    block = None
    if block_increment > 0:
        next_blocks = next_block.next_blocks()
        if next_blocks.count() >= block_increment:
            block = next_blocks[block_increment - 1]

    if not block:
        try:
            block = (EighthBlock.objects
                                .prefetch_related("eighthscheduledactivity_set")
                                .get(id=block_id))
        except EighthBlock.DoesNotExist:
            if EighthBlock.objects.count() == 0:
                # No blocks have been added yet
                return render(request, "eighth/display.html", {"no_blocks": True})
            else:
                # The provided block_id is invalid
                raise http.Http404

    user = User.objects.get(username="awilliam")

    serializer_context = {
        "request": request,
        "user": user
    }
    block_info = EighthBlockDetailSerializer(block, context=serializer_context).data
    try:
        reload_mins = float(request.GET.get("reload_mins") or 5)
    except Exception:
        reload_mins = 5

    context = {
        "user": user,
        "real_user": request.user,
        "block_info": block_info,
        "activities_list": safe_json(block_info["activities"]),
        "active_block": block,
        "active_block_current_signup": None,
        "no_title": ("no_title" in request.GET),
        "no_detail": not ("detail" in request.GET),
        "no_rooms": ("no_rooms" in request.GET),
        "use_scroll": ("no_scroll" not in request.GET),
        "do_reload": ("no_reload" not in request.GET),
        "preload_background": True,
        "reload_mins": reload_mins,
        "no_user_display": True,
        "no_fav": True
    }

    return render(request, "eighth/display.html", context)
