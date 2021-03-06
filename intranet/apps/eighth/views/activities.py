# -*- coding: utf-8 -*-

import logging
from datetime import datetime, timedelta

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render

from ..models import EighthActivity, EighthBlock, EighthScheduledActivity

logger = logging.getLogger(__name__)


@login_required
def activity_view(request, activity_id=None):
    activity = get_object_or_404(EighthActivity, id=activity_id)
    first_block = EighthBlock.objects.get_first_upcoming_block()
    scheduled_activities = EighthScheduledActivity.objects.filter(activity=activity)

    show_all = ("show_all" in request.GET)
    if first_block and not show_all:
        two_months = datetime.now().date() + timedelta(weeks=8)
        scheduled_activities = scheduled_activities.filter(block__date__gte=first_block.date, block__date__lte=two_months)

    scheduled_activities = scheduled_activities.order_by("block__date")

    context = {"activity": activity, "scheduled_activities": scheduled_activities}

    return render(request, "eighth/activity.html", context)


@login_required
def statistics_view(request, activity_id=None):
    if not (request.user.is_eighth_admin or request.user.is_teacher):
        return render(request, "error/403.html", {"reason": "You do not have permission to view statistics for this activity."}, status=403)

    activity = get_object_or_404(EighthActivity, id=activity_id)

    activities = EighthScheduledActivity.objects.filter(activity=activity)

    signups = {}

    old_blocks = 0

    for a in activities:
        if a.block.is_this_year:
            for user in a.members.all():
                if user in signups:
                    signups[user] += 1
                else:
                    signups[user] = 1
        else:
            old_blocks += 1

    signups = sorted(signups.items(), key=lambda kv: (-kv[1], kv[0].username))
    total_blocks = activities.count()
    total_signups = sum(n for _, n in signups)
    if total_blocks:
        average_signups = round(total_signups / total_blocks, 2)
    else:
        average_signups = 0

    context = {"activity": activity, "members": signups, "total_blocks": total_blocks, "total_signups": total_signups, "average_signups": average_signups, "old_blocks": old_blocks}
    return render(request, "eighth/statistics.html", context)
