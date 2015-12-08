# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import time
import logging
from django.contrib import messages
from django.contrib.auth import logout
from django.shortcuts import redirect
from ..db.ldap_db import LDAPConnection
from ..utils import urls

logger = logging.getLogger(__name__)


class CheckLDAPBindMiddleware:

    def process_response(self, request, response):
        if not request.user.is_authenticated():
            # Nothing to check if user isn't already logged in
            return response

        auth_backend = request.session["_auth_user_backend"]
        master_pwd_backend = auth_backend.endswith("MasterPasswordAuthenticationBackend")

        used_simple_bind = LDAPConnection().did_use_simple_bind()

        logger.debug('Used simple bind: {}'.format(used_simple_bind))

        if (used_simple_bind and not master_pwd_backend):
            logger.info("Obtained a simple bind -- {}".format(request.user))
            if "login_time" in request.session:
                login_time = request.session["login_time"]
                now_time = time.time() # seconds
                session_length = int(now_time - login_time)
                minutes = 60
                if session_length > (1 * minutes):
                    try:
                        kerberos_cache = request.session["KRB5CCNAME"]
                        os.system("/usr/bin/kdestroy -c " + kerberos_cache)
                    except KeyError:
                        pass
                    logout(request)

                    response = redirect("login")
                    url = response["Location"]
                    response["Location"] = urls.add_get_parameters(
                        url, {"next": request.path}, percent_encode=False)
                    return response

            messages.error(request, "Access to directory information may be limited: LDAP issue. Try logging out and back in.")
            """
            logger.info("Simple bind being used: Destroying kerberos cache and logging out")

            
            """
        return response
