import jwt
from flask import Request, flash, g, redirect, request, session
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.views import AuthView
from flask_appbuilder.utils.base import get_safe_redirect
from flask_appbuilder.views import expose
from flask_login import login_user, logout_user
from superset.security.manager import SupersetSecurityManager
from werkzeug.sansio.utils import get_current_url
from werkzeug.wrappers import Response as WerkzeugResponse


# Custom Authenticator based on principals in request headers
class HeaderAuthRemoteUserView(AuthView):
    __AUTH_USERNAME_HEADER_KEY = "X-Auth-Request-Preferred-Username"
    __AUTH_EMAIL_HEADER_KEY = "X-Auth-Request-Email"
    __AUTH_JWT_HEADER_KEY = "Authorization"
    __PLATFORM_LOGOUT_URI = "/api/v1/logout"
    __PLATFORM_HOME_SUBDOMAIN = "home"
    __ACCESS_DENIED_FLASH_MESSAGE = "Access is Denied"

    @classmethod
    def get_username_from_request(cls, request: Request):
        return request.headers.get(cls.__AUTH_USERNAME_HEADER_KEY)

    @classmethod
    def __get_email_from_request(cls, request: Request):
        return request.headers.get(cls.__AUTH_EMAIL_HEADER_KEY)

    @classmethod
    def __get_decoded_jwt_from_request(cls, request: Request):
        authorization_header = request.headers.get(cls.__AUTH_JWT_HEADER_KEY)
        if authorization_header:
            token = authorization_header.split(None, 1)
            if len(token) == 2 and token[0] == "Bearer":
                return jwt.decode(token[1], options={"verify_signature": False})
        return None

    @expose("/login/")
    def login(self) -> WerkzeugResponse:
        ab_security_manager = self.appbuilder.sm

        actual_username = self.get_username_from_request(request)
        if g.user is not None and g.user.is_authenticated and g.user.username == actual_username:
            next_url = request.args.get("next", "")
            return redirect(get_safe_redirect(next_url))
        if actual_username:
            self.__get_or_create_user(actual_username)
            user = ab_security_manager.auth_user_remote_user(actual_username)
            if user is None:
                flash(as_unicode(self.invalid_login_message), "warning")
            else:
                login_user(user)
                # AUTH_REMOTE_USER auth type flashes message "Access is denied" for /login/ endpoint.
                # We need to remove such flash message to avoid confusion for users
        else:
            flash(as_unicode(self.invalid_login_message), "warning")
        next_url = request.args.get("next", "")
        return redirect(get_safe_redirect(next_url))

    def __get_or_create_custom_role(self, role_name: str):
        ab_security_manager = self.appbuilder.sm

        custom_alpha_role = ab_security_manager.find_role(role_name)
        if custom_alpha_role:
            return
        
        alpha_role = ab_security_manager.find_role("Alpha")
        if alpha_role:
            alpha_permissions = alpha_role.permissions
            custom_alpha_role = ab_security_manager.add_role(
                role_name,
                alpha_permissions
            )
            
            if custom_alpha_role is None:
                raise Exception(f"Cannot create {role_name} role")

            write_db_perm = ab_security_manager.find_permission_view_menu('can_write', 'Database')
            if write_db_perm:
                custom_alpha_role.permissions.append(write_db_perm)
                ab_security_manager.get_session.commit()
            else:
                raise Exception("'can_write Database' permission does not exist")
        else:
            raise Exception("Alpha role not found")

    def __get_or_create_user(self, username):
        ab_security_manager = self.appbuilder.sm
        user = ab_security_manager.find_user(username)

        if user is None and ab_security_manager.auth_user_registration:
            email = self.__get_email_from_request(request)
            first_name = username
            last_name = "-"
            token_payload = self.__get_decoded_jwt_from_request(request)
            if token_payload:
                first_name = token_payload.get("given_name", first_name)
                last_name = token_payload.get("family_name", last_name)
                
                groups = token_payload.get("groups")
                if "admin" in groups:
                    role_name = ab_security_manager.auth_role_admin
                else:
                    # The default authentication role should be defined in helm/superset/values.yaml as AUTH_USER_REGISTRATION_ROLE
                    role_name = ab_security_manager.auth_user_registration_role
                    
            self.__get_or_create_custom_role(role_name)

            user = ab_security_manager.add_user(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                role = ab_security_manager.find_role(role_name)
            )

        return user

    @expose("/logout/")
    def logout(self):
        full_host = request.host

        # If host from request does not contain "." it means that it is not production environment
        if "." not in full_host:
            return super().logout()

        logout_user()
        _, base_host = full_host.split(".", 1)
        home_host = f"{self.__PLATFORM_HOME_SUBDOMAIN}.{base_host}"
        logout_url = get_current_url(request.scheme, home_host, self.__PLATFORM_LOGOUT_URI)
        return redirect(logout_url)


class HeaderAuthenticationSecurityManager(SupersetSecurityManager):
    authremoteuserview = HeaderAuthRemoteUserView

    def load_user(self, user_id):
        actual_username = HeaderAuthRemoteUserView.get_username_from_request(request)
        loaded_user = super().load_user(user_id)
        # User can be changed by platform authentication provider, so we need to check
        # if user in saved session of current app is the same as in request headers from platform.
        # In case of username is not the same, we need to return None to force re-login
        if loaded_user is not None and loaded_user.username != actual_username:
            return None
        return loaded_user