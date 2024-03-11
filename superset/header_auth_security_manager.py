import jwt
from flask import Request, flash, g, redirect, request, session
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.views import AuthView
from flask_appbuilder.utils.base import get_safe_redirect
from flask_appbuilder.views import expose
from flask_babel import lazy_gettext
from flask_login import login_user, logout_user
from superset.security.manager import SupersetSecurityManager
from werkzeug.sansio.utils import get_current_url
from werkzeug.wrappers import Response as WerkzeugResponse


# Custom Authenticator based on principals in request headers
class HeaderAuthRemoteUserView(AuthView):
    __AUTH_USERNAME_HEADER_KEY = "X-Auth-Request-Preferred-Username"
    __AUTH_EMAIL_HEADER_KEY = "X-Auth-Request-Email"
    __AUTH_GROUPS_HEADER_KEY = "X-Auth-Request-Groups"
    __AUTH_JWT_HEADER_KEY = "Authorization"
    __PLATFORM_ADMIN_ROLE = "admin"
    __PLATFORM_LOGOUT_URI = "/api/v1/logout"
    __PLATFORM_HOME_SUBDOMAIN = "home"
    __ACCESS_DENIED_FLASH_MESSAGE = "Access is Denied"
    __JTI_COOKIE_KEY = "_jti"

    @classmethod
    def get_username_from_request(cls, request: Request):
        return request.headers.get(cls.__AUTH_USERNAME_HEADER_KEY)

    @classmethod
    def __get_email_from_request(cls, request: Request):
        return request.headers.get(cls.__AUTH_EMAIL_HEADER_KEY)

    @classmethod
    def __get_groups_from_request(cls, request: Request):
        groups = request.headers.get(cls.__AUTH_GROUPS_HEADER_KEY)
        if groups:
            return groups.split(",")
        return []

    @classmethod
    def __get_decoded_jwt_from_request(cls, request: Request):
        authorization_header = request.headers.get(cls.__AUTH_JWT_HEADER_KEY)
        if authorization_header:
            token = authorization_header.split(None, 1)
            if len(token) == 2 and token[0] == "Bearer":
                return jwt.decode(token[1], options={"verify_signature": False})
        raise Exception("Incorrect JWT")
    
    @classmethod
    def __get_jti_from_request(cls, request: Request):
        try:
            token_payload = cls.__get_decoded_jwt_from_request(request)
            return token_payload.get("jti")
        except:
            return None

    @classmethod
    def __save_current_jti_to_session(cls, request: Request):
        jti = cls.__get_jti_from_request(request)
        if jti:
            session[cls.__JTI_COOKIE_KEY] = jti

    @classmethod
    def __get_jti_from_session(cls):
        return session.get(cls.__JTI_COOKIE_KEY)

    @classmethod
    def __remove_jti_from_session(cls):
        session.pop(cls.__JTI_COOKIE_KEY, None)

    @classmethod
    def is_session_valid(cls, request: Request):
        jti = cls.__get_jti_from_request(request)
        if jti:
            return jti == cls.__get_jti_from_session()
        return False

    @expose("/login/")
    def login(self) -> WerkzeugResponse:
        ab_security_manager = self.appbuilder.sm

        actual_username = self.get_username_from_request(request)
        jti_is_in_request = self.__get_jti_from_request(request) is not None
        
        if g.user is not None and g.user.is_authenticated:
            next_url = request.args.get("next", "")
            return redirect(get_safe_redirect(next_url))

        if actual_username and jti_is_in_request:
            try:
                self.__create_or_update_user(actual_username)
            except:
                jti_is_in_request = False
                
            user = ab_security_manager.auth_user_remote_user(actual_username)
            if user is None:
                flash(as_unicode(self.invalid_login_message), "warning")
            else:
                login_user(user)
                
                # Save actual JTI from request to app session, which is stored in cookies, in order to
                # validate later if app session in cookies is the same as platform session in request headers
                self.__save_current_jti_to_session(request)
                
                # AUTH_REMOTE_USER auth type flashes message "Access is denied" for /login/ endpoint.
                # We need to remove such flash message to avoid confusion for users
        elif not jti_is_in_request:
            jti_not_found_err_msg = lazy_gettext("Invalid login. JTI claim is not found in JWT from request.")
            flash(as_unicode(jti_not_found_err_msg), "warning")
        else:
            flash(as_unicode(self.invalid_login_message), "warning")
        next_url = request.args.get("next", "")
        return redirect(get_safe_redirect(next_url))

    def __get_or_create_custom_role(self, role_name: str):
        ab_security_manager = self.appbuilder.sm

        role = ab_security_manager.find_role(role_name)
        if role:
            return role

        alpha_role = ab_security_manager.find_role("Alpha")
        if alpha_role:
            alpha_permissions = alpha_role.permissions
            role = ab_security_manager.add_role(
                role_name,
                alpha_permissions
            )
            
            if role is None:
                raise Exception(f"Cannot create {role_name} role")

            write_db_perm = ab_security_manager.find_permission_view_menu('can_write', 'Database')
            if write_db_perm:
                role.permissions.append(write_db_perm)
                ab_security_manager.get_session.commit()
            else:
                raise Exception("'can_write Database' permission does not exist")
        else:
            raise Exception("Alpha role not found")
        
        return role

    def __create_or_update_user(self, username):
        ab_security_manager = self.appbuilder.sm
        user = ab_security_manager.find_user(username)
        
        # Get user info from request headers
        email = self.__get_email_from_request(request)
        if email is None:
            email = f'{username}@email.notfound'
        
        first_name = username
        last_name = "-"
        is_platform_admin = self.__PLATFORM_ADMIN_ROLE in self.__get_groups_from_request(request)

        token_payload = self.__get_decoded_jwt_from_request(request)
        
        first_name = token_payload.get("given_name", first_name)
        last_name = token_payload.get("family_name", last_name)
        
        if is_platform_admin:
            role_name = ab_security_manager.auth_role_admin
        else:
            # The default authentication role should be defined in helm/superset/values.yaml as AUTH_USER_REGISTRATION_ROLE
            role_name = ab_security_manager.auth_user_registration_role            
            
        user_role = self.__get_or_create_custom_role(role_name)

        if user is None and ab_security_manager.auth_user_registration:
            user = ab_security_manager.add_user(
                username=username,
                first_name=first_name,
                last_name=last_name,
                email=email,
                role = ab_security_manager.find_role(role_name)
            )
        elif user is not None:
            # User exists, check if user info is up to date and update it if necessary
            if not user_role in user.roles:
                user.roles = [user_role]
                user = ab_security_manager.update_user(user)
        return user

    @expose("/logout/")
    def logout(self):
        full_host = request.host
        
        # Delete previously saved JTI from app session in cookies
        self.__remove_jti_from_session()

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
        loaded_user = super().load_user(user_id)
        # User can be changed by platform authentication provider, so we need to check
        # if user in saved session of current app is the same as in request headers from platform.
        # In case of username is not the same, we need to return None to force re-login
        if loaded_user is not None:
            # User can be changed by platform authentication provider, so we need to check
            # if user in saved session of current app is the same as in request headers from platform.
            # In case of username is not the same, we need to return None to force re-login.
            # Also, after changing user's role in platform, we need to check if session in current app
            # is valid. To verify it, we need to compare JTI (ID of JWT) from request headers with JTI from
            # saved session in current app. If JTI is not the same, we need to return None to force re-login.
            actual_username = HeaderAuthRemoteUserView.get_username_from_request(request)
            session_is_valid = HeaderAuthRemoteUserView.is_session_valid(request)
            if loaded_user.username != actual_username or not session_is_valid:
                return None
        return loaded_user