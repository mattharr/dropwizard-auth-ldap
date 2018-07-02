package com.yammer.dropwizard.authenticator;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;

import java.util.Optional;

import static com.google.common.base.Preconditions.checkNotNull;

public class UserResourceAuthenticator implements Authenticator<BasicCredentials, User> {

    private final LdapAuthenticationProvider ldapAuthenticator;

    public UserResourceAuthenticator(LdapAuthenticationProvider ldapAuthenticator) {
        this.ldapAuthenticator = checkNotNull(ldapAuthenticator);
    }

    @Override
    public Optional<User> authenticate(BasicCredentials credentials) throws AuthenticationException {
        return ldapAuthenticator.authenticateAndReturnPermittedGroups(credentials);
    }
}