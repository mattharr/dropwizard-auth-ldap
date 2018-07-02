package com.yammer.dropwizard.authenticator;

import java.util.Optional;

import io.dropwizard.auth.basic.BasicCredentials;

public interface LdapAuthenticationProvider {

	boolean canAuthenticate();

	boolean authenticate(BasicCredentials credentials) throws io.dropwizard.auth.AuthenticationException;

	Optional<User> authenticateAndReturnPermittedGroups(BasicCredentials credentials)
			throws io.dropwizard.auth.AuthenticationException;

}