package com.yammer.dropwizard.authenticator;

import java.io.IOException;
import java.util.Hashtable;
import java.util.Optional;
import java.util.Set;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import com.google.common.collect.ImmutableSet;
import io.dropwizard.auth.basic.BasicCredentials;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jetty.util.security.Password;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;

public class LdapSearchingAuthenticator implements LdapAuthenticationProvider {
	private static final Logger LOG = LoggerFactory.getLogger(LdapSearchingAuthenticator.class);
	protected final LdapConfiguration configuration;

	public LdapSearchingAuthenticator(LdapConfiguration configuration) {
		this.configuration = checkNotNull(configuration);
	}

	private static String sanitizeEntity(String name) {
		return name.replaceAll("[^A-Za-z0-9-_.]", "");
	}

	public boolean canAuthenticate() {
		try {
			new AutoclosingLdapContext(contextConfiguration(), configuration.getNegotiateTls()).close();
			return true;
		} catch (Exception err) {
			// can't authenticate
		}
		return false;
	}

	private boolean filterByGroup(AutoclosingLdapContext context, String userDn)
			throws NamingException {
		final Set<String> restrictedToGroups = configuration.getRestrictToGroups();
		if (restrictedToGroups.isEmpty()) {
			return true;
		}

		final StringBuilder groupFilter = new StringBuilder();
		for (String group : restrictedToGroups) {
			final String sanitizedGroup = sanitizeEntity(group);
			groupFilter.append(String.format("(%s=%s)", configuration.getGroupNameAttribute(), sanitizedGroup));
		}

		final String filter = String.format("(&(%s=%s)(|%s))", configuration.getGroupMembershipAttribute(),
				userDn, groupFilter.toString());

		final NamingEnumeration<SearchResult> result = context.search(configuration.getGroupFilter(), filter,
				new SearchControls());
		try {
			return result.hasMore();
		} finally {
			result.close();
		}
	}

	private Set<String> getGroupMembershipsIntersectingWithRestrictedGroups(AutoclosingLdapContext context,
			String userName) throws NamingException, io.dropwizard.auth.AuthenticationException {

		final String filter = String.format("(&(%s=%s)(objectClass=%s))", configuration.getGroupMembershipAttribute(),
				userName, configuration.getGroupClassName());
		final NamingEnumeration<SearchResult> result = context.search(configuration.getGroupFilter(), filter,
				new SearchControls(SearchControls.SUBTREE_SCOPE, 0, 0,
						new String[] { configuration.getGroupNameAttribute() }, false, false));
		LOG.debug("Completed group search query");
		ImmutableSet.Builder<String> overlappingGroups = ImmutableSet.builder();
		try {
			while (result.hasMore()) {
				SearchResult next = result.next();
				if (next.getAttributes() != null
						&& next.getAttributes().get(configuration.getGroupNameAttribute()) != null) {
					String group = (String) next.getAttributes().get(configuration.getGroupNameAttribute()).get(0);
					if (configuration.getRestrictToGroups().isEmpty()
							|| configuration.getRestrictToGroups().contains(group)) {
						overlappingGroups.add(group);
					}
				}
			}
			return overlappingGroups.build();
		} finally {
			result.close();
		}
	}

	public boolean authenticate(BasicCredentials credentials) throws io.dropwizard.auth.AuthenticationException {
		final String sanitizedUsername = sanitizeEntity(credentials.getUsername());
		final String userDn = searchForUserDn(sanitizedUsername);
		try {
			try (AutoclosingLdapContext context = buildLdapContext(userDn, credentials.getPassword())) {
				return filterByGroup(context, userDn);
			}
		} catch (AuthenticationException ae) {
			LOG.debug("{} failed to authenticate. {}", sanitizedUsername, ae);
		} catch (IOException | NamingException err) {
			throw new io.dropwizard.auth.AuthenticationException(
					String.format("LDAP Authentication failure (username: %s)", sanitizedUsername), err);
		}
		return false;
	}

	private AutoclosingLdapContext buildLdapContext(String sanitizedUsername, String password)
			throws IOException, NamingException {
		final Hashtable<String, String> env = contextConfiguration();

		env.put(Context.SECURITY_PRINCIPAL, sanitizedUsername);
		env.put(Context.SECURITY_CREDENTIALS, password);

		return new AutoclosingLdapContext(env, configuration.getNegotiateTls());
	}


	private String searchForUserDn(String username) throws io.dropwizard.auth.AuthenticationException {
		LOG.debug("Searching for user");
		try (AutoclosingLdapContext context = buildLdapContext(configuration.getConnectionUsername(),
				new Password(configuration.getConnectionPassword()).toString())) {
			final String filter = String.format("(&(%s=%s)(objectClass=%s))", configuration.getUserNameAttribute(),
					username, configuration.getUserClassName());
			final NamingEnumeration<SearchResult> result = context.search(configuration.getUserFilter(), filter,
					new SearchControls());

			String userDn = "";
			try {
				while (result.hasMore()) {
					SearchResult next = result.next();
					if (next.getAttributes() != null && next.getAttributes().get("distinguishedName") != null) {
						userDn = (String) next.getAttributes().get("distinguishedName").get(0);
						break;
					}
				}
				if (StringUtils.isEmpty(userDn)) {
					throw new AuthenticationException("Could not find user " + username);
				} else {
					return userDn;
				}
			} finally {
				result.close();
			}
		} catch (NamingException | IOException e) {
			throw new io.dropwizard.auth.AuthenticationException(
					String.format("LDAP Authentication failure (username: %s)", username), e);
		}
	}

	public Optional<User> authenticateAndReturnPermittedGroups(BasicCredentials credentials)
			throws io.dropwizard.auth.AuthenticationException {
		final String sanitizedUsername = sanitizeEntity(credentials.getUsername());
		final String userDn = searchForUserDn(sanitizedUsername);
		try {
			try (AutoclosingLdapContext context = buildLdapContext(userDn, credentials.getPassword())) {
				LOG.debug("Connected, searching for groups");
				Set<String> groupMemberships = getGroupMembershipsIntersectingWithRestrictedGroups(context,
						userDn);
				if (!groupMemberships.isEmpty()) {
					return Optional.of(new User(sanitizedUsername, groupMemberships));
				}
			}
		} catch (AuthenticationException ae) {
			LOG.debug("{} failed to authenticate. {}", sanitizedUsername, ae);
		} catch (IOException | NamingException err) {
			throw new io.dropwizard.auth.AuthenticationException(
					String.format("LDAP Authentication failure (username: %s)", sanitizedUsername), err);
		}
		return Optional.empty();
	}

	private Hashtable<String, String> contextConfiguration() {
		final Hashtable<String, String> env = new Hashtable<>();

		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, configuration.getUri().toString());
		env.put("com.sun.jndi.ldap.connect.timeout",
				String.valueOf(configuration.getConnectTimeout().toMilliseconds()));
		env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(configuration.getReadTimeout().toMilliseconds()));
		env.put("com.sun.jndi.ldap.connect.pool", "true");

		return env;
	}
}
