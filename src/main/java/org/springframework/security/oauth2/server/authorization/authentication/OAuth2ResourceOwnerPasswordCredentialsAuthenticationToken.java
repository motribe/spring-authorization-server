package org.springframework.security.oauth2.server.authorization.authentication;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Resource Owner Password Credentials Grant.
 *
 * @author Moluo
 * @since 0.0.1
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2ResourceOwnerPasswordCredentialsAuthenticationProvider
 */
public class OAuth2ResourceOwnerPasswordCredentialsAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	private final String username;
	private final String password;
	private final Set<String> scopes;

	/**
	 * Constructs an {@code OAuth2ResourceOwnerPasswordCredentialsAuthenticationToken} using the provided parameters.
	 * @param username the username
	 * @param password the password
	 * @param clientPrincipal the authenticated client principal
	 * @param scopes the requested scope(s)
	 * @param additionalParameters the additional parameters
	 */
	public OAuth2ResourceOwnerPasswordCredentialsAuthenticationToken(String username, String password, Authentication clientPrincipal,
																	 @Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
		Assert.hasText(username, "username cannot be empty");
		Assert.hasText(username, "password cannot be empty");
		this.username = username;
		this.password = password;
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}

	/**
	 * Returns the username.
	 *
	 * @return the username
	 */
	public String getUsername() {
		return this.username;
	}

	/**
	 * Returns the password.
	 *
	 * @return the password
	 */
	@Nullable
	public String getPassword() {
		return this.password;
	}

	/**
	 * Returns the requested scope(s).
	 *
	 * @return the requested scope(s), or an empty {@code Set} if not available
	 */
	public Set<String> getScopes() {
		return this.scopes;
	}
}
