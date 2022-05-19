package com.algaworks.algafood.auth;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	/**
	 * configura quais sao os clients que podem ter acesso ao AuthorizationServer
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60) // 6 horas
				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
				
			.and()
				.withClient("app-web")
				.secret(passwordEncoder.encode("abc555"))
				.authorizedGrantTypes("password", "refresh_token")
				.scopes("write", "read")
				
			.and() // instrospeccao
				.withClient("checktoken")
				.secret(passwordEncoder.encode("check123"))
				
			.and() // para uma aplicacao backend
				.withClient("faturamento")
				.secret(passwordEncoder.encode("faturamento123"))
				.authorizedGrantTypes("client_credentials")
				.scopes("write", "read")
				
			.and() // authorization code
			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082
			
			// para usar o PKCE, acrescente code_challenge
			// usando code_challenge_method = plain
			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082&code_challenge_method=plain&code_challenge=teste123
			
			// usando code_challenge_method = s256 tem que gerar o code challenge usando base64url(sha256(codeverifier))
			// https://tonyxu-io.github.io/pkce-generator/   -> ferramente para gerar code verifier e challenge
			// code verifier: v6uIJQsFOzwMpmRXOxuMKbDUtkSLfP7tzOEYadPHq50s9G2QCtahez9-wwwemEwLrTVzsDxK254XiKQUqg.K9KdR1uG7HDXOLS0ng7xMmIVWE9QqV_xFNiloL3QN8GmD
			// code challange: dgMy2Rxlb3MDEIq42jc_GB8Wm6Ffrv4U8umMHg603y0          -> base64url(sha256(codeverifier))
			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082&code_challenge_method=s256&code_challenge=dgMy2Rxlb3MDEIq42jc_GB8Wm6Ffrv4U8umMHg603y0
				.withClient("foodanalytics")
				.secret(passwordEncoder.encode("food123"))
				.authorizedGrantTypes("authorization_code")
				.scopes("write", "read")
				.redirectUris("http://www.foodanalytics.local:8082")
				
			.and() // Grant type implicit
			// http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://aplicacao-cliente");
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// precisa informar type Basic Auth
		//security.checkTokenAccess("isAuthenticated()");
		
		// para passar client_id e client_secret no Body adicione: .allowFormAuthenticationForClients()
		
		// nao precisa informar type Auth no http Baseic
		security.checkTokenAccess("permitAll()");
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
}
