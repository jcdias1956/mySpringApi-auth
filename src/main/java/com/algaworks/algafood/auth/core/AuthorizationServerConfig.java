package com.algaworks.algafood.auth.core;

import java.util.Arrays;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
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
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Autowired
	private JwtKeyStoreProperties jwtKeyStoreProperties;
	
	// injection Connection factory of Redis - SGBD noSql
//	@Autowired
//	private RedisConnectionFactory redisConnectionFactory;
	
	@Autowired
	private DataSource dataSource;
	
	/**
	 * configura quais sao os clients que podem ter acesso ao AuthorizationServer
	 */
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.jdbc(dataSource);
			

//			.inMemory()
//				.withClient("algafood-web")
//				.secret(passwordEncoder.encode("web123"))
//				.authorizedGrantTypes("password", "refresh_token")
//				.scopes("WRITE", "READ")
//				.accessTokenValiditySeconds(6 * 60 * 60) // 6 horas
//				.refreshTokenValiditySeconds(60 * 24 * 60 * 60) // 60 dias
//				
//			.and()
//				.withClient("app-web")
//				.secret(passwordEncoder.encode("abc555"))
//				.authorizedGrantTypes("password", "refresh_token")
//				.scopes("WRITE", "READ")
//				
//			.and() // instrospeccao usado no Resource Server application.properties
//				.withClient("checktoken")
//				.secret(passwordEncoder.encode("check123"))
//				
//			.and() // para uma aplicacao backend
//				.withClient("faturamento")
//				.secret(passwordEncoder.encode("faturamento123"))
//				.authorizedGrantTypes("client_credentials")
//				.scopes("WRITE", "READ")
//				
//			.and() // authorization code
//			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082
//			
//			// para usar o PKCE, acrescente code_challenge
//			// usando code_challenge_method = plain
//			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082&code_challenge_method=plain&code_challenge=teste123
//			
//			// usando code_challenge_method = s256 tem que gerar o code challenge usando base64url(sha256(codeverifier))
//			// https://tonyxu-io.github.io/pkce-generator/   -> ferramente para gerar code verifier e challenge
//			// code verifier: v6uIJQsFOzwMpmRXOxuMKbDUtkSLfP7tzOEYadPHq50s9G2QCtahez9-wwwemEwLrTVzsDxK254XiKQUqg.K9KdR1uG7HDXOLS0ng7xMmIVWE9QqV_xFNiloL3QN8GmD
//			// code challange: dgMy2Rxlb3MDEIq42jc_GB8Wm6Ffrv4U8umMHg603y0          -> base64url(sha256(codeverifier))
//			// http://localhost:8081/oauth/authorize?response_type=code&client_id=foodanalytics&state=abc&redirect_uri=http://www.foodanalytics.local:8082&code_challenge_method=s256&code_challenge=dgMy2Rxlb3MDEIq42jc_GB8Wm6Ffrv4U8umMHg603y0
//				.withClient("foodanalytics")
//				.secret(passwordEncoder.encode("food123"))
//				.authorizedGrantTypes("authorization_code")
//				.scopes("WRITE", "READ")
//				.redirectUris("http://www.foodanalytics.local:8082")
//				
//			.and() // Grant type implicit
//			// http://localhost:8081/oauth/authorize?response_type=token&client_id=webadmin&state=abc&redirect_uri=http://aplicacao-cliente
//				.withClient("webadmin")
//				.authorizedGrantTypes("implicit")
//				.scopes("WRITE", "READ")
//				.redirectUris("http://aplicacao-cliente");
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		// precisa informar type Basic Auth
		//security.checkTokenAccess("isAuthenticated()");
		
		// para passar client_id e client_secret no Body adicione: .allowFormAuthenticationForClients()
		
		// nao precisa informar type Auth no http Basic - so fazer o request http 
		security.checkTokenAccess("permitAll()") // para checar o token
			.tokenKeyAccess("permitAll()") // para extrair a chave publica
			.allowFormAuthenticationForClients();
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		var enhancerChain = new TokenEnhancerChain();
		enhancerChain.setTokenEnhancers(Arrays.asList(new JwtCustomClaimsTokenEnhancer(), jwtAccessTokenConverter()));
		
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			//.tokenStore(redisTokenStore()) // usando o redis
			.accessTokenConverter(jwtAccessTokenConverter()) // usando para o jwt
			.tokenEnhancer(enhancerChain)
			// configurar um handler para permitir aprovacao granular dos escopos
			.approvalStore(approvalStore(endpoints.getTokenStore())) // para obter o fluxo de aprovacao (WRITE,READ) com o uso do jwt
			.tokenGranter(tokenGranter(endpoints));
	}
	
	private ApprovalStore approvalStore(TokenStore tokenStore) {
		var approvalStore = new TokenApprovalStore();
		approvalStore.setTokenStore(tokenStore);
		
		return approvalStore;
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		var jwtAccessTokenConverter = new JwtAccessTokenConverter();
		
		// para assinatura simetrica e tem que ser a mesma no Resource Server (Api)
//		jwtAccessTokenConverter.setSigningKey("xSZdhkYKWGFbPQFq0mi6bYd2wtqfqhBa");
		
		// para assinatura assimetrica usando o keystore algafood gerado pelo keytool
		// Gerando um arquivo JKS com um par de chaves
		// 		keytool -genkeypair -alias algafood -keyalg RSA -keypass 123456 -keystore algafood.jks -storepass 123456 -validity 3650
		//
		// Listando as entradas de um arquivo JKS
		// 		keytool -list -keystore algafood.jks
		

		//Gerando o certificado
		
		//keytool -export -rfc -alias algafood -keystore algafood.jks -file algafood-cert.pem
		
		//Gerando a chave pública
		
		//openssl x509 -pubkey -noout -in algafood-cert.pem > algafood-pkey.pem


		
		var jksResource = new ClassPathResource(jwtKeyStoreProperties.getPath());
		var keyStorePass = jwtKeyStoreProperties.getPassword();
		var keyPairAlias = jwtKeyStoreProperties.getKeypairAlias();
		
		var keyStoreKeyFactory = new KeyStoreKeyFactory(jksResource, keyStorePass.toCharArray());
		var keyPair = keyStoreKeyFactory.getKeyPair(keyPairAlias);
		
		jwtAccessTokenConverter.setKeyPair(keyPair);
		

		return jwtAccessTokenConverter;
	}
	// usado com o redis
//	private TokenStore redisTokenStore() {
//		return new RedisTokenStore(redisConnectionFactory);
//	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		var pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		var granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}
	
}
