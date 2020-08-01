package com.cos.springsocial.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.cos.springsocial.service.CustomOauth2UserService;

import static com.cos.springsocial.config.SocialType.*;


@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.authorizeRequests()
		            .antMatchers("/","/oauth2/**","/login/**","/console/**")
		            .permitAll()
		            .antMatchers("/facebook").hasAnyAuthority(FACEBOOK.getRoleType())
		            .anyRequest().authenticated()
		          .and()
		            .oauth2Login()
		            .userInfoEndpoint().userService(new CustomOauth2UserService())
		          .and()
		            .defaultSuccessUrl("/loginSuccess")
		            .failureUrl("/loginFailure")
		          .and()
		            .exceptionHandling()
		            .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")); 
		
		            
	}
	
	private ClientRegistration getRegistration(OAuth2ClientProperties clientProperties,String client) {
		if("facebook".equals(client)) {
			OAuth2ClientProperties.Registration registration = clientProperties.getRegistration().get("facebook");
			return CommonOAuth2Provider.FACEBOOK.getBuilder(client)
					.clientId(registration.getClientId())
					.clientSecret(registration.getClientSecret())
					.userInfoUri("https://graph.facebook.com/me?fields=id,name,email,link")
					.scope("email")
					.build();
		}
		return null;
		
	}
	
	
}
