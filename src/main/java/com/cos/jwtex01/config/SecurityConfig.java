package com.cos.jwtex01.config;



import com.cos.jwtex01.filter.MyFilter;
import com.cos.jwtex01.filter.MyFilter3;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.cos.jwtex01.config.jwt.JwtAuthenticationFilter;
import com.cos.jwtex01.config.jwt.JwtAuthorizationFilter;
import com.cos.jwtex01.repository.UserRepository;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@EnableWebSecurity // 시큐리티 활성화 -> 기본 스프링 필터체인에 등록
public class SecurityConfig extends WebSecurityConfigurerAdapter{	
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private CorsConfig corsConfig;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// http.addFilter(new MyFilter()); // error occurred ( 니가 만든 Filter 타입의 필터는 springSecurityFilterChain 에 등록이 안돼. 굳이 걸고싶으면 내 시큐리티 필터 중 특정 필터의 시작 전에 걸든 후에 걸어. (Consider using addFilterBefore or addFilterAfter instead.) ) => 해결: 바로 밑에줄
		// http.addFilterBefore(new MyFilter(), BasicAuthenticationFilter.class); // 이렇게 걸려면 springSecurityFilterChain 에 어떤 필터들이(SecurityContextPersistenceFilter ~ FilterSecurityInterceptor) 등록는지 다 알고, 대상을 지정해야 한다. => 그리고 filter를 걸때, 이렇게 굳이 시큐리티 필터 체인에 걸지 않아도 된다. 따로 필터를 걸 수도 있다. ( FilterConfig 참고 )
		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);

		http
				.addFilter(corsConfig.corsFilter())
				.csrf().disable()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션을 사용하지 않겠다. (stateless 서버로 만들겠다.)
			.and()
				.formLogin().disable()
				.httpBasic().disable()
				
				.addFilter(new JwtAuthenticationFilter(authenticationManager()))
				.addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository))
				.authorizeRequests()
				.antMatchers("/api/v1/user/**")
					.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/manager/**")
					.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
				.antMatchers("/api/v1/admin/**")
					.access("hasRole('ROLE_ADMIN')")
				.anyRequest().permitAll();
	}
}

// [ JWT 서버를 만들때 기본 고정 포맷 ]
//		http
//			.csrf().disable()
//			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
//		.and()
//			.formLogin().disable()
//			.httpBasic().disable()


// [ httpBasic() ]
// header에 다가 Authorization 이라는 키 값에 인증 정보(아이디, 패스워드)를 넣어서 전달하는 방식.
// 참고) 매 요청마다 id, password 를 달고 요청한다. ( 보안의 위험이 있다. 따라서 반드시 HTTPS 를 사용해서 암호화 되도록 해야한다. )
// 참고) header Authorization 에 (id, password를 통해서 만든) 토큰을 넣는 방식 -> Bearer 인증 방식.
//
// 참고) Basic 인증이란? Bearer 인증이란?
//   : https://velog.io/@tosspayments/Basic-%EC%9D%B8%EC%A6%9D%EA%B3%BC-Bearer-%EC%9D%B8%EC%A6%9D%EC%9D%98-%EB%AA%A8%EB%93%A0-%EA%B2%83#basic-%EC%9D%B8%EC%A6%9D%EC%9D%B4%EB%9E%80