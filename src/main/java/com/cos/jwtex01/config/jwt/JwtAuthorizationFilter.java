package com.cos.jwtex01.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwtex01.config.auth.PrincipalDetails;
import com.cos.jwtex01.model.User;
import com.cos.jwtex01.repository.UserRepository;

// [인가]
// 시큐리티가 filter 를 가지고 있는데, 그 필터중에 BasicAuthenticationFilter 라는 것이 있다.
// 인증이나 권한이 필요한 특정 주소를 요청했을 때, 위 필터를 무조건 타게 되어있다.
// 만약에 인증이나 권한이 필요한 주소가 아니라면 이 필터를 타지 않는다.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
	
	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		System.out.println("인증이나 권한이 필요한 주소가 요청 됨.");

		String header = request.getHeader(JwtProperties.HEADER_STRING);
		if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		System.out.println("header : " + header);

		// ================================================
		// ==== JWT 토큰을 검증해서 정상적인 사용자인지 확인 ====
		// ================================================
		String token = request.getHeader(JwtProperties.HEADER_STRING)
				.replace(JwtProperties.TOKEN_PREFIX, "");
		
		// JWT 토큰 검증 (이게 인증이기 때문에 AuthenticationManager도 필요 없음)
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token) // 서명
				.getClaim("username").asString(); // 서명이 정상적으로 되면 username 을 가져온다.
		
		if (username != null) {
			User user = userRepository.findByUsername(username);
			
			// 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해 
			// 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장! ( 17:48 세션에 담지 않으면 SecurityConfig 에 설정한 권한 관리가 안됨. 스프링 시큐리티는 세션을 기반으로 권한관리를 한다. 만약에 이런 권한관리를 안할거면 굳이 세션에 담을 필요는 없다. 세션에 담는 이유는 권한 관리를 위해서이다. (굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리때문에 세션에 넣어준다.) )
			PrincipalDetails principalDetails = new PrincipalDetails(user);
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(
							principalDetails, //나중에 컨트롤러에서 DI해서 쓸 때 사용하기 편함.
							null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
							principalDetails.getAuthorities());
			
			// 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}

		chain.doFilter(request, response);
	}
	
}

// 참고) https://www.inflearn.com/questions/714149/jwt-token-%EA%B5%AC%ED%98%84%EC%97%90%EC%84%9C-session-%EC%9D%84-%EC%82%AC%EC%9A%A9%ED%95%9C%EB%8B%A4
// 참고) https://www.inflearn.com/questions/740712/session-%EA%B3%BC-securitycontext%EC%97%90-%EA%B4%80%EB%A0%A8%EB%90%9C-%EC%A7%88%EB%AC%B8%EC%9E%85%EB%8B%88%EB%8B%A4
