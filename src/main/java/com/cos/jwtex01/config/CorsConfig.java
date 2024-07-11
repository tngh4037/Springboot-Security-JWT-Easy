package com.cos.jwtex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true); // 내 서버가 (json 데이터 등을) 응답을 할 때, 그 응답을 자바스크립트가 받아서 처리할 수 있게 할지를 설정하는 것. ( 만약 false 로 설정하면, 자바스크립트로 어떤 요청을 했을 때, 응답이 오지않음 )
      config.addAllowedOrigin("*"); // 모든 ip에 응답을 허용하겠다. e.g. http://domain1.com
      config.addAllowedHeader("*"); // 모든 header에 응답을 허용하겠다.
      config.addAllowedMethod("*"); // 모든 post,get,put,delete,patch 요청을 허용하겠다.

      source.registerCorsConfiguration("/api/**", config); // "/api/**" 로 들어오는 모든 요청은 config 설정을 따른다.
      return new CorsFilter(source);
   }

}
