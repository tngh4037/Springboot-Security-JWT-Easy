package com.cos.jwtex01.config;

import com.cos.jwtex01.filter.MyFilter;
import com.cos.jwtex01.filter.MyFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// springSecurityFilterChain 에 필터를 거는게 아니라, 내가 필터를 하나 만드는 것이다.
// 그러면 우리가 만든 이 필터들은 springSecurityFilterChain 보다 이후에 실행된다. => 그래서 만약, 내가 어떤 필터를 만들고 싶은데, 이 필터가 스프링 시큐리티 보다 먼저 동작하게 만들고 싶은 경우, SecurityConfig 에 http.addFilterBefore(..) 를 통해 등록해서 걸어야 한다. ( e.g. http.addFilterBefore(new MyFilter(), SecurityContextPersistenceFilter.class); )
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter> myFilter() {
        FilterRegistrationBean<MyFilter> bean = new FilterRegistrationBean<>(new MyFilter());
        bean.addUrlPatterns("/*"); // 모든 요청에서 수행.
        bean.setOrder(1); // 낮은 번호가 필터중에서 가장 먼저 실행됨.
        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> myFilter2() {
        FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
        bean.addUrlPatterns("/*"); // 모든 요청에서 수행.
        bean.setOrder(0); // 낮은 번호가 필터중에서 가장 먼저 실행됨.
        return bean;
    }

}