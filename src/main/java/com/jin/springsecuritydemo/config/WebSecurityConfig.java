package com.jin.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.activation.DataSource;

/**
 * @author wu.jinqing
 * @date 2020年07月02日
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable();
            super.configure(http);
        }



//    @Override
//    public void configure(AuthenticationManagerBuilder builder) {
//        builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
//                .password("secret").roles("USER");
//    }

    /**
     * In a Spring Boot application you can @Autowired the global one into another bean, but you can’t do that with the local one unless you explicitly expose it yourself.
     */
//    @Autowired
//    public void initialize(AuthenticationManagerBuilder builder, DataSource dataSource) {
//        builder.jdbcAuthentication().dataSource(dataSource).withUser("dave")
//                .password("secret").roles("USER");
//    }

//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                    .antMatchers("/","/home").hasRole("USER")
////                    .permitAll()
//                    .anyRequest()
//                    .authenticated()
//                    .and()
//                .formLogin()
//                    .loginPage("/login")
//                    .permitAll()
//                    .and()
//                .logout()
//                    .permitAll();
//    }

//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                // ...
//                .authorizeRequests(authorize -> authorize
//                        .anyRequest().authenticated()
//                );
//    }


//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                // ...
//                .authorizeRequests(authorize -> authorize
//                        .mvcMatchers("/resources/**", "/signup", "/about").permitAll()
//                        .mvcMatchers("/admin/**").hasRole("ADMIN")
//                        .mvcMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
//                        .anyRequest().denyAll()
//                );
//    }



//    public class WebSecurity {
//        public boolean check(Authentication authentication, HttpServletRequest request) {
//                ...
//        }
//    }


//    http
//        .authorizeRequests(authorize -> authorize
//            .antMatchers("/user/**").access("@webSecurity.check(authentication,request)")
//        ...
//                )

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        UserDetails user =
                User.withDefaultPasswordEncoder()
                        .username("user")
                        .password("password")
                        .roles("USER")
                        .build();

        return new InMemoryUserDetailsManager(user);
    }
}
