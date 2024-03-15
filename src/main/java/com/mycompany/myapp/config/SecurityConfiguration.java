package com.mycompany.myapp.config;

import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.web.util.matcher.AntPathRequestMatcher.antMatcher;

import com.mycompany.myapp.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;
import tech.jhipster.config.JHipsterConstants;
import tech.jhipster.config.JHipsterProperties;
import tech.jhipster.web.filter.CookieCsrfFilter;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

    private final Environment env;

    private final JHipsterProperties jHipsterProperties;

    private final RememberMeServices rememberMeServices;

    public SecurityConfiguration(Environment env, RememberMeServices rememberMeServices, JHipsterProperties jHipsterProperties) {
        this.env = env;
        this.rememberMeServices = rememberMeServices;
        this.jHipsterProperties = jHipsterProperties;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, MvcRequestMatcher.Builder mvc) throws Exception {
        http
            .cors(withDefaults())
            .csrf(csrf ->
                csrf
                    .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                    // See https://stackoverflow.com/q/74447118/65681
                    .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .addFilterAfter(new CookieCsrfFilter(), BasicAuthenticationFilter.class)
            .authorizeHttpRequests(authz ->
                // prettier-ignore
                authz
                    .requestMatchers(mvc.pattern("/api/authenticate")).permitAll()
                    .requestMatchers(mvc.pattern("/api/register")).permitAll()
                    .requestMatchers(mvc.pattern("/api/activate")).permitAll()
                    .requestMatchers(mvc.pattern("/api/account/reset-password/init")).permitAll()
                    .requestMatchers(mvc.pattern("/api/account/reset-password/finish")).permitAll()
                    .requestMatchers(mvc.pattern("/api/admin/**")).hasAuthority(AuthoritiesConstants.ADMIN)
                    .requestMatchers(mvc.pattern("/api/**")).authenticated()
                    .requestMatchers(mvc.pattern("/v3/api-docs/**")).hasAuthority(AuthoritiesConstants.ADMIN)
                    .requestMatchers(mvc.pattern("/management/health")).permitAll()
                    .requestMatchers(mvc.pattern("/management/health/**")).permitAll()
                    .requestMatchers(mvc.pattern("/management/info")).permitAll()
                    .requestMatchers(mvc.pattern("/management/prometheus")).permitAll()
                    .requestMatchers(mvc.pattern("/management/**")).hasAuthority(AuthoritiesConstants.ADMIN)
            )
            .rememberMe(rememberMe ->
                rememberMe
                    .rememberMeServices(rememberMeServices)
                    .rememberMeParameter("remember-me")
                    .key(jHipsterProperties.getSecurity().getRememberMe().getKey())
            )
            .exceptionHandling(exceptionHanding ->
                exceptionHanding.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    new OrRequestMatcher(antMatcher("/api/**"))
                )
            )
            .formLogin(formLogin ->
                formLogin
                    .loginPage("/")
                    .loginProcessingUrl("/api/authentication")
                    .successHandler((request, response, authentication) -> response.setStatus(HttpStatus.OK.value()))
                    .failureHandler((request, response, exception) -> response.setStatus(HttpStatus.UNAUTHORIZED.value()))
                    .permitAll()
            )
            .logout(logout ->
                logout.logoutUrl("/api/logout").logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler()).permitAll()
            );
        if (env.acceptsProfiles(Profiles.of(JHipsterConstants.SPRING_PROFILE_DEVELOPMENT))) {
            http
                .csrf(csrf -> csrf.ignoringRequestMatchers(antMatcher("/h2-console/**")))
                .authorizeHttpRequests(authz -> authz.requestMatchers(antMatcher("/h2-console/**")).permitAll());
        }
        return http.build();
    }

    @Bean
    MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
        return new MvcRequestMatcher.Builder(introspector);
    }
}
