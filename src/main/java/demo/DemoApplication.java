package demo;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;


@SpringBootApplication
@RestController
public class DemoApplication {

    @RequestMapping("/user")
    public Principal user(Principal user) {
        return user;
    }

    @RequestMapping("/resource")
    public Map<String, Object> home() {
        Map<String, Object> model = new HashMap<String, Object>();
        String log = "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.u.m.MediaTypeRequestMatcher      : Processing application/json\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.u.m.MediaTypeRequestMatcher      : application/json .isCompatibleWith application/json = true\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.u.matcher.NegatedRequestMatcher  : matches = false\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.util.matcher.AndRequestMatcher   : Did not match\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.s.HttpSessionRequestCache        : Request not saved as configured RequestMatcher did not match\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] o.s.s.w.a.ExceptionTranslationFilter     : Calling Authentication entry point.\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] s.w.a.DelegatingAuthenticationEntryPoint : Trying to match using RequestHeaderRequestMatcher [expectedHeaderName=X-Requested-With, expectedHeaderValue=XMLHttpRequest]\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] s.w.a.DelegatingAuthenticationEntryPoint : Match found! Executing org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer$HttpStatusEntryPoint@44bfe13d\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] w.c.HttpSessionSecurityContextRepository : SecurityContext is empty or contents are anonymous - context will not be stored in HttpSession.\n"
            + "2015-04-22 09:44:24.025 DEBUG 5340 --- [nio-8080-exec-6] s.s.w.c.SecurityContextPersistenceFilter : SecurityContextHolder now cleared, as request processing completed";
        
        model.put("id", log);
        model.put("content", "Hello World");
        return model;
    }

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Configuration
    @Order(SecurityProperties.ACCESS_OVERRIDE_ORDER)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.httpBasic().and().authorizeRequests()
                    .antMatchers("/index.html", "/home.html", "/login.html", "/").permitAll().anyRequest()
                    .authenticated().and().csrf()
                    .csrfTokenRepository(csrfTokenRepository()).and()
                    .addFilterAfter(csrfHeaderFilter(), CsrfFilter.class);
        }

        private Filter csrfHeaderFilter() {
            return new OncePerRequestFilter() {
                @Override
                protected void doFilterInternal(HttpServletRequest request,
                        HttpServletResponse response, FilterChain filterChain)
                        throws ServletException, IOException {
                    CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class
                            .getName());
                    if (csrf != null) {
                        Cookie cookie = WebUtils.getCookie(request, "XSRF-TOKEN");
                        String token = csrf.getToken();
                        if (cookie == null || token != null
                                && !token.equals(cookie.getValue())) {
                            cookie = new Cookie("XSRF-TOKEN", token);
                            cookie.setPath("/");
                            response.addCookie(cookie);
                        }
                    }
                    filterChain.doFilter(request, response);
                }
            };
        }

        private CsrfTokenRepository csrfTokenRepository() {
            HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
            repository.setHeaderName("X-XSRF-TOKEN");
            return repository;
        }
    }
}
