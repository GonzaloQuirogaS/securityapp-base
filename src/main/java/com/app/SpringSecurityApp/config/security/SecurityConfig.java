package com.app.SpringSecurityApp.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//
//                //Cross-site request forgery, vulnerabilidad web en apps con formularios y manejo de sesiones.
//                .csrf(csrf -> csrf.disable())
//
//                //Se utiliza para cuando se loguea con usuario y contraseña y no TOKEN
//                .httpBasic(Customizer.withDefaults())
//
//                //Manejo de sesion, STATELESS para que no expire la sesion ni se guarde en memoria
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//
//                //Autorizar endpoints y peticiones
//                .authorizeHttpRequests(http -> {
//
//                    //Publicos
//                    http.requestMatchers(HttpMethod.GET, "/auth/hello").permitAll();
//
//                    //Privados
//                    http.requestMatchers(HttpMethod.GET, "/auth/hello-secured").hasAuthority("READ");
//
//                    //Denegar acceso a cualquier endpoint no especificado
//                    http.anyRequest().denyAll();
//
//                    //Denegar acceso a cualquier endpoint no especificado si no se esta autenticado antes
//                    //http.anyRequest().authenticated();
//                })
//
//                .build();
//
//    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity

                //Cross-site request forgery, vulnerabilidad web en apps con formularios y manejo de sesiones.
                .csrf(csrf -> csrf.disable())

                //Se utiliza para cuando se loguea con usuario y contraseña y no TOKEN
                .httpBasic(Customizer.withDefaults())

                //Manejo de sesion, STATELESS para que no expire la sesion ni se guarde en memoria
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                //Autorizar endpoints y peticiones
                .authorizeHttpRequests(http -> {

                    //Publicos
                    http.requestMatchers(HttpMethod.GET, "/auth/hello").permitAll();

                    //Privados
                    http.requestMatchers(HttpMethod.GET, "/auth/hello-secured").hasAuthority("READ");

                    //Denegar acceso a cualquier endpoint no especificado
                    http.anyRequest().denyAll();

                    //Denegar acceso a cualquier endpoint no especificado si no se esta autenticado antes
                    //http.anyRequest().authenticated();
                })

                .build();

    }
    //Administra la autenticacion
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //Proveedor de autenticacion
    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(userDetailsService());

        return provider;
    }

    //UserDetailService, trae usuario de BD
    @Bean
    public UserDetailsService userDetailsService() {
        List<UserDetails> userDetails = new ArrayList<>();

        userDetails.add(User.withUsername("Gonzalo")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ", "CREATE")
                .build());

        userDetails.add(User.withUsername("Pepe")
                .password("1234")
                .roles("ADMIN")
                .authorities("READ")
                .build());

        return new InMemoryUserDetailsManager(userDetails);
    }

    //Password Encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


}
