package com.app.SpringSecurityApp.config.security;

import com.app.SpringSecurityApp.service.UserDetailServiceImpl;
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
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

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
                    http.requestMatchers(HttpMethod.GET, "/auth/get").permitAll();

                    //Privados
                    http.requestMatchers(HttpMethod.POST, "/auth/post").hasAnyAuthority("CREATE");
                    http.requestMatchers(HttpMethod.PATCH, "/auth/patch").hasAnyAuthority("REFACTOR");

                    //Denegar acceso a cualquier endpoint no especificado
                    http.anyRequest().denyAll();

                    //Denegar acceso a cualquier endpoint no especificado si no se esta autenticado antes
                    //http.anyRequest().authenticated();
                })

                .build();

    }

    //    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//                .csrf(csrf -> csrf.disable())
//                .httpBasic(Customizer.withDefaults())
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .build();
//    }


    //Administra la autenticacion
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    //Proveedor de autenticacion
    @Bean
    public AuthenticationProvider authenticationProvider(UserDetailServiceImpl userDetailService) {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        //UserDetailService, trae usuario de BD
        provider.setUserDetailsService(userDetailService);
        return provider;
    }


    //UserDetailService con usuarios en memoria
//    @Bean
//    public UserDetailsService userDetailsService() {
//        List<UserDetails> userDetails = new ArrayList<>();
//
//        userDetails.add(User.withUsername("Gonzalo")
//                .password("1234")
//                .roles("ADMIN")
//                .authorities("READ", "CREATE")
//                .build());
//
//        userDetails.add(User.withUsername("Pepe")
//                .password("1234")
//                .roles("ADMIN")
//                .authorities("READ")
//                .build());
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }


    //Password Encoder encripta contraseñas
    @Bean
    public PasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();

        //Solo para pruebas
        // return NoOpPasswordEncoder.getInstance();
    }



}
