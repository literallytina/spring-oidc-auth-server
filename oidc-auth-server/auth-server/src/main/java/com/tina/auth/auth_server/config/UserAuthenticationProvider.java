package com.tina.auth.auth_server.config;

import com.tina.auth.auth_server.entities.AuthUser;
import com.tina.auth.auth_server.repositories.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.CharBuffer;
import java.util.Collections;
import java.util.Optional;

@Slf4j
@Component
public class UserAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String login = authentication.getName();
        String password = authentication.getCredentials().toString();

        if (userRepository == null) {
            throw new IllegalStateException("UserRepository is not initialized.");
        }

        Optional<AuthUser> oUser = userRepository.findByLogin(login);

        if (oUser.isEmpty()) {
            return null;
        }

        AuthUser user = oUser.get();

        if (passwordEncoder.matches(CharBuffer.wrap(password), user.getPassword())) {
            log.info(UsernamePasswordAuthenticationToken.authenticated(login, password, Collections.emptyList()).toString());
            return UsernamePasswordAuthenticationToken.authenticated(login, password, Collections.emptyList());
        }

        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.equals(authentication);
    }
}
