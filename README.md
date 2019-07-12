# Argon2 support for spring-security-oauth2

Argon2 is a key derivation function that was selected as the winner of the Password Hashing Competition in July 2015.
With a custom PasswordEncoderFactories implementation argon2 support is enabled as a PasswordEncoder variant.

## Maven
Required Argon2 library:

```xml
<dependency>
    <groupId>de.mkammerer</groupId>
    <artifactId>argon2-jvm</artifactId>
    <version>2.5</version>
</dependency>
```

## Example UserDetailsService implementation
Referenced custom UserDetailsService implementation within DaoAuthenticationProvider (SecurityConfig):

```java
import com.jbellic.sample.service.user.domain.User;
import com.jbellic.sample.service.user.domain.UserRole;
import com.jbellic.sample.service.user.domain.UserRoleType;
import com.jbellic.sample.service.user.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class UserService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    @Autowired
    public UserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void init() {
        // just for testing purposes only
        User user = new User();
        user.setEmail("admin");
        user.setPassword(passwordEncoder.encode("password"));
        user.setUserRoles(Collections.singletonList(new UserRole(UserRoleType.ADMIN)));
        userRepository.save(user);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Optional<User> userResult = userRepository.findByEmail(email);

        if (userResult.isEmpty()) {
            throw new UsernameNotFoundException("invalid username or password");
        }

        User user = userResult.get();
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), getAuthority(user));
    }

    private List<SimpleGrantedAuthority> getAuthority(User user) {
        return user
                .getUserRoles()
                .stream()
                .map(e -> new SimpleGrantedAuthority(e.getRole().toString()))
                .collect(Collectors.toList());
    }
}
```
