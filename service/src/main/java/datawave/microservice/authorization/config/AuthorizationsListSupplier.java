package datawave.microservice.authorization.config;

import datawave.user.AuthorizationsListBase;
import datawave.user.DefaultAuthorizationsList;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Component
public class AuthorizationsListSupplier implements Supplier<AuthorizationsListBase<?>> {
    @Override
    public AuthorizationsListBase<?> get() {
        return new DefaultAuthorizationsList();
    }
}
