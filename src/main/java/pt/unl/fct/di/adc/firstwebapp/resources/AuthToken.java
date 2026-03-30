package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.Timestamp;

import java.util.UUID;

public class AuthToken {
    public String tokenId;
    public String username;
    public UserRole role;
    public Timestamp issuedAt;
    public Timestamp expiresAt;

    public AuthToken() {}

    public AuthToken(String username, UserRole role) {
        this.tokenId = UUID.randomUUID().toString();
        this.username = username;
        this.role = role;
        this.issuedAt = Timestamp.now();
        this.expiresAt = Timestamp.ofTimeSecondsAndNanos(this.issuedAt.getSeconds() + 900, this.issuedAt.getNanos());
    }
}
