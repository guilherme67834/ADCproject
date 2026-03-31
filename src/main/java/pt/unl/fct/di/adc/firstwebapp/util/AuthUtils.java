package pt.unl.fct.di.adc.firstwebapp.util;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Response;
import pt.unl.fct.di.adc.firstwebapp.exceptions.ErrorCode;
import pt.unl.fct.di.adc.firstwebapp.models.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.models.ErrorResponse;


public class AuthUtils {
    public static Entity validateSession(Datastore datastore, AuthToken token, UserRole... roles) {
        if(token == null || token.tokenId == null)
            throw new WebApplicationException(Response.ok(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build());

        Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
        Entity session = datastore.get(sessionKey);

        if(session == null)
            throw new WebApplicationException(Response.ok(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build());

        if (session.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0) {
            datastore.delete(sessionKey);
            throw new WebApplicationException(Response.ok(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build());
        }

        UserRole sessionRole = UserRole.valueOf(session.getString("role"));
        for(UserRole role : roles) {
            if(role == sessionRole) return session;
        }

        throw new WebApplicationException(Response.ok(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build());
    }
}
