package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import pt.unl.fct.di.adc.firstwebapp.data.RegisterData;
import pt.unl.fct.di.adc.firstwebapp.exceptions.ErrorCode;
import pt.unl.fct.di.adc.firstwebapp.models.AuthToken;
import pt.unl.fct.di.adc.firstwebapp.models.ErrorResponse;
import pt.unl.fct.di.adc.firstwebapp.models.InboundData;
import pt.unl.fct.di.adc.firstwebapp.models.OutboundResponse;
import pt.unl.fct.di.adc.firstwebapp.util.AuthUtils;
import pt.unl.fct.di.adc.firstwebapp.util.UserRole;

import java.util.*;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class AuthResource {

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public AuthResource() { }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response login(InboundData<RegisterData> request) {
        RegisterData data = request.input;

        if (data == null || data.username == null || data.password == null) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
        }

        if (!user.getString("password").equals(data.password)) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_CREDENTIALS)).build();
        }

        UserRole role = UserRole.valueOf(user.getString("role"));
        AuthToken token = new AuthToken(user.getKey().getName(), role);

        Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
        Entity session = Entity.newBuilder(sessionKey)
                .set("username", token.username)
                .set("role", token.role.name())
                .set("issuedAt", token.issuedAt)
                .set("expiresAt", token.expiresAt)
                .build();
        datastore.put(session);

        return Response.ok(OutboundResponse.success(Map.of("token", token))).build();
    }

    @POST
    @Path("/logout")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response logout(InboundData<Map<String, String>> request) {
        if (request.input == null || !request.input.containsKey("username")) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }
        String targetUsername = request.input.get("username");
        Entity sessionExecutor = AuthUtils.validateSession(datastore, request.token, UserRole.USER, UserRole.BOFFICER, UserRole.ADMIN);
        String accessorUsername = sessionExecutor.getString("username");
        UserRole accessorRole = UserRole.valueOf(sessionExecutor.getString("role"));

        if (accessorRole != UserRole.ADMIN && !accessorUsername.equals(targetUsername)) {
            return Response.ok(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        try {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Session")
                    .setFilter(StructuredQuery.PropertyFilter.eq("username", targetUsername))
                    .build();

            QueryResults<Entity> results = datastore.run(query);

            List<Key> keysToDelete = new ArrayList<>();
            while (results.hasNext()) {
                keysToDelete.add(results.next().getKey());
            }

            if (!keysToDelete.isEmpty()) {
                datastore.delete(keysToDelete.toArray(new Key[0]));
            }

            return Response.ok(OutboundResponse.success(Map.of("message", "Logout successful")))
                    .build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }
}
