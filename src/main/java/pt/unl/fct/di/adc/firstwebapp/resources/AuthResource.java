package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

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
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
        }

        if (!user.getString("password").equals(data.password)) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.INVALID_CREDENTIALS)).build();
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
        AuthToken token = request.token;

        if (request.input == null || !request.input.containsKey("username")) {
            return Response.status(400).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }
        String targetUsername = request.input.get("username");
        Entity sessionExecutor = AuthUtils.validateSession(datastore, token, UserRole.USER, UserRole.BOFFICER, UserRole.ADMIN);

        if (sessionExecutor == null) {
            return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
        }

        String accessorUsername = sessionExecutor.getString("username");
        UserRole accessorRole = UserRole.valueOf(sessionExecutor.getString("role"));

        if (accessorRole != UserRole.ADMIN && !accessorUsername.equals(targetUsername)) {
            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
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
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }
}
