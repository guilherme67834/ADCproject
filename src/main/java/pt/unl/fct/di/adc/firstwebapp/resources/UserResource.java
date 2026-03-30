package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class UserResource {

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public UserResource() { }

    @POST
    @Path("/createaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response createAccount(InboundData<RegisterData> request) {
        RegisterData data = request.input;

        if (data == null || data.username == null || data.password == null
                || data.confirmation == null || !data.password.equals(data.confirmation)
                || !data.username.contains("@") || data.phone == null || data.address == null
                || data.role == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = datastore.get(userKey);

        if (user != null) {
            return Response.status(Response.Status.CONFLICT).entity(new ErrorResponse(ErrorCode.USER_ALREADY_EXISTS)).build();
        }

        user = Entity.newBuilder(userKey)
                .set("password", data.password)
                .set("username", data.username)
                .set("phone", data.phone != null ? data.phone : "")
                .set("address", data.address != null ? data.address : "")
                .set("role", data.role != null ? data.role.name() : UserRole.USER.name())
                .build();

        datastore.put(user);

        Map<String, String> successData = new HashMap<>();
        successData.put("username", user.getString("username"));
        successData.put("role", user.getString("role"));

        return Response.ok(OutboundResponse.success(successData)).build();
    }

    @POST
    @Path("/modaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response modifyAccount(InboundData<ModifyData> request) {
        AuthToken token = request.token;
        ModifyData input = request.input;

        if (input == null || input.username == null || input.attributes == null) {
            return Response.status(400).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
        Entity targetUser = datastore.get(targetKey);
        if (targetUser == null)
            return Response.status(404).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();

        if (token == null || token.tokenId == null)
            return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

        Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
        Entity session = datastore.get(sessionKey);

        if (session == null)
            return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

        if (session.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0) {
            datastore.delete(sessionKey);
            return Response.status(403).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();
        }

        String accessorUsername = session.getString("username");
        UserRole accessorRole = UserRole.valueOf(session.getString("role"));
        UserRole targetRole = UserRole.valueOf(targetUser.getString("role"));

        boolean allowed = false;
        if (accessorRole == UserRole.ADMIN) {
            allowed = true;
        } else if (accessorRole == UserRole.BOFFICER) {
            if (accessorUsername.equals(input.username) || targetRole == UserRole.USER) {
                allowed = true;
            }
        } else if (accessorRole == UserRole.USER) {
            if (accessorUsername.equals(input.username)) {
                allowed = true;
            }
        }

        if (!allowed)
            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();

        try {
            Entity.Builder builder = Entity.newBuilder(targetUser);

            if (input.attributes.containsKey("phone")) {
                builder.set("phone", input.attributes.get("phone"));
            }
            if (input.attributes.containsKey("email")) {
                builder.set("email", input.attributes.get("email"));
            }

            datastore.put(builder.build());
            return Response.ok(OutboundResponse.success(Map.of("message", "Updated successfully"))).build();

        } catch (Exception e) {
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }


    @POST
    @Path("/changeuserpwd")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePassword(InboundData<ChangePwdData> request) {
        AuthToken token = request.token;
        ChangePwdData input = request.input;
        Entity session = AuthUtils.validateSession(datastore, token, UserRole.USER, UserRole.BOFFICER, UserRole.ADMIN);

        if (session == null) {
            if (token == null || token.tokenId == null)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

            Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
            Entity existingSession = datastore.get(sessionKey);

            if (existingSession == null)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

            if (existingSession.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0) {
                datastore.delete(sessionKey);
                return Response.status(403).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();
            }
            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        if (input == null || input.username == null || input.oldPassword == null || input.newPassword == null) {
            return Response.status(400).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        String accessorUsername = session.getString("username");

        if (!accessorUsername.equals(input.username)) {
            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.status(404).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
            }

            if (!user.getString("password").equals(input.oldPassword)) {
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_CREDENTIALS)).build();
            }

            Entity updatedUser = Entity.newBuilder(user).set("password", input.newPassword).build();

            datastore.put(updatedUser);

            return Response.ok(OutboundResponse.success(Map.of("message", "Password changed successfully"))).build();

        } catch (Exception e) {
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

}
