package pt.unl.fct.di.adc.firstwebapp.resources;

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
import pt.unl.fct.di.adc.firstwebapp.data.ChangePwdData;
import pt.unl.fct.di.adc.firstwebapp.data.ModifyData;
import pt.unl.fct.di.adc.firstwebapp.data.RegisterData;
import pt.unl.fct.di.adc.firstwebapp.exceptions.ErrorCode;
import pt.unl.fct.di.adc.firstwebapp.models.ErrorResponse;
import pt.unl.fct.di.adc.firstwebapp.models.InboundData;
import pt.unl.fct.di.adc.firstwebapp.models.OutboundResponse;
import pt.unl.fct.di.adc.firstwebapp.util.AuthUtils;
import pt.unl.fct.di.adc.firstwebapp.util.UserRole;

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
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.username);
        Entity user = datastore.get(userKey);

        if (user != null) {
            return Response.ok(new ErrorResponse(ErrorCode.USER_ALREADY_EXISTS)).build();
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
        Entity session = AuthUtils.validateSession(datastore, request.token, UserRole.USER, UserRole.BOFFICER, UserRole.ADMIN);
        ModifyData input = request.input;

        if (input == null || input.username == null || input.attributes == null) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key targetKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
        Entity targetUser = datastore.get(targetKey);
        if (targetUser == null)
            return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();

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
            return Response.ok(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();

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
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }


    @POST
    @Path("/changeuserpwd")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changePassword(InboundData<ChangePwdData> request) {
        Entity session = AuthUtils.validateSession(datastore, request.token, UserRole.USER, UserRole.BOFFICER, UserRole.ADMIN);
        ChangePwdData input = request.input;

        if (input == null || input.username == null || input.oldPassword == null || input.newPassword == null) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        String accessorUsername = session.getString("username");
        if (!accessorUsername.equals(input.username)) {
            return Response.ok(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
            }

            if (!user.getString("password").equals(input.oldPassword)) {
                return Response.ok(new ErrorResponse(ErrorCode.INVALID_CREDENTIALS)).build();
            }

            Entity updatedUser = Entity.newBuilder(user).set("password", input.newPassword).build();
            datastore.put(updatedUser);

            return Response.ok(OutboundResponse.success(Map.of("message", "Password changed successfully"))).build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

}
