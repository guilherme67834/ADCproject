package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.datastore.*;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import pt.unl.fct.di.adc.firstwebapp.data.ChangeRoleData;
import pt.unl.fct.di.adc.firstwebapp.exceptions.ErrorCode;
import pt.unl.fct.di.adc.firstwebapp.models.ErrorResponse;
import pt.unl.fct.di.adc.firstwebapp.models.InboundData;
import pt.unl.fct.di.adc.firstwebapp.models.OutboundResponse;
import pt.unl.fct.di.adc.firstwebapp.util.AuthUtils;
import pt.unl.fct.di.adc.firstwebapp.util.UserRole;

import java.util.*;

@Path("/")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class AdminResource {

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public AdminResource() { }

    @POST
    @Path("/showusers")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showUsers(InboundData<Map<String, Object>> request) {
        AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN, UserRole.BOFFICER);

        Query<Entity> query = Query.newEntityQueryBuilder().setKind("User").build();
        QueryResults<Entity> results = datastore.run(query);

        List<Map<String, String>> userList = new ArrayList<>();
        while (results.hasNext()) {
            Entity user = results.next();
            Map<String, String> userData = new LinkedHashMap<>();
            userData.put("username", user.getKey().getName());
            userData.put("role", user.getString("role"));
            userList.add(userData);
        }

        return Response.ok(OutboundResponse.success(Map.of("users", userList))).build();
    }

    @POST
    @Path("/deleteaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response deleteAccount(InboundData<Map<String, String>> request) {
        AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN);

        String targetUsername = request.input != null ? request.input.get("username") : null;
        if (targetUsername == null) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
        if (datastore.get(userKey) == null) {
            return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
        }

        try {
            datastore.delete(userKey);
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Session")
                    .setFilter(StructuredQuery.PropertyFilter.eq("username", targetUsername))
                    .build();
            QueryResults<Entity> results = datastore.run(query);

            while (results.hasNext()) {
                datastore.delete(results.next().getKey());
            }

            return Response.ok(OutboundResponse.success(Map.of("message", "Account deleted successfully"))).build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/showauthsessions")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showSessions(InboundData<Map<String, Object>> request) {
        AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN);

        try {
            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Session")
                    .build();
            QueryResults<Entity> results = datastore.run(query);

            List<Map<String, Object>> sessionList = new ArrayList<>();
            while (results.hasNext()) {
                Entity s = results.next();
                Map<String, Object> sessionData = new LinkedHashMap<>();
                sessionData.put("tokenId", s.getKey().getName());
                sessionData.put("username", s.getString("username"));
                sessionData.put("role", s.getString("role"));
                sessionData.put("expiresAt", s.getTimestamp("expiresAt").getSeconds());

                sessionList.add(sessionData);
            }

            Map<String, Object> responseData = new HashMap<>();
            responseData.put("sessions", sessionList);

            return Response.ok(OutboundResponse.success(responseData)).build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/showuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showRole(InboundData<Map<String, String>> request) {
        AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN, UserRole.BOFFICER);

        try {
            String targetUsername = request.input.get("username");
            if (targetUsername == null) {
                return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
            }

            Map<String, String> responseData = new LinkedHashMap<>();
            responseData.put("username", targetUsername);
            responseData.put("role", user.getString("role"));

            return Response.ok(OutboundResponse.success(responseData)).build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/changeuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(InboundData<ChangeRoleData> request) {
        AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN);
        ChangeRoleData input = request.input;
        if (input == null || input.username == null || input.newRole == null) {
            return Response.ok(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.ok(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
            }

            Entity updatedUser = Entity.newBuilder(user).set("role", input.newRole.name()).build();
            datastore.put(updatedUser);

            Query<Entity> query = Query.newEntityQueryBuilder()
                    .setKind("Session")
                    .setFilter(StructuredQuery.PropertyFilter.eq("username", input.username))
                    .build();
            QueryResults<Entity> results = datastore.run(query);

            while (results.hasNext()) {
                Entity s = results.next();
                Entity updatedSession = Entity.newBuilder(s)
                        .set("role", input.newRole.name())
                        .build();
                datastore.put(updatedSession);
            }

            return Response.ok(OutboundResponse.success(Map.of("message", "Role updated successfully"))).build();

        } catch (Exception e) {
            return Response.ok(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }
}
