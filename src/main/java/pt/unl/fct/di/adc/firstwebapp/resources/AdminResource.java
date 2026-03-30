package pt.unl.fct.di.adc.firstwebapp.resources;

import com.google.cloud.Timestamp;
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
public class AdminResource {

    private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

    public AdminResource() { }

    @POST
    @Path("/showusers")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showUsers(InboundData<Map<String, Object>> request) {
        AuthToken token = request.token;

        if (token == null || token.tokenId == null) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
        }

        Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
        Entity session = datastore.get(sessionKey);

        if (session == null) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
        }

        if (session.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0) {
            datastore.delete(sessionKey);
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();
        }

        Entity session2 = AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN, UserRole.BOFFICER);

        if (session2 == null) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }


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

        Map<String, Object> responseData = new LinkedHashMap<>();
        responseData.put("users", userList);

        return Response.ok(OutboundResponse.success(responseData)).build();
    }

    @POST
    @Path("/deleteaccount")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response deleteAccount(InboundData<Map<String, String>> request) {
        String targetUsername = request.input.get("username");
        if (targetUsername == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        Key userKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
        Entity user = datastore.get(userKey);

        if (user == null) {
            return Response.status(Response.Status.NOT_FOUND).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
        }
        AuthToken token = request.token;

        if (token == null || token.tokenId == null) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
        }

        Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
        Entity session = datastore.get(sessionKey);

        if (session == null) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
        }

        if (session.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0) {
            datastore.delete(sessionKey);
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();
        }

        UserRole userRole = UserRole.valueOf(session.getString("role"));
        if (userRole != UserRole.ADMIN) {
            return Response.status(Response.Status.FORBIDDEN).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
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
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/showauthsessions")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showSessions(InboundData<Map<String, Object>> request) {
        Entity sessionCaller = AuthUtils.validateSession(datastore, request.token, UserRole.ADMIN);

        if (sessionCaller == null) {
            if (request.token == null || request.token.tokenId == null) {
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();
            }

            Key checkKey = datastore.newKeyFactory().setKind("Session").newKey(request.token.tokenId);
            Entity existingSession = datastore.get(checkKey);

            if (existingSession == null)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

            if (existingSession.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();

            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

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
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/showuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response showRole(InboundData<Map<String, String>> request) {
        AuthToken token = request.token;
        Entity session = AuthUtils.validateSession(datastore, token, UserRole.ADMIN, UserRole.BOFFICER);

        if (session == null) {
            if (token == null || token.tokenId == null)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

            Key sessionKey = datastore.newKeyFactory().setKind("Session").newKey(token.tokenId);
            Entity existingSession = datastore.get(sessionKey);

            if (existingSession == null)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.INVALID_TOKEN)).build();

            if (existingSession.getTimestamp("expiresAt").compareTo(Timestamp.now()) < 0)
                return Response.status(403).entity(new ErrorResponse(ErrorCode.TOKEN_EXPIRED)).build();

            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        try {
            String targetUsername = request.input.get("username");
            if (targetUsername == null) {
                return Response.status(400).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
            }

            Key userKey = datastore.newKeyFactory().setKind("User").newKey(targetUsername);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.status(404).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
            }

            Map<String, String> responseData = new LinkedHashMap<>();
            responseData.put("username", targetUsername);
            responseData.put("role", user.getString("role"));

            return Response.ok(OutboundResponse.success(responseData)).build();

        } catch (Exception e) {
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }

    @POST
    @Path("/changeuserrole")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response changeRole(InboundData<ChangeRoleData> request) {
        AuthToken token = request.token;
        ChangeRoleData input = request.input;
        Entity session = AuthUtils.validateSession(datastore, token, UserRole.ADMIN);
        if (session == null) {
            return Response.status(403).entity(new ErrorResponse(ErrorCode.UNAUTHORIZED)).build();
        }

        if (input == null || input.username == null || input.newRole == null) {
            return Response.status(400).entity(new ErrorResponse(ErrorCode.INVALID_INPUT)).build();
        }

        try {
            Key userKey = datastore.newKeyFactory().setKind("User").newKey(input.username);
            Entity user = datastore.get(userKey);

            if (user == null) {
                return Response.status(404).entity(new ErrorResponse(ErrorCode.USER_NOT_FOUND)).build();
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
            return Response.status(500).entity(new ErrorResponse(ErrorCode.FORBIDDEN)).build();
        }
    }
}
