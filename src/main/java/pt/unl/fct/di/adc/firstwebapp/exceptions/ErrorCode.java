package pt.unl.fct.di.adc.firstwebapp.exceptions;

public enum ErrorCode {
    INVALID_CREDENTIALS(9900, "The username-password pair is not valid"),
    USER_ALREADY_EXISTS(9901, "Error in creating an account because the username already exists"),
    USER_NOT_FOUND(9902, "The username referred in the operation doesn’t exist in registered accounts"),
    INVALID_TOKEN(9903, "The operation is called with an invalid token (wrong format for example)"),
    TOKEN_EXPIRED(9904, "The operation is called with a token that is expired"),
    UNAUTHORIZED(9905, "The operation is not allowed for the user role"),
    INVALID_INPUT(9906, "The call is using input data not following the correct specification"),
    FORBIDDEN(9907, "The operation generated a forbidden error by other reason");

    public final int code;
    public final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }
}
