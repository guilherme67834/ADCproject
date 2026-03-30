package pt.unl.fct.di.adc.firstwebapp.resources;

public class ErrorResponse {
    public String status;
    public String data;

    public ErrorResponse(ErrorCode error) {
        this.status = String.valueOf(error.code);
        this.data = error.message;
    }
}
