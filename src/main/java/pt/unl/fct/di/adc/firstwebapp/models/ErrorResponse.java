package pt.unl.fct.di.adc.firstwebapp.models;

import pt.unl.fct.di.adc.firstwebapp.exceptions.ErrorCode;

public class ErrorResponse {
    public String status;
    public String data;

    public ErrorResponse(ErrorCode error) {
        this.status = String.valueOf(error.code);
        this.data = error.message;
    }
}
