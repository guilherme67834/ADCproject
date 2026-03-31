package pt.unl.fct.di.adc.firstwebapp.models;

public class OutboundResponse {
    public String status;
    public Object data;

    public OutboundResponse(String status, Object data) {
        this.status = status;
        this.data = data;
    }

    public static OutboundResponse success(Object data) {
        return new OutboundResponse("success", data);
    }
}
