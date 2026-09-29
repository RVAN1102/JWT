package vn.iotstar.exceptions;

public class ExpiredJwtTokenException extends RuntimeException {
    public ExpiredJwtTokenException(String message) {
        super(message);
    }

    public ExpiredJwtTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
