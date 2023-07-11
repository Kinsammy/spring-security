package io.samtech.security.exception;

public class UserAlreadyExistException extends Throwable {

    public UserAlreadyExistException(String message){
        super(message);
    }
}
