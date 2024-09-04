package ru.userservice.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.HandlerMethod;

@ControllerAdvice
public class ExceptionController {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e, HandlerMethod handlerMethod) {
        String errorMessage = createErrorMessage(e, handlerMethod);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMessage);
    }

    private static String createErrorMessage(Exception e, HandlerMethod handlerMethod) {
        String methodName = handlerMethod.getMethod().getName();
        String className = handlerMethod.getBeanType().getSimpleName();
        String endpoint = className + "." + methodName;
        return String.format("Error occurred in endpoint: %s. Message: %s", endpoint, e.getMessage());
    }
}
