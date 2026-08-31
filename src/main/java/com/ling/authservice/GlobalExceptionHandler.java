package com.ling.authservice;

import com.ling.authservice.security.oauth.InvalidOAuth2UserException;
import com.ling.authservice.user.common.UserAlreadyExistsException;
import com.ling.authservice.user.common.UserNotFoundException;
import com.ling.authservice.user.identity.common.IdentityAlreadyExistsException;
import org.hibernate.exception.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.*;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.net.URI;
import java.util.Map;
import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log =
            LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /*
     * ============================
     * 400 Bad Request
     * ============================
     */

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArgument(
            IllegalArgumentException ex
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Bad request",
                "The request contains invalid data",
                "BAD_REQUEST"
        );
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ProblemDetail handleConstraintViolation(
            ConstraintViolationException ex
    ) {
        return problem(
                HttpStatus.BAD_REQUEST,
                "Validation failed",
                "One or more request parameters are invalid",
                "VALIDATION_FAILED"
        );
    }

    /*
     * ============================
     * 404 Not Found
     * ============================
     */

    @ExceptionHandler(UserNotFoundException.class)
    public ProblemDetail handleUserNotFound(
            UserNotFoundException ex
    ) {
        return problem(
                HttpStatus.NOT_FOUND,
                "User not found",
                "The requested user does not exist",
                "USER_NOT_FOUND"
        );
    }

    /*
     * ============================
     * 409 Conflict
     * ============================
     */

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ProblemDetail handleUserAlreadyExists(
            UserAlreadyExistsException ex
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "User already exists",
                "A user with the specified data already exists",
                "USER_ALREADY_EXISTS"
        );
    }

    @ExceptionHandler(IdentityAlreadyExistsException.class)
    public ProblemDetail handleIdentityAlreadyExists(
            IdentityAlreadyExistsException ex
    ) {
        return problem(
                HttpStatus.CONFLICT,
                "Identity already exists",
                "This identity is already associated with a user",
                "IDENTITY_ALREADY_EXISTS"
        );
    }

    /*
     * ============================
     * OAuth provider
     * ============================
     */

    @ExceptionHandler(InvalidOAuth2UserException.class)
    public ProblemDetail handleInvalidOAuth2User(
            InvalidOAuth2UserException ex
    ) {
        return problem(
                HttpStatus.BAD_GATEWAY,
                "OAuth provider error",
                "The OAuth provider returned invalid user data",
                "OAUTH_PROVIDER_INVALID_RESPONSE"
        );
    }

    /*
     * ============================
     * Database
     * ============================
     */

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail handleDataIntegrityViolation(
            DataIntegrityViolationException ex
    ) {
        log.warn("Data integrity violation", ex);

        String code = resolveDatabaseErrorCode(ex);

        HttpStatus status = switch (code) {
            case "USER_EMAIL_ALREADY_EXISTS",
                 "USER_USERNAME_ALREADY_EXISTS",
                 "IDENTITY_ALREADY_EXISTS" ->
                    HttpStatus.CONFLICT;

            default ->
                    HttpStatus.BAD_REQUEST;
        };

        return problem(
                status,
                "Data integrity violation",
                "The request conflicts with existing data",
                code
        );
    }

    /*
     * ============================
     * 500 Internal Server Error
     * ============================
     */

    @ExceptionHandler(Exception.class)
    public ProblemDetail handleUnexpected(
            Exception ex
    ) {
        log.error("Unhandled exception", ex);

        return problem(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Internal server error",
                "An unexpected error occurred",
                "INTERNAL_ERROR"
        );
    }

    /*
     * ============================
     * Spring MVC validation
     * ============================
     */

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request
    ) {
        ProblemDetail problem = problem(
                HttpStatus.BAD_REQUEST,
                "Validation failed",
                "One or more fields are invalid",
                "VALIDATION_FAILED"
        );

        Map<String, String> errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        error -> error.getField(),
                        error -> error.getDefaultMessage() != null
                                ? error.getDefaultMessage()
                                : "Invalid value",
                        (first, second) -> first
                ));

        problem.setProperty("errors", errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .headers(headers)
                .body(problem);
    }

    @Override
    protected ResponseEntity<Object> handleHandlerMethodValidationException(
            HandlerMethodValidationException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request
    ) {
        ProblemDetail problem = problem(
                HttpStatus.BAD_REQUEST,
                "Validation failed",
                "One or more request parameters are invalid",
                "VALIDATION_FAILED"
        );

        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .headers(headers)
                .body(problem);
    }

    /*
     * ============================
     * Helpers
     * ============================
     */

    private ProblemDetail problem(
            HttpStatus status,
            String title,
            String detail,
            String code
    ) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                status,
                detail
        );

        problem.setTitle(title);

        problem.setType(
                URI.create(
                        "https://localhost/problems/" +
                                code.toLowerCase()
                )
        );

        problem.setProperty("code", code);

        return problem;
    }

    private String resolveDatabaseErrorCode(
            DataIntegrityViolationException ex
    ) {
        Throwable cause = ex;

        while (cause != null) {

            if (cause instanceof org.hibernate.exception.ConstraintViolationException hibernateEx) {

                String constraint = hibernateEx.getConstraintName();

                if ("uk_user_email".equals(constraint)) {
                    return "USER_EMAIL_ALREADY_EXISTS";
                }

                if ("uk_user_username".equals(constraint)) {
                    return "USER_USERNAME_ALREADY_EXISTS";
                }

                if ("uk_identity_issuer_subject".equals(constraint)) {
                    return "IDENTITY_ALREADY_EXISTS";
                }

                if (hibernateEx.getKind()
                        == org.hibernate.exception.ConstraintViolationException.ConstraintKind.UNIQUE) {
                    return "UNIQUE_CONSTRAINT_VIOLATION";
                }

                return "DATA_INTEGRITY_VIOLATION";
            }

            cause = cause.getCause();
        }

        return "DATA_INTEGRITY_VIOLATION";
    }
}