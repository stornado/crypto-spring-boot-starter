package com.zxytech.crypto.starter.result;


import lombok.Getter;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@ToString
@Getter
public enum ResultStatus {
    SUCCESS(HttpStatus.OK, HttpStatus.OK.value(), HttpStatus.OK.getReasonPhrase()),
    BAD_REQUEST(HttpStatus.BAD_REQUEST, HttpStatus.BAD_REQUEST.value(),
        HttpStatus.BAD_REQUEST.getReasonPhrase()),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, HttpStatus.UNAUTHORIZED.value(),
        HttpStatus.UNAUTHORIZED.getReasonPhrase()),
    FORBIDDEN(HttpStatus.FORBIDDEN, HttpStatus.FORBIDDEN.value(),
        HttpStatus.FORBIDDEN.getReasonPhrase()),
    NOT_FOUND(HttpStatus.NOT_FOUND, HttpStatus.NOT_FOUND.value(),
        HttpStatus.NOT_FOUND.getReasonPhrase()),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR,
        HttpStatus.INTERNAL_SERVER_ERROR.value(),
        HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase()),
    CRYPTO_ERROR(HttpStatus.BAD_REQUEST,
        HttpStatus.BAD_REQUEST.value(),
        "crypto error"),
    ;

    /**
     * 返回的HTTP状态码,  符合http请求
     */
    private HttpStatus httpStatus;
    /**
     * 业务异常码
     */
    private Integer code;
    /**
     * 业务异常信息描述
     */
    private String message;

    ResultStatus(HttpStatus httpStatus, Integer code, String message) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.message = message;
    }
}

