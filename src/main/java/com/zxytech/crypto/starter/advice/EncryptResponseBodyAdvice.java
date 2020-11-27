package com.zxytech.crypto.starter.advice;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.zxytech.crypto.starter.annotation.CryptoDetector;
import com.zxytech.crypto.starter.crypt.Crypto;
import com.zxytech.crypto.starter.crypt.CryptoException;
import com.zxytech.crypto.starter.request.RequestException;
import com.zxytech.crypto.starter.result.Result;
import com.zxytech.crypto.starter.result.ResultException;
import com.zxytech.crypto.starter.result.ResultStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.HttpClientErrorException.NotFound;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;
import org.springframework.web.util.WebUtils;

@Slf4j
@RestControllerAdvice
@ConditionalOnProperty(prefix = "crypto.encrypt", name = "enable", havingValue = "true", matchIfMissing = false)
public class EncryptResponseBodyAdvice implements ResponseBodyAdvice<Object> {

    @Value("${crypto.charset:UTF-8}")
    private String charset = "UTF-8";

    @Autowired
    private Crypto crypto;


    @Override
    public boolean supports(MethodParameter mp,
        Class<? extends HttpMessageConverter<?>> converter) {
        if (log.isDebugEnabled()) {
            log.debug("Assignable: {}, Encrypt: {}",
                AbstractJackson2HttpMessageConverter.class.isAssignableFrom(converter),
                CryptoDetector.encryptEnabled(mp));
        }
        return CryptoDetector.encryptEnabled(mp);
    }


    @Override
    public Object beforeBodyWrite(Object body, MethodParameter mp,
        MediaType contentType,
        Class<? extends HttpMessageConverter<?>> converter, ServerHttpRequest request,
        ServerHttpResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("ResponseBody Before Encrypt: body {}", body);
        }
        if (!CryptoDetector.encryptEnabled(mp)) {
            return body;
        }

        if (body instanceof Result) {
            return body;
        }

        if (body instanceof String) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                return mapper.writeValueAsString(Result.success(body, crypto, charset));
            } catch (JsonProcessingException e) {
                log.error("Encrypt String ResponseBody failed", e);
            }
        }

        return Result.success(body, crypto, charset);
    }

    /**
     * 提供对标准Spring MVC异常的处理
     *
     * @param ex the target exception
     * @param request the current request
     */
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<Result<?>> exceptionHandler(Exception ex, WebRequest request) {
        log.error("ExceptionHandler: {}", ex.getMessage(), ex);
        HttpHeaders headers = new HttpHeaders();
        if (ex instanceof ResultException) {
            return this.handleResultException((ResultException) ex, headers, request);
        }
        if (ex instanceof RequestException) {
            return this.handleRequestException((RequestException) ex, headers, request);
        }
        if (ex instanceof CryptoException) {
            return this.handleCryptoException((CryptoException) ex, headers, request);
        }
        if (ex instanceof NotFound) {
            return this.handleNotFound((NotFound) ex, headers, request);
        }
        return this.handleException(ex, headers, request);
    }

    /**
     * 对RequestException类返回返回结果的处理
     */
    protected ResponseEntity<Result<?>> handleRequestException(RequestException ex,
        HttpHeaders headers, WebRequest request) {
        Result<?> body = Result.failure(ResultStatus.BAD_REQUEST);
        HttpStatus status = ResultStatus.BAD_REQUEST.getHttpStatus();
        return this.handleExceptionInternal(ex, body, headers, status, request);
    }

    /**
     * 对ResultException类返回返回结果的处理
     */
    protected ResponseEntity<Result<?>> handleResultException(ResultException ex,
        HttpHeaders headers, WebRequest request) {
        Result<?> body = Result.failure(ex.getResultStatus());
        HttpStatus status = ex.getResultStatus().getHttpStatus();
        return this.handleExceptionInternal(ex, body, headers, status, request);
    }

    protected ResponseEntity<Result<?>> handleNotFound(NotFound ex,
        HttpHeaders headers, WebRequest request) {
        Result<?> body = Result.failure(ResultStatus.NOT_FOUND);
        HttpStatus status = ResultStatus.NOT_FOUND.getHttpStatus();
        return this.handleExceptionInternal(ex, body, headers, status, request);
    }

    /**
     * 对CryptoException类返回返回结果的处理
     */
    protected ResponseEntity<Result<?>> handleCryptoException(CryptoException ex,
        HttpHeaders headers, WebRequest request) {
        Result<?> body = Result.failure(ResultStatus.CRYPTO_ERROR);
        HttpStatus status = ResultStatus.CRYPTO_ERROR.getHttpStatus();
        return this.handleExceptionInternal(ex, body, headers, status, request);
    }

    /**
     * 异常类的统一处理
     */
    protected ResponseEntity<Result<?>> handleException(Exception ex, HttpHeaders headers,
        WebRequest request) {
        Result<?> body = Result.failure();
        HttpStatus status = HttpStatus.INTERNAL_SERVER_ERROR;
        return this.handleExceptionInternal(ex, body, headers, status, request);
    }

    /**
     * org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler#handleExceptionInternal(java.lang.Exception,
     * java.lang.Object, org.springframework.http.HttpHeaders, org.springframework.http.HttpStatus,
     * org.springframework.web.context.request.WebRequest)
     * <p>
     * A single place to customize the response body of all exception types.
     * <p>The default implementation sets the {@link WebUtils#ERROR_EXCEPTION_ATTRIBUTE}
     * request attribute and creates a {@link ResponseEntity} from the given
     * body, headers, and status.
     */
    protected ResponseEntity<Result<?>> handleExceptionInternal(
        Exception ex, Result<?> body, HttpHeaders headers, HttpStatus status, WebRequest request) {

        if (HttpStatus.INTERNAL_SERVER_ERROR.equals(status)) {
            request.setAttribute(WebUtils.ERROR_EXCEPTION_ATTRIBUTE, ex, WebRequest.SCOPE_REQUEST);
        }
        return new ResponseEntity<>(body, headers, status);
    }

}
